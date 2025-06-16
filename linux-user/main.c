/*
 *  qemu user main
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/help-texts.h"
#include "qemu/units.h"
#include "qemu/accel.h"
#include "qemu-version.h"
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <linux/binfmts.h>

#include "qapi/error.h"
#include "qemu.h"
#include "user-internals.h"
#include "qemu/path.h"
#include "qemu/queue.h"
#include "qemu/config-file.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/help_option.h"
#include "qemu/module.h"
#include "qemu/plugin.h"
#include "user/guest-base.h"
#include "user/page-protection.h"
#include "exec/exec-all.h"
#include "exec/gdbstub.h"
#include "gdbstub/user.h"
#include "tcg/startup.h"
#include "qemu/timer.h"
#include "qemu/envlist.h"
#include "qemu/guest-random.h"
#include "elf.h"
#include "trace/control.h"
#include "target_elf.h"
#include "user/cpu_loop.h"
#include "crypto/init.h"
#include "fd-trans.h"
#include "signal-common.h"
#include "loader.h"
#include "user-mmap.h"
#include "tcg/perf.h"
#include "exec/page-vary.h"

#ifdef CONFIG_SEMIHOSTING
#include "semihosting/semihost.h"
#endif

#ifndef AT_FLAGS_PRESERVE_ARGV0
#define AT_FLAGS_PRESERVE_ARGV0_BIT 0
#define AT_FLAGS_PRESERVE_ARGV0 (1 << AT_FLAGS_PRESERVE_ARGV0_BIT)
#endif

char *exec_path;
char real_exec_path[PATH_MAX];

static bool opt_one_insn_per_tb;
static unsigned long opt_tb_size;
static const char *argv0;
static const char *gdbstub;
static envlist_t *envlist;
static const char *cpu_model;
static const char *cpu_type;
static const char *seed_optarg;
unsigned long mmap_min_addr;
uintptr_t guest_base;
bool have_guest_base;

/*
 * Used to implement backwards-compatibility for the `-strace`, and
 * QEMU_STRACE options. Without this, the QEMU_LOG can be overwritten by
 * -strace, or vice versa.
 */
static bool enable_strace;

/*
 * The last log mask given by the user in an environment variable or argument.
 * Used to support command line arguments overriding environment variables.
 */
static int last_log_mask;
static const char *last_log_filename;

/*
 * When running 32-on-64 we should make sure we can fit all of the possible
 * guest address space into a contiguous chunk of virtual host memory.
 *
 * This way we will never overlap with our own libraries or binaries or stack
 * or anything else that QEMU maps.
 *
 * Many cpus reserve the high bit (or more than one for some 64-bit cpus)
 * of the address for the kernel.  Some cpus rely on this and user space
 * uses the high bit(s) for pointer tagging and the like.  For them, we
 * must preserve the expected address space.
 */
#ifndef MAX_RESERVED_VA
# if HOST_LONG_BITS > TARGET_VIRT_ADDR_SPACE_BITS
#  if TARGET_VIRT_ADDR_SPACE_BITS == 32 && \
      (TARGET_LONG_BITS == 32 || defined(TARGET_ABI32))
#   define MAX_RESERVED_VA(CPU)  0xfffffffful
#  else
#   define MAX_RESERVED_VA(CPU)  ((1ul << TARGET_VIRT_ADDR_SPACE_BITS) - 1)
#  endif
# else
#  define MAX_RESERVED_VA(CPU)  0
# endif
#endif

unsigned long reserved_va;

static void usage(int exitcode);

static const char *interp_prefix = CONFIG_QEMU_INTERP_PREFIX;
const char *qemu_uname_release;

#if !defined(TARGET_DEFAULT_STACK_SIZE)
/* XXX: on x86 MAP_GROWSDOWN only works if ESP <= address + 32, so
   we allocate a bigger stack. Need a better solution, for example
   by remapping the process stack directly at the right place */
#define TARGET_DEFAULT_STACK_SIZE	8 * 1024 * 1024UL
#endif

unsigned long guest_stack_size = TARGET_DEFAULT_STACK_SIZE;

/***********************************************************/
/* Helper routines for implementing atomic operations.  */

/* Make sure everything is in a consistent state for calling fork().  */
void fork_start(void)
{
    start_exclusive();
    mmap_fork_start();
    cpu_list_lock();
    qemu_plugin_user_prefork_lock();
    gdbserver_fork_start();
}

void fork_end(pid_t pid)
{
    bool child = pid == 0;

    qemu_plugin_user_postfork(child);
    mmap_fork_end(child);
    if (child) {
        CPUState *cpu, *next_cpu;
        /* Child processes created by fork() only have a single thread.
           Discard information about the parent threads.  */
        CPU_FOREACH_SAFE(cpu, next_cpu) {
            if (cpu != thread_cpu) {
                QTAILQ_REMOVE_RCU(&cpus_queue, cpu, node);
            }
        }
        qemu_init_cpu_list();
        get_task_state(thread_cpu)->ts_tid = qemu_get_thread_id();
    } else {
        cpu_list_unlock();
    }
    gdbserver_fork_end(thread_cpu, pid);
    /*
     * qemu_init_cpu_list() reinitialized the child exclusive state, but we
     * also need to keep current_cpu consistent, so call end_exclusive() for
     * both child and parent.
     */
    end_exclusive();
}

__thread CPUState *thread_cpu;

bool qemu_cpu_is_self(CPUState *cpu)
{
    return thread_cpu == cpu;
}

void qemu_cpu_kick(CPUState *cpu)
{
    cpu_exit(cpu);
}

void task_settid(TaskState *ts)
{
    if (ts->ts_tid == 0) {
        ts->ts_tid = (pid_t)syscall(SYS_gettid);
    }
}

void stop_all_tasks(void)
{
    /*
     * We trust that when using NPTL, start_exclusive()
     * handles thread stopping correctly.
     */
    start_exclusive();
}

/* Assumes contents are already zeroed.  */
void init_task_state(TaskState *ts)
{
    long ticks_per_sec;
    struct timespec bt;

    ts->used = 1;
    ts->sigaltstack_used = (struct target_sigaltstack) {
        .ss_sp = 0,
        .ss_size = 0,
        .ss_flags = TARGET_SS_DISABLE,
    };

    /* Capture task start time relative to system boot */

    ticks_per_sec = sysconf(_SC_CLK_TCK);

    if ((ticks_per_sec > 0) && !clock_gettime(CLOCK_BOOTTIME, &bt)) {
        /* start_boottime is expressed in clock ticks */
        ts->start_boottime = bt.tv_sec * (uint64_t) ticks_per_sec;
        ts->start_boottime += bt.tv_nsec * (uint64_t) ticks_per_sec /
                              NANOSECONDS_PER_SECOND;
    }
}

CPUArchState *cpu_copy(CPUArchState *env)
{
    CPUState *cpu = env_cpu(env);
    CPUState *new_cpu = cpu_create(cpu_type);
    CPUArchState *new_env = cpu_env(new_cpu);
    CPUBreakpoint *bp;

    /* Reset non arch specific state */
    cpu_reset(new_cpu);

    new_cpu->tcg_cflags = cpu->tcg_cflags;
    memcpy(new_env, env, sizeof(CPUArchState));
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    new_env->gdt.base = target_mmap(0, sizeof(uint64_t) * TARGET_GDT_ENTRIES,
                                    PROT_READ | PROT_WRITE,
                                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    memcpy(g2h_untagged(new_env->gdt.base), g2h_untagged(env->gdt.base),
           sizeof(uint64_t) * TARGET_GDT_ENTRIES);
    OBJECT(new_cpu)->free = OBJECT(cpu)->free;
#endif

    /* Clone all break/watchpoints.
       Note: Once we support ptrace with hw-debug register access, make sure
       BP_CPU break/watchpoints are handled correctly on clone. */
    QTAILQ_INIT(&new_cpu->breakpoints);
    QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
        cpu_breakpoint_insert(new_cpu, bp->pc, bp->flags, NULL);
    }

    return new_env;
}

static void handle_arg_help(const char *arg)
{
    usage(EXIT_SUCCESS);
}

static void handle_arg_log(const char *arg)
{
    last_log_mask = qemu_str_to_log_mask(arg);
    if (!last_log_mask) {
        qemu_print_log_usage(stdout);
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_dfilter(const char *arg)
{
    qemu_set_dfilter_ranges(arg, &error_fatal);
}

static void handle_arg_log_filename(const char *arg)
{
    last_log_filename = arg;
}

static void handle_arg_set_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_setenv(envlist, token) != 0) {
            usage(EXIT_FAILURE);
        }
    }
    free(r);
}

static void handle_arg_unset_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_unsetenv(envlist, token) != 0) {
            usage(EXIT_FAILURE);
        }
    }
    free(r);
}

static void handle_arg_argv0(const char *arg)
{
    argv0 = strdup(arg);
}

static void handle_arg_stack_size(const char *arg)
{
    char *p;
    guest_stack_size = strtoul(arg, &p, 0);
    if (guest_stack_size == 0) {
        usage(EXIT_FAILURE);
    }

    if (*p == 'M') {
        guest_stack_size *= MiB;
    } else if (*p == 'k' || *p == 'K') {
        guest_stack_size *= KiB;
    }
}

static void handle_arg_ld_prefix(const char *arg)
{
    interp_prefix = strdup(arg);
}

static void handle_arg_pagesize(const char *arg)
{
    unsigned size, want = qemu_real_host_page_size();

    if (qemu_strtoui(arg, NULL, 10, &size) || size != want) {
        warn_report("Deprecated page size option cannot "
                    "change host page size (%u)", want);
    }
}

static void handle_arg_seed(const char *arg)
{
    seed_optarg = arg;
}

static void handle_arg_gdb(const char *arg)
{
    gdbstub = g_strdup(arg);
}

static void handle_arg_uname(const char *arg)
{
    qemu_uname_release = strdup(arg);
}

static void handle_arg_cpu(const char *arg)
{
    cpu_model = strdup(arg);
    if (cpu_model == NULL || is_help_option(cpu_model)) {
        list_cpus();
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_guest_base(const char *arg)
{
    guest_base = strtol(arg, NULL, 0);
    have_guest_base = true;
}

static void handle_arg_reserved_va(const char *arg)
{
    char *p;
    int shift = 0;
    unsigned long val;

    val = strtoul(arg, &p, 0);
    switch (*p) {
    case 'k':
    case 'K':
        shift = 10;
        break;
    case 'M':
        shift = 20;
        break;
    case 'G':
        shift = 30;
        break;
    }
    if (shift) {
        unsigned long unshifted = val;
        p++;
        val <<= shift;
        if (val >> shift != unshifted) {
            fprintf(stderr, "Reserved virtual address too big\n");
            exit(EXIT_FAILURE);
        }
    }
    if (*p) {
        fprintf(stderr, "Unrecognised -R size suffix '%s'\n", p);
        exit(EXIT_FAILURE);
    }
    /* The representation is size - 1, with 0 remaining "default". */
    reserved_va = val ? val - 1 : 0;
}

static const char *rtsig_map = CONFIG_QEMU_RTSIG_MAP;

static void handle_arg_rtsig_map(const char *arg)
{
    rtsig_map = arg;
}

static void handle_arg_one_insn_per_tb(const char *arg)
{
    opt_one_insn_per_tb = true;
}

static void handle_arg_tb_size(const char *arg)
{
    if (qemu_strtoul(arg, NULL, 0, &opt_tb_size)) {
        usage(EXIT_FAILURE);
    }
}

static void handle_arg_strace(const char *arg)
{
    enable_strace = true;
}

static void handle_arg_version(const char *arg)
{
    printf("qemu-" TARGET_NAME " version " QEMU_FULL_VERSION
           "\n" QEMU_COPYRIGHT "\n");
    exit(EXIT_SUCCESS);
}

static void handle_arg_trace(const char *arg)
{
    trace_opt_parse(arg);
}

#if defined(TARGET_XTENSA)
static void handle_arg_abi_call0(const char *arg)
{
    xtensa_set_abi_call0();
}
#endif

static void handle_arg_perfmap(const char *arg)
{
    perf_enable_perfmap();
}

static void handle_arg_jitdump(const char *arg)
{
    perf_enable_jitdump();
}

static QemuPluginList plugins = QTAILQ_HEAD_INITIALIZER(plugins);

#ifdef CONFIG_PLUGIN
static void handle_arg_plugin(const char *arg)
{
    qemu_plugin_opt_parse(arg, &plugins);
}
#endif

struct qemu_argument {
    const char *argv;
    const char *env;
    bool has_arg;
    void (*handle_opt)(const char *arg);
    const char *example;
    const char *help;
};

static const struct qemu_argument arg_table[] = {
    {"h",          "",                 false, handle_arg_help,
     "",           "print this help"},
    {"help",       "",                 false, handle_arg_help,
     "",           ""},
    {"g",          "QEMU_GDB",         true,  handle_arg_gdb,
     "port",       "wait gdb connection to 'port'"},
    {"L",          "QEMU_LD_PREFIX",   true,  handle_arg_ld_prefix,
     "path",       "set the elf interpreter prefix to 'path'"},
    {"s",          "QEMU_STACK_SIZE",  true,  handle_arg_stack_size,
     "size",       "set the stack size to 'size' bytes"},
    {"cpu",        "QEMU_CPU",         true,  handle_arg_cpu,
     "model",      "select CPU (-cpu help for list)"},
    {"E",          "QEMU_SET_ENV",     true,  handle_arg_set_env,
     "var=value",  "sets targets environment variable (see below)"},
    {"U",          "QEMU_UNSET_ENV",   true,  handle_arg_unset_env,
     "var",        "unsets targets environment variable (see below)"},
    {"0",          "QEMU_ARGV0",       true,  handle_arg_argv0,
     "argv0",      "forces target process argv[0] to be 'argv0'"},
    {"r",          "QEMU_UNAME",       true,  handle_arg_uname,
     "uname",      "set qemu uname release string to 'uname'"},
    {"B",          "QEMU_GUEST_BASE",  true,  handle_arg_guest_base,
     "address",    "set guest_base address to 'address'"},
    {"R",          "QEMU_RESERVED_VA", true,  handle_arg_reserved_va,
     "size",       "reserve 'size' bytes for guest virtual address space"},
    {"t",          "QEMU_RTSIG_MAP",   true,  handle_arg_rtsig_map,
     "tsig hsig n[,...]",
                   "map target rt signals [tsig,tsig+n) to [hsig,hsig+n]"},
    {"d",          "QEMU_LOG",         true,  handle_arg_log,
     "item[,...]", "enable logging of specified items "
     "(use '-d help' for a list of items)"},
    {"dfilter",    "QEMU_DFILTER",     true,  handle_arg_dfilter,
     "range[,...]","filter logging based on address range"},
    {"D",          "QEMU_LOG_FILENAME", true, handle_arg_log_filename,
     "logfile",     "write logs to 'logfile' (default stderr)"},
    {"p",          "QEMU_PAGESIZE",    true,  handle_arg_pagesize,
     "pagesize",   "deprecated change to host page size"},
    {"one-insn-per-tb",
                   "QEMU_ONE_INSN_PER_TB",  false, handle_arg_one_insn_per_tb,
     "",           "run with one guest instruction per emulated TB"},
    {"tb-size",    "QEMU_TB_SIZE",     true,  handle_arg_tb_size,
     "size",       "TCG translation block cache size"},
    {"strace",     "QEMU_STRACE",      false, handle_arg_strace,
     "",           "log system calls"},
    {"seed",       "QEMU_RAND_SEED",   true,  handle_arg_seed,
     "",           "Seed for pseudo-random number generator"},
    {"trace",      "QEMU_TRACE",       true,  handle_arg_trace,
     "",           "[[enable=]<pattern>][,events=<file>][,file=<file>]"},
#ifdef CONFIG_PLUGIN
    {"plugin",     "QEMU_PLUGIN",      true,  handle_arg_plugin,
     "",           "[file=]<file>[,<argname>=<argvalue>]"},
#endif
    {"version",    "QEMU_VERSION",     false, handle_arg_version,
     "",           "display version information and exit"},
#if defined(TARGET_XTENSA)
    {"xtensa-abi-call0", "QEMU_XTENSA_ABI_CALL0", false, handle_arg_abi_call0,
     "",           "assume CALL0 Xtensa ABI"},
#endif
    {"perfmap",    "QEMU_PERFMAP",     false, handle_arg_perfmap,
     "",           "Generate a /tmp/perf-${pid}.map file for perf"},
    {"jitdump",    "QEMU_JITDUMP",     false, handle_arg_jitdump,
     "",           "Generate a jit-${pid}.dump file for perf"},
    {NULL, NULL, false, NULL, NULL, NULL}
};

static void usage(int exitcode)
{
    const struct qemu_argument *arginfo;
    int maxarglen;
    int maxenvlen;

    printf("usage: qemu-" TARGET_NAME " [options] program [arguments...]\n"
           "Linux CPU emulator (compiled for " TARGET_NAME " emulation)\n"
           "\n"
           "Options and associated environment variables:\n"
           "\n");

    /* Calculate column widths. We must always have at least enough space
     * for the column header.
     */
    maxarglen = strlen("Argument");
    maxenvlen = strlen("Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        int arglen = strlen(arginfo->argv);
        if (arginfo->has_arg) {
            arglen += strlen(arginfo->example) + 1;
        }
        if (strlen(arginfo->env) > maxenvlen) {
            maxenvlen = strlen(arginfo->env);
        }
        if (arglen > maxarglen) {
            maxarglen = arglen;
        }
    }

    printf("%-*s %-*s Description\n", maxarglen+1, "Argument",
            maxenvlen, "Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->has_arg) {
            printf("-%s %-*s %-*s %s\n", arginfo->argv,
                   (int)(maxarglen - strlen(arginfo->argv) - 1),
                   arginfo->example, maxenvlen, arginfo->env, arginfo->help);
        } else {
            printf("-%-*s %-*s %s\n", maxarglen, arginfo->argv,
                    maxenvlen, arginfo->env,
                    arginfo->help);
        }
    }

    printf("\n"
           "Defaults:\n"
           "QEMU_LD_PREFIX  = %s\n"
           "QEMU_STACK_SIZE = %ld byte\n",
           interp_prefix,
           guest_stack_size);

    printf("\n"
           "You can use -E and -U options or the QEMU_SET_ENV and\n"
           "QEMU_UNSET_ENV environment variables to set and unset\n"
           "environment variables for the target process.\n"
           "It is possible to provide several variables by separating them\n"
           "by commas in getsubopt(3) style. Additionally it is possible to\n"
           "provide the -E and -U options multiple times.\n"
           "The following lines are equivalent:\n"
           "    -E var1=val2 -E var2=val2 -U LD_PRELOAD -U LD_DEBUG\n"
           "    -E var1=val2,var2=val2 -U LD_PRELOAD,LD_DEBUG\n"
           "    QEMU_SET_ENV=var1=val2,var2=val2 QEMU_UNSET_ENV=LD_PRELOAD,LD_DEBUG\n"
           "Note that if you provide several changes to a single variable\n"
           "the last change will stay in effect.\n"
           "\n"
           QEMU_HELP_BOTTOM "\n");

    exit(exitcode);
}

static int parse_args(int argc, char **argv)
{
    const char *r;
    int optind;
    const struct qemu_argument *arginfo;

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->env == NULL) {
            continue;
        }

        r = getenv(arginfo->env);
        if (r != NULL) {
            arginfo->handle_opt(r);
        }
    }

    optind = 1;
    for (;;) {
        if (optind >= argc) {
            break;
        }
        r = argv[optind];
        if (r[0] != '-') {
            break;
        }
        optind++;
        r++;
        if (!strcmp(r, "-")) {
            break;
        }
        /* Treat --foo the same as -foo.  */
        if (r[0] == '-') {
            r++;
        }

        for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
            if (!strcmp(r, arginfo->argv)) {
                if (arginfo->has_arg) {
                    if (optind >= argc) {
                        (void) fprintf(stderr,
                            "qemu: missing argument for option '%s'\n", r);
                        exit(EXIT_FAILURE);
                    }
                    arginfo->handle_opt(argv[optind]);
                    optind++;
                } else {
                    arginfo->handle_opt(NULL);
                }
                break;
            }
        }

        /* no option matched the current argv */
        if (arginfo->handle_opt == NULL) {
            (void) fprintf(stderr, "qemu: unknown option '%s'\n", r);
            exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        (void) fprintf(stderr, "qemu: no user program specified\n");
        exit(EXIT_FAILURE);
    }

    exec_path = argv[optind];

    return optind;
}

int main(int argc, char **argv, char **envp)
{
    struct target_pt_regs regs1, *regs = &regs1; // CPU寄存器镜像，包括PC寄存器、状态寄存器、通用寄存器等，上下文切换时用其保存信息
    struct image_info info1, *info = &info1;     // 模拟目标程序的内存映射布局用于内存管理，即虚拟地址分布（代码段、数据段、堆、栈、位置和大小）
    struct linux_binprm bprm;                    // 模拟一个目标程序启动环境-包含了目标程序启动时传入的命令行参数、环境变量、权限、文件名、装载缓冲区
    TaskState *ts;      // 维护的guest 线程/进程的状态信息结构体,如信号堆、线程栈、信号处理等
    CPUArchState *env;  // 不同架构有不同的env，env是CPU状态结构体
    CPUState *cpu;      // 抽象出的一个虚拟CPU实例，是qemu中的桥梁：连接起：调度器、tcg翻译器、信号处理、gdb调度器等，其中有一个env_ptr指向上一行的env
    // CPUArchState VS target_pt_regs
    // CPUArchState：   TCG翻译器执行指令时的上下文、始终存在、随着CPU创建而存在。
    // target_pt_regs:  模拟内核ABI中暴露给用户态寄存器状态，只在syscall、signal等需要构造用户态寄存器上下文时使用。
    // 简单来说：env是常用的，regs1是在syscall、signal时会用的
    int optind;
    char **target_environ, **wrk;
    char **target_argv;
    int target_argc;
    int i;
    int ret;
    int execfd;
    int host_page_size;
    unsigned long max_reserved_va;
    bool preserve_argv0;

    // 初始化错误打印、模块系统、QOM类型系统环境
    error_init(argv[0]);
    module_call_init(MODULE_INIT_TRACE); // 初始化trace模块，MODULE_INIT_TRACE-运行时事件跟踪，插桩记录关键事件
    qemu_init_cpu_list();                // 初始化QEMU中CPU列表的同步机制
    module_call_init(MODULE_INIT_QOM);   // 对象模型模块（QOM）

    envlist = envlist_create();

    /*
     * add current environment into the list
     * envlist_setenv adds to the front of the list; to preserve environ
     * order add from back to front
     */
    for (wrk = environ; *wrk != NULL; wrk++) {
        continue;
    }
    while (wrk != environ) {
        wrk--;
        (void) envlist_setenv(envlist, *wrk);
    }

    /* Read the stack limit from the kernel.  If it's "unlimited",
       then we can do little else besides use the default.  */
    {
        struct rlimit lim; // 栈限制大小
        if (getrlimit(RLIMIT_STACK, &lim) == 0
            && lim.rlim_cur != RLIM_INFINITY
            && lim.rlim_cur == (target_long)lim.rlim_cur
            && lim.rlim_cur > guest_stack_size) {
            guest_stack_size = lim.rlim_cur;
        }
    }

    cpu_model = NULL;

    // 注册tarce和plugin的命令行参数 （注册概念：将一个描述trace选项的结构体加入到全局列表中，让后续解析器或调度器可以调用它）
    qemu_add_opts(&qemu_trace_opts);
    qemu_plugin_add_opts();
    // 处理传入的参数（模拟的程序、启用的插件...）
    optind = parse_args(argc, argv);
    // 配置日志文件名和启用哪些日志类别
    qemu_set_log_filename_flags(last_log_filename,
                                last_log_mask | (enable_strace * LOG_STRACE),
                                &error_fatal);
    // 初始trace系统
    if (!trace_init_backends()) {
        exit(1);
    }
    trace_init_file();
    // 加载plugin插件
    qemu_plugin_load_list(&plugins, &error_fatal);

    // 清除这些结构体，防止脏数据
    /* Zero out regs */
    memset(regs, 0, sizeof(struct target_pt_regs));

    /* Zero out image_info */
    memset(info, 0, sizeof(struct image_info));

    memset(&bprm, 0, sizeof (bprm));

    // 初始化路径相关逻辑，告诉模拟器用哪里的动态链接器（异架构情况下默认路径的动态链接无法使用或不存在）
    /* Scan interp_prefix dir for replacement files. */
    init_paths(interp_prefix);

    // 初始化uname返回信息,uname是一个系统调用，用来获取当前运行内核的信息-模拟系统返回的uname内容
    // guest 程序如果获取内核信息，那么会直接拿到host的内核信息，这不符合guest环境，所以需要单独特殊处理
    init_qemu_uname_release();

    /*
     * Manage binfmt-misc open-binary flag
     */
    errno = 0;
    execfd = qemu_getauxval(AT_EXECFD); // 文件描述符execfd
    if (errno != 0) {
        execfd = open(exec_path, O_RDONLY);
        if (execfd < 0) {
            printf("Error while loading %s: %s\n", exec_path, strerror(errno));
            _exit(EXIT_FAILURE);
        }
    }

    /* Resolve executable file name to full path name */
    if (realpath(exec_path, real_exec_path)) { // 获取绝对路径
        exec_path = real_exec_path;
    }
    
    /*
     * get binfmt_misc flags
     */
    preserve_argv0 = !!(qemu_getauxval(AT_FLAGS) & AT_FLAGS_PRESERVE_ARGV0); 

    /*
     * Manage binfmt-misc preserve-arg[0] flag
     *    argv[optind]     full path to the binary
     *    argv[optind + 1] original argv[0]
     */
    if (optind + 1 < argc && preserve_argv0) { // 解析binfmt_misc的flag，用于自动调用qemu-arch去执行guest程序
        optind++;
    }

    if (cpu_model == NULL) {
        // 根据文件描述符获取到e_flags字段，推导应该仿真的CPU型号
        //（文件描述符是指向ELF文件的一个打开的只读指针，可以用来read/lseek/fstat/mmap）
        cpu_model = cpu_get_model(get_elf_eflags(execfd));
    }
    cpu_type = parse_cpu_option(cpu_model);

    /* init tcg before creating CPUs */
    {
        AccelState *accel = current_accel();
        AccelClass *ac = ACCEL_GET_CLASS(accel);

        accel_init_interfaces(ac);
        object_property_set_bool(OBJECT(accel), "one-insn-per-tb",   // one-insn-per-tb = true - 一条一条翻译 false - 采用下面的tb-size方式  是否打开通过qemu的命令行参数
                                 opt_one_insn_per_tb, &error_abort); 
        object_property_set_int(OBJECT(accel), "tb-size",  // QEMU是通用解释器，目标指令不是定长的，所以用字节数去限制：比如tb-size=128bit：32条4bit 64条2bit 4条32bit更加合理
                                opt_tb_size, &error_abort);
        ac->init_machine(NULL);  // 机器的初始化
    }

    /*
     * Finalize page size before creating CPUs.
     * This will do nothing if !TARGET_PAGE_BITS_VARY.
     * The most efficient setting is to match the host.
     */
    host_page_size = qemu_real_host_page_size(); // 获取host真实大小
    set_preferred_target_page_bits(ctz32(host_page_size)); // 设置guest页大小与host相同
    finalize_target_page_bits();    // 避免guest架构支持多种页大小，不需要做全特性支持行为，所以直接固定页大小，简化内存管理单元行为（页表、内存分配、地址映射、TBL模拟等...）

    cpu = cpu_create(cpu_type);     // 利用类型创建CPU实例
    env = cpu_env(cpu);                      // 从CPU实例中提取出env
    cpu_reset(cpu);       // 初始化寄存器
    thread_cpu = cpu;

    // 对guest内存地址进行合理性检查并给定预留值
    /*
     * Reserving too much vm space via mmap can run into problems with rlimits,
     * oom due to page table creation, etc.  We will still try it, if directed
     * by the command-line option, but not by default. Unless we're running a
     * target address space of 32 or fewer bits on a host with 64 bits.
     */
    max_reserved_va = MAX_RESERVED_VA(cpu);
    if (reserved_va != 0) {
        if ((reserved_va + 1) % host_page_size) {
            char *s = size_to_str(host_page_size);
            fprintf(stderr, "Reserved virtual address not aligned mod %s\n", s);
            g_free(s);
            exit(EXIT_FAILURE);
        }
        if (max_reserved_va && reserved_va > max_reserved_va) {
            fprintf(stderr, "Reserved virtual address too big\n");
            exit(EXIT_FAILURE);
        }
    } else if (HOST_LONG_BITS == 64 && TARGET_VIRT_ADDR_SPACE_BITS <= 32) {
        /* MAX_RESERVED_VA + 1 is a large power of 2, so is aligned. */
        reserved_va = max_reserved_va;
    }

    /*
     * Temporarily disable
     *   "comparison is always false due to limited range of data type"
     * due to comparison between (possible) uint64_t and uintptr_t.
     */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
#pragma GCC diagnostic ignored "-Wtautological-compare"

    // task_unmapped_base是guest用户空间中 mmap 动态分配区域（未映射区域）的基地址，保证guest虚拟地址使用合法、不重叠不越界
    /*
     * Select an initial value for task_unmapped_base that is in range.
     */
    if (reserved_va) {
        if (TASK_UNMAPPED_BASE < reserved_va) {
            task_unmapped_base = TASK_UNMAPPED_BASE; 
        } else {
            /* The most common default formula is TASK_SIZE / 3. */
            task_unmapped_base = TARGET_PAGE_ALIGN(reserved_va / 3);
        }
    } else if (TASK_UNMAPPED_BASE < UINTPTR_MAX) {
        task_unmapped_base = TASK_UNMAPPED_BASE;
    } else {
        /* 32-bit host: pick something medium size. */
        task_unmapped_base = 0x10000000;
    }
    mmap_next_start = task_unmapped_base;

    // 为ELF动态链接可执行文件（Position Independent Executable, PIE）
    // ，选择合适的默认加载基地址（现代linux gcc编译生成的都是PIE可执行文件）
    /* Similarly for elf_et_dyn_base. */
    if (reserved_va) {
        if (ELF_ET_DYN_BASE < reserved_va) {
            elf_et_dyn_base = ELF_ET_DYN_BASE;
        } else {
            /* The most common default formula is TASK_SIZE / 3 * 2. */
            elf_et_dyn_base = TARGET_PAGE_ALIGN(reserved_va / 3) * 2;
        }
    } else if (ELF_ET_DYN_BASE < UINTPTR_MAX) {
        elf_et_dyn_base = ELF_ET_DYN_BASE;
    } else {
        /* 32-bit host: pick something medium size. */
        elf_et_dyn_base = 0x18000000;
    }

#pragma GCC diagnostic pop
    // 加密子系统
    {
        Error *err = NULL;
        if (seed_optarg != NULL) {
            qemu_guest_random_seed_main(seed_optarg, &err);
        } else {
            qcrypto_init(&err);
        }
        if (err) {
            error_reportf_err(err, "cannot initialize crypto: ");
            exit(1);
        }
    }

    target_environ = envlist_to_environ(envlist, NULL); // target_environ就是guest的envp
    envlist_free(envlist); // 释放掉

    // 通过mmap_min_addr来限制guest映射到host的地址范围（不能小于mmap_min_addr中的存值）
    /*
     * Read in mmap_min_addr kernel parameter.  This value is used
     * When loading the ELF image to determine whether guest_base
     * is needed.  It is also used in mmap_find_vma.
     */
    {
        FILE *fp;

        if ((fp = fopen("/proc/sys/vm/mmap_min_addr", "r")) != NULL) {
            unsigned long tmp;
            if (fscanf(fp, "%lu", &tmp) == 1 && tmp != 0) {
                mmap_min_addr = MAX(tmp, host_page_size);
                qemu_log_mask(CPU_LOG_PAGE, "host mmap_min_addr=0x%lx\n",
                              mmap_min_addr);
            }
            fclose(fp);
        }
    }
    /*
     * We prefer to not make NULL pointers accessible to QEMU.
     * If we're in a chroot with no /proc, fall back to 1 page.
     */
    if (mmap_min_addr == 0) {
        mmap_min_addr = host_page_size;
        qemu_log_mask(CPU_LOG_PAGE,
                      "host mmap_min_addr=0x%lx (fallback)\n",
                      mmap_min_addr);
    }

    /*
     * Prepare copy of argv vector for target.
     */
    target_argc = argc - optind;
    target_argv = g_new0(char *, target_argc + 1); // 准备guest的参数表

    /*
     * If argv0 is specified (using '-0' switch) we replace
     * argv[0] pointer with the given one.
     */
    i = 0;
    if (argv0 != NULL) {
        target_argv[i++] = strdup(argv0);
    }
    for (; i < target_argc; i++) {
        target_argv[i] = strdup(argv[optind + i]);
    }
    target_argv[target_argc] = NULL;

    // 模拟的进程控制块-ts,并初始化
    ts = g_new0(TaskState, 1);
    init_task_state(ts);
    /* build Task State */
    ts->info = info; // guset EIF加载信息
    ts->bprm = &bprm; // bprm启动环境
    cpu->opaque = ts; // 又把进程控制块给到了cpu的opaque中
    task_settid(ts);

    fd_trans_init(); // guest系统调用使用的fd和host fd不同，需要有一张映射表 guest_fd 3 -> host_fd 11 懒加载，现在是空表

    // 加载guest程序
    ret = loader_exec(execfd, exec_path, target_argv, target_environ, regs,
        info, &bprm);
    if (ret != 0) {
        printf("Error while loading %s: %s\n", exec_path, strerror(-ret));
        _exit(EXIT_FAILURE);
    }

    // 释放target_environ所占的内存
    for (wrk = target_environ; *wrk; wrk++) {
        g_free(*wrk);
    }
    g_free(target_environ);

    if (qemu_loglevel_mask(CPU_LOG_PAGE)) {
        FILE *f = qemu_log_trylock();
        if (f) {
            fprintf(f, "guest_base  %p\n", (void *)guest_base);
            fprintf(f, "page layout changed following binary load\n");
            page_dump(f);
            // 打印各种内存分布和地址映射、命令行参数等
            fprintf(f, "end_code    0x" TARGET_ABI_FMT_lx "\n",
                    info->end_code);
            fprintf(f, "start_code  0x" TARGET_ABI_FMT_lx "\n",
                    info->start_code);
            fprintf(f, "start_data  0x" TARGET_ABI_FMT_lx "\n",
                    info->start_data);
            fprintf(f, "end_data    0x" TARGET_ABI_FMT_lx "\n",
                    info->end_data);
            fprintf(f, "start_stack 0x" TARGET_ABI_FMT_lx "\n",
                    info->start_stack);
            fprintf(f, "brk         0x" TARGET_ABI_FMT_lx "\n",
                    info->brk);
            fprintf(f, "entry       0x" TARGET_ABI_FMT_lx "\n",
                    info->entry);
            fprintf(f, "argv_start  0x" TARGET_ABI_FMT_lx "\n",
                    info->argv);
            fprintf(f, "env_start   0x" TARGET_ABI_FMT_lx "\n",
                    info->envp);
            fprintf(f, "auxv_start  0x" TARGET_ABI_FMT_lx "\n",
                    info->saved_auxv);
            qemu_log_unlock(f);
        }
    }

    target_set_brk(info->brk); // 堆边界
    syscall_init();         // 注册各系统调用处理函数
    signal_init(rtsig_map); // 初始化信号处理系统

    /* Now that we've loaded the binary, GUEST_BASE is fixed.  Delay
       generating the prologue until now so that the prologue can take
       the real value of GUEST_BASE into account.  */
    tcg_prologue_init(); // tcg的前导代码，用于状态同步和TB调度

    target_cpu_copy_regs(env, regs); // regs存入env中

    if (gdbstub) {
        gdbserver_start(gdbstub, &error_fatal);
    }

#ifdef CONFIG_SEMIHOSTING
    qemu_semihosting_guestfd_init();
#endif
    // 模拟CPU开始执行guest程序，并在运行过程中处理系统调用、中断、异常等事件，使得guest程序按照真实CPU被逐步执行
    cpu_loop(env);
    /* never exits */
    return 0;
}

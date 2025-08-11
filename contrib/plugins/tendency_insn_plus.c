
/*
    cd ~/work/qemu/
    gcc -Wall -fPIC -shared -o ./target_dir/plugin_so/tendency_insn.so ./contrib/plugins/tendency_insn.c -I ./include/qemu $(pkg-config --cflags --libs gio-2.0 glib-2.0) -I /usr/local/include/capstone/ -L /usr/local/lib/ -lcapstone
    ./target_dir/qemu_elf/qemu-riscv64 -d plugin -D ./target_dir/res/tendency_outs2.log -plugin ./target_dir/plugin_so/tendency_insn_plus.so ./target_dir/elf_dir/hello.elf
*/
#include <sched.h>
#include<sys/syscall.h>
int a = SYS_mmap;
// #include <sched.h>
#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <inttypes.h>
#include "glibconfig.h"
#include "qemu-plugin.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
static int max_vcpus;
static qemu_plugin_u64 insn_count;
static qemu_plugin_u64 insn_branch_count;
static qemu_plugin_u64 insn_branch_jmp_count;

static uint64_t prev_vaddr = 0;
static uint64_t now_vaddr = 0;
static size_t prev_size = 0;        

static GTree *tree_branch = NULL;
static GTree *tree_jmp_branch = NULL;
static GArray *words = NULL;
FILE *fp = NULL;
typedef struct counternode{
    qemu_plugin_u64 counter;
} CounterNode;
gint str_compare(gconstpointer a, gconstpointer b);
gint str_compare(gconstpointer a, gconstpointer b) {
    return g_strcmp0((const char *)a, (const char *)b);
}
// static void vcpu_insn_exec(unsigned int vcpu_index, void *userdata)
// {
//     // qemu_plugin_u64_add(insn_count, vcpu_index, 1);
//     qemu_plugin_u64_add(((CounterNode*)userdata)->counter, vcpu_index, 1);
// }
typedef struct user_data_branch{
    char* mnemonic;
    struct qemu_plugin_insn *insn;
} User_Data_Branch;

typedef struct user_data_jmp_branch{
    char* mnemonic;
    struct qemu_plugin_insn *insn;

    uint64_t now_vaddr;
    uint64_t prev_vaddr;
    size_t prev_size;
}User_Data_Jmp_Branch;

gboolean print_free_pair(gpointer key, gpointer value, gpointer user_data);
gboolean print_free_pair(gpointer key, gpointer value, gpointer user_data) {
    char *str = key;
    CounterNode *node = value;
    if(node == NULL){
         fprintf(stderr, "print_free_pair is false\n");
    }
    uint64_t total = 0;
    g_autoptr(GString) result = g_string_new("|--- count_each_insn ---|\n");
    for(int i = 0; i < max_vcpus + 1; i++)
    {
        total += qemu_plugin_u64_get(node->counter, i);
    }
    // check_all += total;
    if(GPOINTER_TO_INT(user_data) == true)
    {
        printf("total_branch:%s->%" PRIu64 "\n", str, total);
        g_string_append_printf(result, "total_branch:%s->%"PRIu64"\n", str, total);
    }else{
        printf("total_jmp_branch:%s->%" PRIu64 "\n", str, total);
        g_string_append_printf(result, "total_jmp_branch:%s->%"PRIu64"\n", str, total);
    }
    fprintf(fp, "%s", result->str);
    fflush(fp);
    // qemu_plugin_outs(result->str);

    qemu_plugin_scoreboard_free(node->counter.score);
    g_free(node);
    // g_free(str); // key不需要手动free
    return FALSE;
}

void parse_line(const char *line, char *mnemonic, size_t msize, char *operands, size_t osize);
void parse_line(const char *line, char *mnemonic, size_t msize, char *operands, size_t osize) {
    size_t i = 0;
    while (*line == ' ' || *line == '\t') line++;
    i = 0;
    while (*line != ' ' && *line != '\t' && *line != '\0' && i < msize - 1) {
        mnemonic[i++] = *line++;
    }
    mnemonic[i] = '\0';
    while (*line == ' ' || *line == '\t') line++;
    i = 0;
    while (*line != '#' && *line != '\0' && *line != '\n' && i < osize - 1) {
        operands[i++] = *line++;
    }
    while (i > 0 && (operands[i-1] == ' ' || operands[i-1] == '\t')) i--;
    operands[i] = '\0';
}

static void insn_exec_cb(unsigned int vcpu_index, void *userdata)
{
    qemu_plugin_u64_add(insn_count, vcpu_index, 1);
    fprintf(fp, "%s", (char*)userdata);
    fflush(fp);
    // qemu_plugin_outs((char*)userdata);
    // g_free(userdata); 
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    printf("this tb is start!\n");
    printf("max_vcpus:%d\n", max_vcpus);
    // printf("id:%" PRIu64 "\n", id);
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        // qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_ADD_U64, insn_count, 1);
        char *insn_disas;
        insn_disas = qemu_plugin_insn_disas(insn);
        // uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
        char mnemonic[8] = {0};
        char operands[32] = {0};
        parse_line(insn_disas, mnemonic, sizeof(mnemonic), operands, sizeof(operands));

        now_vaddr = qemu_plugin_insn_vaddr(insn);
        printf("|--- mnemonic:%s\tnow_vaddr:%" PRIx64 "\t prev_vaddr:%" PRIx64 "\t\n", mnemonic, now_vaddr, prev_vaddr);
        
        CounterNode *branch_node = g_tree_lookup(tree_branch, mnemonic);
        if(branch_node)
        {
            printf("*mnemonic:%s\tnow_vaddr:%" PRIx64 "\tprev_vaddr:%" PRIx64 "\tprev_size:%zu\n",mnemonic, now_vaddr, prev_vaddr, prev_size);
            if(now_vaddr != prev_vaddr + prev_size)
            {
                // 跳转
                printf("|---this branch jmp: now_vaddr:%" PRIx64 "\t prev_vaddr:%" PRIx64 "\t size:%zu ---|\n", now_vaddr, prev_vaddr, prev_size);
                qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_ADD_U64, insn_branch_jmp_count, 1);

                CounterNode *jmp_node = g_tree_lookup(tree_jmp_branch, mnemonic);
                if (jmp_node) {
                    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_ADD_U64, jmp_node->counter, 1);
                }
            }
            qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_ADD_U64, insn_branch_count, 1); // 分支总体加1
            qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_ADD_U64, branch_node->counter, 1); // 对应分支指令加1
        }

        printf("start:|--- mnemonic:%s\tnow_vaddr:%" PRIx64 "\t prev_vaddr:%" PRIx64 "\tsize:%zu\n", mnemonic, now_vaddr, prev_vaddr, prev_size);

        prev_vaddr = qemu_plugin_insn_vaddr(insn);
        prev_size = qemu_plugin_insn_size(insn);
        // qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS, NULL);

        printf("end:|--- mnemonic:%s\tnow_vaddr:%" PRIx64 "\t prev_vaddr:%" PRIx64 "\tsize:%zu\n", mnemonic, now_vaddr, prev_vaddr, prev_size);

        char buf[64];
        snprintf(buf, sizeof(buf), "%s %s\n", mnemonic, operands);
        // snprintf(buf, sizeof(buf), "%s\n", mnemonic);
        // snprintf(buf, sizeof(buf),"%s\n",mnemonic);
        char *buf_copy = g_strdup(buf); // 不copy一份的话执行时已经变成脏数据了
        qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec_cb, QEMU_PLUGIN_CB_NO_REGS, buf_copy);

        // qemu_plugin_outs(buf);

        g_free(insn_disas);
    }
}

static void plugin_exit(qemu_plugin_id_t id, void *user_data)
{
    // g_autoptr不需要手动free --当 result 离开作用域（plugin_exit return）时，编译器自动调用 g_string_free(result, TRUE);
    g_autoptr(GString) result_branch = g_string_new("|--- count ---|\n");
    g_autoptr(GString) result_jmp_branch = g_string_new("|--- count ---|\n");
    uint64_t total_insn = 0, total_insn_branch_count = 0, total_insn_branch_jmp_count = 0;
    for(int i = 0; i < max_vcpus + 1; i++)
    {
        total_insn += qemu_plugin_u64_get(insn_count, i);
        total_insn_branch_count += qemu_plugin_u64_get(insn_branch_count, i);
        total_insn_branch_jmp_count += qemu_plugin_u64_get(insn_branch_jmp_count, i);
    }

    printf("total_insn:%" PRIu64 "\ntotal_insn_branch_count:%" PRIu64 "\ntotal_insn_branch_jmp_count:%" PRIu64 "\n", 
        total_insn, total_insn_branch_count, total_insn_branch_jmp_count);
    double jmp_rate = (double)total_insn_branch_jmp_count / (double)total_insn_branch_count;
    printf("rate of branch jmp:%f\n", jmp_rate);
    g_string_append_printf(result_branch, "insn_count:%" PRIu64"\n""insn_branch_count:%" PRIu64"\ninsn_branch_jmp_count:%" PRIu64"\n"
        , total_insn, total_insn_branch_count, total_insn_branch_jmp_count);
    
    g_tree_foreach(tree_branch, print_free_pair, GINT_TO_POINTER(1));
    g_tree_foreach(tree_jmp_branch, print_free_pair, GINT_TO_POINTER(0));
    
    fprintf(fp, "%s", result_branch->str);
    fflush(fp);
    // qemu_plugin_outs(result_branch->str);

    qemu_plugin_scoreboard_free(insn_count.score);
    qemu_plugin_scoreboard_free(insn_branch_count.score);
    qemu_plugin_scoreboard_free(insn_branch_jmp_count.score);
    // g_tree_destroy(tree_branch);
    g_array_free(words, TRUE);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
    fp = fopen("./target_dir/res/plugin_output1.log", "w");
    // fp = fopen("./plugin.log", "w");
    if (!fp) {
        fprintf(stderr, "Failed to open plugin log file!\n");
        return -1;
    }
    // fprintf(fp, "Plugin start!\n");
    // fflush(fp);
    tree_branch = g_tree_new(str_compare);
    tree_jmp_branch = g_tree_new(str_compare);
    words = g_array_new(TRUE, TRUE, sizeof(char *));
    const char *batch[] = {"jal", "bne", "bgeu", "beqz", "j", 
                           "ble", "jalr", "blt", "beq", "bleu", 
                           "bnez", "ret", "bge", "bltu", "bgtu", 
                           "jr"};
    
    g_array_append_vals(words, batch, sizeof(batch)/sizeof(batch[0]));
    for (guint i = 0; i < words->len; i++) {
        char *word = g_array_index(words, char*, i);
        gpointer val = g_tree_lookup(tree_branch, word);
        if(val != NULL) continue; // 重复了
        CounterNode *node_branch = g_new0(CounterNode, 1);
        CounterNode *node_jmp_branch = g_new0(CounterNode, 1);
        node_branch->counter = qemu_plugin_scoreboard_u64(qemu_plugin_scoreboard_new(sizeof(uint64_t)));
        node_jmp_branch->counter = qemu_plugin_scoreboard_u64(qemu_plugin_scoreboard_new(sizeof(uint64_t)));
        g_tree_insert(tree_branch, word, node_branch);
        g_tree_insert(tree_jmp_branch, word, node_jmp_branch);
        // g_tree_insert(tree_branch, word, GINT_TO_POINTER(0));
    }        

    max_vcpus = qemu_plugin_num_vcpus();
    // printf("max_vpus:%d\n", max_vcpus);
    insn_count = qemu_plugin_scoreboard_u64(qemu_plugin_scoreboard_new(sizeof(uint64_t) * (max_vcpus + 1)));
    insn_branch_count = qemu_plugin_scoreboard_u64(qemu_plugin_scoreboard_new(sizeof(uint64_t) * (max_vcpus + 1)));
    insn_branch_jmp_count = qemu_plugin_scoreboard_u64(qemu_plugin_scoreboard_new(sizeof(uint64_t) * (max_vcpus + 1)));

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
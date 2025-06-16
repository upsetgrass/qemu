/*
 *  qemu user cpu loop
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
#include "qemu/error-report.h"
#include "qemu.h"
#include "user-internals.h"
#include "user/cpu_loop.h"
#include "signal-common.h"
#include "elf.h"
#include "semihosting/common-semi.h"

// // RISCVCPU-ArchCPU -> [CPUState， CPURISCVState, ...]
void cpu_loop(CPURISCVState *env)
{
    // env_cpu就是把env的地址回退到ArchCPU的起始地址，同时这个起始地址也是CPUState通用的起始地址，即可转换
    CPUState *cs = env_cpu(env); // 通过特定架构的状态指针env获取到这个CPU实例通用状态结构体
    int trapnr; // 处理trap时的编号
    target_ulong ret; 

    // 循环执行
    for (;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs); // 调用TCG编译器，如果遇到异常（系统调用、非法指令、断点等）返回异常号
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);
        
        // 处理各个的异常
        switch (trapnr) {
        case EXCP_INTERRUPT:        // 中断
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_ATOMIC:           // 处理原子操作
            cpu_exec_step_atomic(cs);
            break;
        case RISCV_EXCP_U_ECALL:    // riscv系统调用
            env->pc += 4;
            if (env->gpr[xA7] == TARGET_NR_riscv_flush_icache) {
                /* riscv_flush_icache_syscall is a no-op in QEMU as
                   self-modifying code is automatically detected */
                ret = 0;
            } else {
                ret = do_syscall(env,
                                 env->gpr[(env->elf_flags & EF_RISCV_RVE)
                                    ? xT0 : xA7],
                                 env->gpr[xA0],
                                 env->gpr[xA1],
                                 env->gpr[xA2],
                                 env->gpr[xA3],
                                 env->gpr[xA4],
                                 env->gpr[xA5],
                                 0, 0);
            }
            if (ret == -QEMU_ERESTARTSYS) {
                env->pc -= 4;
            } else if (ret != -QEMU_ESIGRETURN) {
                env->gpr[xA0] = ret;
            }
            if (cs->singlestep_enabled) {
                goto gdbstep;
            }
            break;
        case RISCV_EXCP_ILLEGAL_INST: // 非法指令
            force_sig_fault(TARGET_SIGILL, TARGET_ILL_ILLOPC, env->pc);
            break;
        case RISCV_EXCP_BREAKPOINT: // 调试断点
        case EXCP_DEBUG:
        gdbstep:
            force_sig_fault(TARGET_SIGTRAP, TARGET_TRAP_BRKPT, env->pc);
            break;
        case RISCV_EXCP_SEMIHOST: // 半主机调试接口
            do_common_semihosting(cs);
            env->pc += 4;
            break;
        default:                // 未知异常退出
            EXCP_DUMP(env, "\nqemu: unhandled CPU exception %#x - aborting\n",
                     trapnr);
            exit(EXIT_FAILURE);
        }

        process_pending_signals(env); // 转发用户发送给qemu的信号（Ctrl+C...）给到guest，模拟正确行为
        // 开启下一轮
    }
}

void target_cpu_copy_regs(CPUArchState *env, target_pt_regs *regs)
{
    CPUState *cpu = env_cpu(env);
    TaskState *ts = get_task_state(cpu);
    struct image_info *info = ts->info;

    env->pc = regs->sepc;
    env->gpr[xSP] = regs->sp;
    env->elf_flags = info->elf_flags;

    if ((env->misa_ext & RVE) && !(env->elf_flags & EF_RISCV_RVE)) {
        error_report("Incompatible ELF: RVE cpu requires RVE ABI binary");
        exit(EXIT_FAILURE);
    }

    ts->stack_base = info->start_stack;
    ts->heap_base = info->brk;
    /* This will be filled in on the first SYS_HEAPINFO call.  */
    ts->heap_limit = 0;
}

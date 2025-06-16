/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Definition of TranslationBlock.
 *  Copyright (c) 2003 Fabrice Bellard
 */

#ifndef EXEC_TRANSLATION_BLOCK_H
#define EXEC_TRANSLATION_BLOCK_H

#include "qemu/atomic.h"
#include "qemu/thread.h"
#include "exec/cpu-common.h"
#include "exec/vaddr.h"
#ifdef CONFIG_USER_ONLY
#include "qemu/interval-tree.h"
#endif

/*
 * Page tracking code uses ram addresses in system mode, and virtual
 * addresses in userspace mode.  Define tb_page_addr_t to be an
 * appropriate type.
 */
#if defined(CONFIG_USER_ONLY)
typedef vaddr tb_page_addr_t;
#define TB_PAGE_ADDR_FMT "%" VADDR_PRIx
#else
typedef ram_addr_t tb_page_addr_t;
#define TB_PAGE_ADDR_FMT RAM_ADDR_FMT
#endif

/*
 * Translation Cache-related fields of a TB.
 * This struct exists just for convenience; we keep track of TB's in a binary
 * search tree, and the only fields needed to compare TB's in the tree are
 * @ptr and @size.
 * Note: the address of search data can be obtained by adding @size to @ptr.
 */
// TB缓存相关数据结构，qemu中有一颗二叉搜索树来组织所有的TB，用于查找，使用ptr和size来判断两个TB是否是同一个TB，是否在同一个位置
struct tb_tc {
    const void *ptr;    /* pointer to the translated code */ // 指向host code buffer的指针
    size_t size;    // 代码指令条数
};

struct TranslationBlock {
    /*
     * Guest PC corresponding to this block.  This must be the true
     * virtual address.  Therefore e.g. x86 stores EIP + CS_BASE, and
     * targets like Arm, MIPS, HP-PA, which reuse low bits for ISA or
     * privilege, must store those bits elsewhere.
     *
     * CF_PCREL用于页内代码共享，TB中生成的指令（host代码）是以“页内偏移量”的形式编码的，不依赖于完整的虚拟地址
     * TB自身的pc字段不再表示实际的执行地址，真正的 PC 必须从 ENV 中取得，且具体做法依赖于具体的 guest 架构（target-specific）。
     * If CF_PCREL, the opcodes for the TranslationBlock are written
     * such that the TB is associated only with the physical page and
     * may be run in any virtual address context.  In this case, PC
     * must always be taken from ENV in a target-specific manner.
     * Unwind information is taken as offsets from the page, to be
     * deposited into the "current" PC.
     */
    vaddr pc; // 当前TB的虚拟地址

    /* 
     * Target-specific data associated with the TranslationBlock, e.g.:
     * x86: the original user, the Code Segment virtual base,
     * arm: an extension of tb->flags,
     * s390x: instruction data for EXECUTE,
     * sparc: the next pc of the instruction queue (for delay slots).
     */
    uint64_t cs_base; // 代码段基地址

    uint32_t flags; /* flags defining in which context the code was generated */ /* TB创建时的环境上下文 */
    uint32_t cflags;    /* compile flags */ /* 翻译行为编译选项 */

/* Note that TCG_MAX_INSNS is 512; we validate this match elsewhere. cflags */
#define CF_COUNT_MASK    0x000001ff
#define CF_NO_GOTO_TB    0x00000200 /* Do not chain with goto_tb */
#define CF_NO_GOTO_PTR   0x00000400 /* Do not chain with goto_ptr */
#define CF_SINGLE_STEP   0x00000800 /* gdbstub single-step in effect */
#define CF_MEMI_ONLY     0x00001000 /* Only instrument memory ops */
#define CF_USE_ICOUNT    0x00002000
#define CF_INVALID       0x00004000 /* TB is stale. Set with @jmp_lock held */
#define CF_PARALLEL      0x00008000 /* Generate code for a parallel context */
#define CF_NOIRQ         0x00010000 /* Generate an uninterruptible TB */
#define CF_PCREL         0x00020000 /* Opcodes in TB are PC-relative */
#define CF_BP_PAGE       0x00040000 /* Breakpoint present in code page */
#define CF_CLUSTER_MASK  0xff000000 /* Top 8 bits are cluster ID */
#define CF_CLUSTER_SHIFT 24

    /*
     * Above fields used for comparing
     */

    /* size of target code for this block (1 <= size <= TARGET_PAGE_SIZE)  */
    uint16_t size;   // tb翻译guest指令的字节总长度
    uint16_t icount; // 指令条数

    struct tb_tc tc; // TCG生成的host机器码相关字段
 
    /*
     * Track tb_page_addr_t intervals that intersect this TB.
     * For user-only, the virtual addresses are always contiguous,
     * and we use a unified interval tree.  For system, we use a
     * linked list headed in each PageDesc.  Within the list, the lsb
     * of the previous pointer tells the index of page_next[], and the
     * list is protected by the PageDesc lock(s).
     */
#ifdef CONFIG_USER_ONLY
    IntervalTreeNode itree;
#else
    uintptr_t page_next[2]; // 当前TB在页page_addr[0]链表中的next指针，用于TB失效时找到TB
    tb_page_addr_t page_addr[2]; // TB所在页page_addr[0]，及出现跨页时的下一页page_addr[1]
#endif

    /* jmp_lock placed here to fill a 4-byte hole. Its documentation is below */
    QemuSpin jmp_lock;

    /* 
     * The following data are used to directly call another TB from
     * the code of this one. This can be done either by emitting direct or
     * indirect native jump instructions. These jumps are reset so that the TB
     * just continues its execution. The TB can be linked to another one by
     * setting one of the jump targets (or patching the jump instruction). Only
     * two of such jumps are supported.
     */
#define TB_JMP_OFFSET_INVALID 0xffff /* indicates no jump generated */  // 标识跳转不存在或无效
    uint16_t jmp_reset_offset[2]; /* offset of original jump target */  // TB末尾原始跳转指令的偏移，用于TB被链接后，目标TB被修改/失效后的恢复原始的跳转指令
    uint16_t jmp_insn_offset[2];  /* offset of direct jump insn */      // 和jmp_reset_offset类似，只不过insn这一个是直接是跳转指令的地址，reset是需要恢复的最后几条指令的偏移
    uintptr_t jmp_target_addr[2]; /* target address */                  // 执行完当前TB后，跳转到哪个地址继续执行
    // 0x00f0        mov eax, ebx
    // 0x00f3        cmp eax, 0
    // 0x00f6        jz 0xdeadbeef  ; 这是原始跳转
    // tb->jmp_insn_offset[0] = 0x00f6;     // 跳转指令写入处
    // tb->jmp_reset_offset[0] = 0x00f3;    // 需要恢复的起始处
    // tb->jmp_target_addr[0] = (uintptr_t)tb2->tc.ptr; // TB2 地址

    /*
     * Each TB has a NULL-terminated list (jmp_list_head) of incoming jumps.
     * Each TB can have two outgoing jumps, and therefore can participate
     * in two lists. The list entries are kept in jmp_list_next[2]. The least
     * significant bit (LSB) of the pointers in these lists is used to encode
     * which of the two list entries is to be used in the pointed TB.
     *
     * List traversals are protected by jmp_lock. The destination TB of each
     * outgoing jump is kept in jmp_dest[] so that the appropriate jmp_lock
     * can be acquired from any origin TB.
     *
     * jmp_dest[] are tagged pointers as well. The LSB is set when the TB is
     * being invalidated, so that no further outgoing jumps from it can be set.
     *
     * jmp_lock also protects the CF_INVALID cflag; a jump must not be chained
     * to a destination TB that has CF_INVALID set.
     */
    uintptr_t jmp_list_head;
    uintptr_t jmp_list_next[2];
    uintptr_t jmp_dest[2];
};

/* The alignment given to TranslationBlock during allocation. */
#define CODE_GEN_ALIGN  16

/* Hide the qatomic_read to make code a little easier on the eyes */
static inline uint32_t tb_cflags(const TranslationBlock *tb)
{
    return qatomic_read(&tb->cflags);
}

bool tcg_cflags_has(CPUState *cpu, uint32_t flags);
void tcg_cflags_set(CPUState *cpu, uint32_t flags);

#endif /* EXEC_TRANSLATION_BLOCK_H */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <qemu-plugin.h>

// 必须导出这个符号，声明插件使用的 API 版本
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

// 执行时回调
static void insn_exec_cb(unsigned int vcpu_id, void *userdata)
{
    uint64_t insn_addr = (uintptr_t)userdata;
    printf("[QEMU Plugin] vCPU %u executing instruction at 0x%" PRIx64 "\n",
           vcpu_id, insn_addr);
}

// TB 翻译时回调
static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t num_insns = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < num_insns; ++i) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t insn_addr = qemu_plugin_insn_vaddr(insn);

        // 为该指令注册执行时回调
        qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec_cb,
                                               QEMU_PLUGIN_INLINE, (void *)insn_addr);
    }
}

// QEMU 退出时回调
static void plugin_exit_cb(qemu_plugin_id_t id, void *p)
{
    printf("[QEMU Plugin] Exiting.\n");
}

// 插件入口：安装时调用
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv)
{
    printf("[QEMU Plugin] Plugin loaded. QEMU Plugin API version: %d\n",
           info->version);

    // 注册 TB 翻译回调
    qemu_plugin_register_tb_trans_cb(id, tb_trans_cb);

    // 注册退出回调
    qemu_plugin_register_atexit_cb(id, plugin_exit_cb, NULL);

    return 0;
}

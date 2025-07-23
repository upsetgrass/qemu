/*
    gcc -Wall -fPIC -shared -o ~/work/qemu/target_dir/plugin_so/my_first_plugin.so ~/work/qemu/tests/tcg/plugins/my_first_plugin.c $(pkg-config --cflags --libs glib-2.0) -I ~/work/qemu/include/qemu
    ./qemu-riscv64 -d plugin -D ~/work/qemu/target_dir/res/my_first_plugin.log -plugin ../target_dir/plugin_so/my_first_plugin.so ../target_dir/elf_dir/hello.elf
*/


#include <stdio.h>
#include <qemu-plugin.h>
#include <glib.h>
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;



static qemu_plugin_u64 insn_count;
static GHashTable* insn_addrs = NULL; // 近似存储了静态指令数  QEMU 运行时翻译过程中遇到的唯一地址数量

static void vcpu_insn_exec(unsigned int vcpu_index, void *userdata)
{
    qemu_plugin_u64_add(insn_count, vcpu_index, 1);
}
// static void vcpu_tb_exec(unsigned int vcpu_index, void *userdata)
// {
//     dynamoic_cnt += qemu_plugin_tb_n_insns((struct qemu_plugin_tb *)userdata);
// }

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t cnt = qemu_plugin_tb_n_insns(tb);
    // size_t* dynamoic_cnt = g_malloc(sizeof(size_t));
    for(size_t i = 0; i < cnt; i++)
    {
        struct qemu_plugin_insn * insn = qemu_plugin_tb_get_insn(tb, i);
        /* 
            第三个参数flags决定是否获取该指令执行时的寄存器值（寄存器上下文），是否保持寄存器上下文的开销较大，所以需要参数控制决定
               QEMU_PLUGIN_CB_NO_REGS-不需要 
               QEMU_PLUGIN_CB_R_REGS-需要读取寄存器状态,保存一次读寄存器
               QEMU_PLUGIN_CB_RW_REGS-需要读+写寄存器状态，在执行时保存寄存器，且允许修改寄存器，然后写回
            第四个参数是传给回调的参数，是自定义类型
        */ 
        uint64_t addr = qemu_plugin_insn_vaddr(insn);
        gpointer key = GINT_TO_POINTER(addr);
        if(!g_hash_table_contains(insn_addrs, key))
        {
            g_hash_table_add(insn_addrs, key);
        }
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS, NULL);
    }
    // qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec, QEMU_PLUGIN_CB_NO_REGS, tb); // 这里统计不妥，因为可能会遇到tb中某条指令异常或中断等情况
}

// plugin结束时一般用于统计、释放之前创建的空间等
static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    GString* msg = g_string_new(NULL);
    uint64_t val = qemu_plugin_u64_sum(insn_count);
    g_string_printf(msg, "static_counter:%u\ndynamoic_counter:%"PRIu64"\n", g_hash_table_size(insn_addrs), val);
    qemu_plugin_outs(msg->str);
    g_string_free(msg, true);
    g_hash_table_destroy(insn_addrs);
    qemu_plugin_scoreboard_free(insn_count.score);
}

/*
    id   - 插件实例ID，qemu内部提供，后续注册，卸载时会用到
    info - 当前的架构、qemu插件API版本、用户模式还是系统模式，有多少个vCPU
    argc、args是qemu命令行参数中-plugin传给插件的额外参数

    qemu_plugin_install只会调用一次，之后就靠注册的回调来工作
    qemu_plugin_install的返回值0代表成功，1代表失败

*/
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
    fprintf(stdout, "success to start the plugin!\n");
    insn_addrs = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (info->version.cur < 3){
        // info->version.cur - 当前qemu插件支持的API版本号
        // info->version.min - 当前qemu插件兼容的最小版本
        // eg:当前qemu是v2，但是插件中用了v3独有的API，所以就会出问题,需要提示升级，直接返回
        fprintf(stderr, "plugin needs API bigger than v2\n");
        return 1;
    }
    if(info->system_emulation == true)
    {
        fprintf(stderr,"this plugin only use to user-mode\n");
        return 1;
    }
    // version is right, mode is right
    GString *msg = g_string_new(NULL);
    g_string_printf(msg, "runging on %s, smp_vcpus=%d, mode=user-mode\n", info->target_name,
                                                                         info->system.smp_vcpus);
    qemu_plugin_outs(msg->str);
    g_string_free(msg, TRUE);

    insn_count = qemu_plugin_scoreboard_u64(qemu_plugin_scoreboard_new(sizeof(uint64_t)));
    // start register
    // qemu中插桩基本单元是TB，若是想要对指令做分析，也需要在针对TB的回调中循环遍历指令
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
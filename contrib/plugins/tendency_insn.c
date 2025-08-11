// /*
//     gcc -Wall -fPIC -shared -o ./target_dir/plugin_so/tendency_insn.so ./contrib/plugins/tendency_insn.c -I ./include/qemu/ $(pkg-config --cflags --libs glib-2.0 gio-2.0) -L /usr/local/lib -lcapstone -I /usr/local/include/capstone
    
//     强行指定动态链接库是/usr/local/bin中的capstone-6.0
    
//     LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH LD_PRELOAD=/usr/local/lib/libcapstone.so ./qemu_elf/qemu-riscv64 -d plugin -D ./res/tendency.log   -plugin ./plugin_so/tendency_insn.so ./elf_dir/hello.elf
// */
// #include <stdio.h>
// #include <gio/gio.h>
// #include <glib.h>
// #include "qemu-plugin.h"
// #include <inttypes.h>
// #include <capstone/capstone.h>

// // #include "riscv_insn_names.h"


// // #define g_ascii_strcasecmp GCMP
// // #define GCMP(a, b) (g_ascii_strcasecmp((a), (b)) == 0)
// QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
// static csh cs_handle;
// // 用 GHashTable 作为 set
// static GHashTable* dict_insn = NULL;

// // // 遍历打印 key
// // static void print_set(gpointer key, gpointer value, gpointer user_data) {
// //     g_print("%s\n", (char *)key);
// //     // return FALSE; // 继续遍历
// // }

// void capstone_tov_inv(uint8_t* insn_opcode, uint64_t vaddr, size_t size);
// void capstone_tov_inv(uint8_t* insn_opcode, uint64_t vaddr, size_t size)
// {
//     cs_insn *insn;
//     size_t count;

//     count = cs_disasm(cs_handle, insn_opcode, size, vaddr, 1, &insn);
//     if (count > 0) {
//         for (size_t j = 0; j < count; j++) {
//             // const char *real_name = RISCV_insn_name(cs_handle, insn->id);
//             char buf[256];
//             snprintf(buf,sizeof(buf), "0x%"PRIx64":\t%s\t%s\n",
//                    insn[j].address,
//                    insn[j].mnemonic,
//                    insn[j].op_str);
//             // printf("\n");
//             qemu_plugin_outs(buf);
//         }

//         cs_free(insn, count);
//     } else {
//         char err[128];
//         snprintf(err, sizeof(err),
//                  "ERROR: Failed to disassemble at 0x%" PRIx64 "\n", vaddr);
//         qemu_plugin_outs(err);
//     }


// }

// static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
// {
//     size_t n = qemu_plugin_tb_n_insns(tb);
//     for (size_t i = 0; i < n; i++) {
//         struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
//         // cs_insn *insn_inv;
//         // uint32_t insn_opcode = 0;
//         uint8_t code_buf[8]; 
//         uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
//         size_t size = qemu_plugin_insn_size(insn);
//         qemu_plugin_insn_data(insn, &code_buf, size);
        
//         capstone_tov_inv(code_buf, vaddr, size);
//         // printf("insn_opcode:%" PRIu32, insn_opcode);
//         // printf("\n");


//         // char *disas = qemu_plugin_insn_disas(insn);
//         // char mnemonic[32] = {0};
//         // sscanf(disas, "%31s", mnemonic);
//         // gchar *upper_mnemonic = g_ascii_strup(mnemonic, -1);
//         // if (
//         //     GCMP(upper_mnemonic, "JAL")  || GCMP(upper_mnemonic, "JALR") ||
//         //     GCMP(upper_mnemonic, "BEQ")  || GCMP(upper_mnemonic, "BNE")  ||
//         //     GCMP(upper_mnemonic, "BLT")  || GCMP(upper_mnemonic, "BGE")  ||
//         //     GCMP(upper_mnemonic, "BLTU") || GCMP(upper_mnemonic, "BGEU") ||
//         //     GCMP(upper_mnemonic, "RET")  || GCMP(upper_mnemonic, "CALL")
//         // )
//         // {
//         //     // printf("检测到 CFI: %s\n", upper_mnemonic);
//         //     qemu_plugin_outs(upper_mnemonic);
//         // }
//         // if (g_hash_table_contains(dict_insn, upper_mnemonic)) {
//         //     // printf("指令在 Set 中: %s\n", upper_mnemonic);
//         //     // qemu_plugin_outs(upper_mnemonic);
//         // } else {
//         //     qemu_plugin_outs("未知指令:");
//         //     qemu_plugin_outs(upper_mnemonic);
//         //     qemu_plugin_outs("\n");
//         //     // printf("未知指令: %s\n", upper_mnemonic);
//         // }
//         // g_free(disas);  // 注意释放
//     }
// }

// static void plugin_exit(qemu_plugin_id_t id, void *p)
// {
//     if (dict_insn) {
//         g_hash_table_destroy(dict_insn);
//     }
//     cs_close(&cs_handle);
// }

// QEMU_PLUGIN_EXPORT
// int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
// {
//     int major, minor;
//     cs_version(&major, &minor);
//     printf("Capstone version in plugin: %d.%d\n", major, minor);

//     cs_mode mode = CS_MODE_RISCV64 | CS_MODE_RISCVC | CS_MODE_LITTLE_ENDIAN;

//     if (cs_open(CS_ARCH_RISCV, mode, &cs_handle) != CS_ERR_OK) {
//         fprintf(stderr, "ERROR: Capstone initialization failed\n");
//         return -1;
//     }
//     cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);


//     // RV_ALL.txt中160行之前是指令，后面是伪指令MV开始
//     GFile *file = g_file_new_for_path("/home/happy_grass/work/qemu/target_dir/insn_type/riscv/RV_ALL.txt");
//     GError *error = NULL;
//     GFileInputStream *input = g_file_read(file, NULL, &error);
//     if (!input) {
//         g_printerr("打开文件失败: %s\n", error->message);
//         g_error_free(error);
//         g_object_unref(file);
//         return 1;
//     }
//     GDataInputStream *data_input = g_data_input_stream_new(G_INPUT_STREAM(input));
//     dict_insn = g_hash_table_new_full(
//         g_str_hash,
//         g_str_equal,
//         g_free,
//         NULL
//     );
//     gchar *line;
//     gsize length;
//     while ((line = g_data_input_stream_read_line(data_input, &length, NULL, &error)) != NULL) {
//         gchar *trimmed = g_strstrip(line);
//         gchar *upper = g_ascii_strup(trimmed, -1);
//         g_hash_table_add(dict_insn, upper);
//         g_free(line);
//     }
//     if (error) {
//         g_printerr("读文件出错: %s\n", error->message);
//         g_error_free(error);
//     }
//     // g_print("Set 中的指令有：\n");
//     // g_hash_table_foreach(dict_insn, print_set, NULL);
//     g_object_unref(data_input);
//     g_object_unref(input);
//     g_object_unref(file);

//     qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
//     qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
//     return 0;
// }

////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
    gcc -Wall -fPIC -shared -o ./target_dir/plugin_so/tendency_insn.so ./contrib/plugins/tendency_insn.c -I ./include/qemu/ $(pkg-config --cflags --libs glib-2.0 gio-2.0) -L /usr/local/lib -lcapstone -I /usr/local/include/capstone
    gcc -Wall -fPIC -shared -o ./target_dir/plugin_so/tendency_insn.so ./contrib/plugins/tendency_insn.c -I ./include/qemu $(pkg-config --cflags --libs gio-2.0 glib-2.0) -I /usr/local/include/capstone/ -L /usr/local/lib/ -lcapstone
    强行指定动态链接库是/usr/local/bin中的capstone-6.0
    
    LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH LD_PRELOAD=/usr/local/lib/libcapstone.so ./qemu_elf/qemu-riscv64 -d plugin -D ./res/tendency.log   -plugin ./plugin_so/tendency_insn.so ./elf_dir/hello.elf
*/
#include <stdio.h>
#include <glib.h>
#include <string.h>
// #include <sys/types.h>
#include <inttypes.h>
#include "qemu-plugin.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
static int max_vcpus;
static qemu_plugin_u64 insn_count;
static qemu_plugin_u64 insn_branch_count;
static qemu_plugin_u64 insn_branch_jmp_count;

// static void vcpu_insn_exec(unsigned int vcpu_index, void *userdata)
// {
//     printf("1\n");
//     // if (vcpu_index >= max_vcpus){
//     //     printf("vcpu_insn_exec-vcpu_index:%u\n", vcpu_index);
//     //     return;
//     // } 
     
//     qemu_plugin_u64_add(insn_count, vcpu_index, 1);
// }
// static void vcpu_insn_is_branch(unsigned int vcpu_index, void *userdata)
// {
//     printf("2\n");
//     // if (vcpu_index >= max_vcpus){
//     //     printf("vcpu_insn_is_branch-vcpu_index:%u\n", vcpu_index);
//     //     return;
//     // }
//     // printf("vcpu_insn_is_branch");
//     qemu_plugin_u64_add(insn_branch_count, vcpu_index, 1);
// }
// static void vcpu_insn_branch_jmp(unsigned int vcpu_index, void *userdata)
// {
//     printf("3\n");
//     // if (vcpu_index >= max_vcpus){
//     //     printf("vcpu_insn_branch_jmp-vcpu_index:%u\n", vcpu_index);
//     //     return;
//     // } 
//     qemu_plugin_u64_add(insn_branch_jmp_count, vcpu_index, 1);
// }



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

static uint64_t prev_vaddr = 0;
static uint64_t now_vaddr = 0;
static size_t prev_size = 0;
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    // if(id > max_vcpus)
    // {
    //     // printf("id >= max_vcpus\n");
    //     return;
    // }

    printf("max_vcpus:%d\n", max_vcpus);
    printf("id:%" PRIu64 "\n", id);
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_ADD_U64, insn_count, 1);
        char *insn_disas;
        insn_disas = qemu_plugin_insn_disas(insn);
        // uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
        char mnemonic[8] = {0};
        char operands[32] = {0};
        parse_line(insn_disas, mnemonic, sizeof(mnemonic), operands, sizeof(operands));

        now_vaddr = qemu_plugin_insn_vaddr(insn);
        // prev_vaddr = now_vaddr;
        // printf("now_vaddr:%" PRIx64 "\n", now_vaddr);
        // printf("prev_vaddr:%" PRIx64 "\n", prev_vaddr);
        // printf("now_vaddr + size:%" PRIx64 "\n", now_vaddr + size);
        
        // printf("|--- mnemonic:%s\n", mnemonic);
        // printf("%d\n", strcmp(mnemonic, "jal") == 0);

        printf("|--- now_vaddr:%" PRIx64 "\t prev_vaddr:%" PRIx64 "\t\n", now_vaddr, prev_vaddr);

        if(now_vaddr != prev_vaddr + prev_size /* && prev_vaddr != 0*/)
        {
            // 跳转
            printf("|---this branch jmp: now_vaddr:%" PRIx64 "\t prev_vaddr:%" PRIx64 "\t size:%zu ---|\n", now_vaddr, prev_vaddr, prev_size);
            qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_ADD_U64, insn_branch_jmp_count, 1);
            // qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_branch_jmp, QEMU_PLUGIN_CB_NO_REGS, NULL);

            qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_ADD_U64, insn_branch_jmp_count, 1);
        }

        if(strcmp(mnemonic, "jal") == 0 || strcmp(mnemonic, "jalr") == 0 || strcmp(mnemonic, "ret") == 0 || 
           strcmp(mnemonic, "bne") == 0 || strcmp(mnemonic, "blt") == 0  || strcmp(mnemonic, "bge") == 0 || 
           strcmp(mnemonic, "bgeu") == 0|| strcmp(mnemonic, "beq") == 0  || strcmp(mnemonic, "bltu") == 0||
           strcmp(mnemonic, "beqz") == 0|| strcmp(mnemonic, "bleu") == 0 || strcmp(mnemonic, "bgtu") == 0||
           strcmp(mnemonic, "j") == 0   || strcmp(mnemonic, "bnez") == 0 || strcmp(mnemonic, "jr") == 0  ||
           strcmp(mnemonic, "ble") == 0
        ){
            // 分支指令
            qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_ADD_U64, insn_branch_count, 1);
            // qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_is_branch, QEMU_PLUGIN_CB_NO_REGS, NULL);
            // prev_vaddr = qemu_plugin_insn_vaddr(insn);
            // prev_size = qemu_plugin_insn_size(insn);
            printf("*** this is branch:prev_vaddr:%" PRIx64 "\n", prev_vaddr);
        }
        else {
            // 不是分支指令，置空
            // prev_vaddr = 0;
            // prev_size = qemu_plugin_insn_size(insn);
        }
        prev_vaddr = qemu_plugin_insn_vaddr(insn);
        prev_size = qemu_plugin_insn_size(insn);
        // qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS, NULL);

        char buf[256];
        snprintf(buf, sizeof(buf), "%s %s\n", mnemonic, operands);
        // snprintf(buf, sizeof(buf),"%s\n",mnemonic);
        qemu_plugin_outs(buf);

        g_free(insn_disas);
    }
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_autoptr(GString) result = g_string_new("|--- count ---|\n");
    
    uint64_t total_insn = 0, total_insn_branch_count = 0, total_insn_branch_jmp_count = 0;
    for(int i = 0; i < max_vcpus + 1; i++)
    {
        total_insn = qemu_plugin_u64_get(insn_count, i);
        total_insn_branch_count = qemu_plugin_u64_get(insn_branch_count, i);
        total_insn_branch_jmp_count = qemu_plugin_u64_get(insn_branch_jmp_count, i);
    }

    printf("total_insn:%" PRIu64 "\ntotal_insn_branch_count%" PRIu64 "\ntotal_insn_branch_jmp_count:%" PRIu64 "\n", 
        total_insn, total_insn_branch_count, total_insn_branch_jmp_count);
    double jmp_rate = (double)total_insn_branch_jmp_count / (double)total_insn_branch_count;
    printf("rate of branch jmp:%f\n", jmp_rate);
    g_string_append_printf(result, "insn_count:%" PRIu64"\n""insn_branch_count:%" PRIu64"\ninsn_branch_jmp_count:%" PRIu64"\n"
        , total_insn, total_insn_branch_count, total_insn_branch_jmp_count);
    
    qemu_plugin_outs(result->str);
    qemu_plugin_scoreboard_free(insn_count.score);
    qemu_plugin_scoreboard_free(insn_branch_count.score);
    qemu_plugin_scoreboard_free(insn_branch_jmp_count.score);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
    max_vcpus = qemu_plugin_num_vcpus();
    // printf("max_vpus:%d\n", max_vcpus);
    insn_count = qemu_plugin_scoreboard_u64(qemu_plugin_scoreboard_new(sizeof(uint64_t) * (max_vcpus + 1)));
    insn_branch_count = qemu_plugin_scoreboard_u64(qemu_plugin_scoreboard_new(sizeof(uint64_t) * (max_vcpus + 1)));
    insn_branch_jmp_count = qemu_plugin_scoreboard_u64(qemu_plugin_scoreboard_new(sizeof(uint64_t) * (max_vcpus + 1)));

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}

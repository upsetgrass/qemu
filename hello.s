.section .text # 表示接下来的是可执行程序段
.globl _start    # 将_start声明为全局符号，链接器会将其作为程序入口
_start: # 程序入口函数
    li a7, 64    # Linux write 系统调用号  a7=64表示系统调用号64就是write
    li a0, 1     # stdout
    la a1, msg   # 字符串地址
    li a2, 12    # 字符串长度
    ecall        # 触发系统调用
    
    li a7, 93    # exit 系统调用
    li a0, 0     # 退出码，0-正常退出
    ecall        # 触发退出

.section .rodata # 只读数据段
msg:             # 字符串名
    .string "hello world\n"

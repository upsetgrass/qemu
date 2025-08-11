cd ~/work/qemu
./target_dir/qemu_elf/qemu-riscv64 -d plugin -D ./target_dir/res/tendency_outs3.log -plugin ./target_dir/plugin_so/tendency_insn_plus.so ./target_dir/elf_dir/hello.elf
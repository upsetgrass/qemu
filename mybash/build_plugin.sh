cd ~/work/qemu
gcc -Wall -fPIC -shared -o ./target_dir/plugin_so/tendency_insn_plus.so ./contrib/plugins/tendency_insn_plus.c -I ./include/qemu $(pkg-config --cflags --libs gio-2.0 glib-2.0)
    
echo "res path:./target_dir/plugin_so"
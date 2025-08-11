cd ~/work/qemu/
rm build/ -fr
./configure --target-list=riscv64-softmmu \
            --enable-plugins \
            --enable-debug \
            --enable-sdl \
            --enable-gtk \
            --enable-virtfs \
            --enable-slirp \
            --enable-vnc \
            --enable-spice

cd build

ninja -j 10
# x86_64-softmmu,
# cp ./qemu-system-riscv64 ../target_dir/qemu_elf/qemu-system-riscv64
# cp ./qemu-system-x86_64 ../target_dir/qemu_elf/qemu-system-x86_64
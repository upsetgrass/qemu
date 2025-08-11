{ pkgs ? import <nixpkgs> {} 

}:

let

  # Capstone: 启用 RISC-V B 扩展，仅构建 riscv 支持
  capstoneRiscv = pkgs.capstone.overrideAttrs (old: {
    cmakeFlags = (old.cmakeFlags or []) ++ [
      "-DCAPSTONE_RISCV64_B_EXTENSION=ON"
      "-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF"
      "-DCAPSTONE_RISCV_SUPPORT=ON"
      # 禁用其他架构
      "-DCAPSTONE_X86_SUPPORT=OFF"
      "-DCAPSTONE_ARM_SUPPORT=OFF"
      "-DCAPSTONE_ARM64_SUPPORT=OFF"
      "-DCAPSTONE_MIPS_SUPPORT=OFF"
      "-DCAPSTONE_PPC_SUPPORT=OFF"
      "-DCAPSTONE_SPARC_SUPPORT=OFF"
      "-DCAPSTONE_SYSZ_SUPPORT=OFF"
      "-DCAPSTONE_XCORE_SUPPORT=OFF"
      "-DCAPSTONE_M68K_SUPPORT=OFF"
      "-DCAPSTONE_TMS320C64X_SUPPORT=OFF"
    ];
  });
in
pkgs.mkShell {
  buildInputs = [
    # Capstone riscv 支持
    capstoneRiscv
  ];

  shellHook = ''
    export LIBRARY_PATH="${capstoneRiscv}/lib:$LIBRARY_PATH"
    echo "Capstone: $(cstool --version 2>&1 | head -n1)"
    echo "目录：${capstoneRiscv}"
    echo "编译时添加 -I${capstoneRiscv}/include -lcapstone"
  '';
}


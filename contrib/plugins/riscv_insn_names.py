with open("riscv_insn.txt", "r") as f:
    lines = f.readlines()

print("static const name_map riscv_insn_name_maps[] = {")
print("    { RISCV_INS_INVALID, NULL },")
for line in lines:
    line = line.strip().rstrip(",")
    if line.startswith("RISCV_INS_"):
        enum_name = line
        insn_name = line[len("RISCV_INS_"):].lower()
        print(f'    {{ {enum_name}, "{insn_name}" }},')
print("};")

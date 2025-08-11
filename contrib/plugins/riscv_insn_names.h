#ifndef RISCV_INSN_NAME_H
#define RISCV_INSN_NAME_H

#ifdef __cplusplus
extern "C" {
#endif

#include "capstone/capstone.h"

// 如果你的 name_map 在 capstone 内有就包含，没有就自己定义
typedef struct name_map {
  unsigned int id;
  const char *name;
} name_map;

// 返回指令名字
const char *RISCV_insn_name(csh handle, unsigned int id);

#ifdef __cplusplus
}
#endif

#endif // RISCV_INSN_NAME_H

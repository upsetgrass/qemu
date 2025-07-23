#include <stdint.h>

volatile uint64_t sink = 0;

int main() {
    uint64_t sum = 0;
    for (uint64_t i = 0; i < 100000000; i++) {
        sum += i;
    }
    sink = sum;  // 防止优化掉循环
    return 0;
}

#ifndef UTILS_H
#define UTILS_H


// code coverage counters
#define PCS_N (1 << 16)

void hookBlock(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unicorn/unicorn.h>

#include "elfLoader.h"
#include "utils.h"

extern int uniFuzzerInit(uc_engine *uc);
extern int uniFuzzerBeforeExec(uc_engine *uc, const uint8_t *data, size_t len);
extern int uniFuzzerAfterExec(uc_engine *uc);
extern uint16_t prevPR;

uc_engine *uc;

__attribute__((section("__libfuzzer_extra_counters")))
uint8_t Counters[PCS_N];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    char *target = getenv("UF_TARGET");
    char *preload = getenv("UF_PRELOAD");
    char *libPath = getenv("UF_LIBPATH");

    uc = loadELF(target, preload, libPath);
    if(uc == NULL || uniFuzzerInit(uc)) {
        fprintf(stderr, "init failed for %s\n",target);
        fprintf(stderr, "Usage: UF_TARGET=<target> [UF_PRELOAD=<preload>] UF_LIBPATH=<libPath> ./uf\n");
        exit(1);
    }

    // hook basic block to get code coverage
    uc_hook hookHandle;
    uc_hook_add(uc, &hookHandle, UC_HOOK_BLOCK, hookBlock, NULL, 1, 0);

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    prevPR = 0;
    if(uniFuzzerBeforeExec(uc, data, size)) {
        exit(1);
    }
    if(uniFuzzerAfterExec(uc)) {
        exit(1);
    }

    return 0;  // Non-zero return values are reserved for future use.
}

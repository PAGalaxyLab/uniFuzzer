#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <unicorn/unicorn.h>

#include <assert.h>

static uc_context *context;

// CHANGE ME!
// start addr of the emulation (entry point of function vuln)
#define START 0x4007f0
// end addr of the emulation (return addr in main)
#define END 0x400970
// return addr of the target function
#define RA 0x400970

// CHANGE ME!
// name of the preload library
#define PRELOAD_LIB "demo-libcpreload.so"

// CHANGE ME!
// readelf -sW demo-libcpreload.so | grep heap_boundary
#define HEAP_BOUNDARY_GOT_OFFSET 0x10380

#define HEAP_SIZE 1024*1024*32
#define STACK_SIZE 1024*1024*8
#define DATA_SIZE 0x1000

static char *heapBase;
static char *stackTop;
static char *dataAddr;

// heap_boundary@got for the simplified malloc() in demo-preload
static uint32_t *heapBoundaryGOT;

#define HEAP_CANARY 0xdeadbeef 

// callback: invoked when ELFs(target binary and dependent libs) are loaded 
void onLibLoad(const char *libName, void *baseAddr, void *ucBaseAddr) {
    fprintf(stderr, "loading %s at %p, uc addr: %p\n", libName, baseAddr, ucBaseAddr);

    if(strlen(libName)+1 >= sizeof(PRELOAD_LIB)) {
        // libname ends with "demo-libcpreload.so"
        if(strcmp(libName+strlen(libName)-sizeof(PRELOAD_LIB)+1, PRELOAD_LIB) == 0) {
            heapBoundaryGOT = (char *)baseAddr + HEAP_BOUNDARY_GOT_OFFSET;
            fprintf(stderr, "demo-libcpreload.so is at %p, heap_boundary@got is at %p\n", baseAddr, heapBoundaryGOT);
        }
    }
}

// callback: setup the env before emulation starts
int uniFuzzerInit(uc_engine *uc) {

    // setup heap area
    heapBase = mmap(NULL, HEAP_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT, -1, 0);
    if(heapBase == MAP_FAILED) {
        perror("mapping heap");
        return 1;
    }
    if(uc_mem_map_ptr(uc, heapBase, HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE, heapBase) != UC_ERR_OK) {
        fprintf(stderr, "uc mapping heap failed\n");
        return 1;
    }
    printf("heap is at %p\n", heapBase);


    // setup stack area
    stackTop = mmap(NULL, STACK_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT, -1, 0);
    if(stackTop == MAP_FAILED) {
        perror("mapping stack");
        return 1;
    }
    if(uc_mem_map_ptr(uc, stackTop, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE, stackTop) != UC_ERR_OK) {
        fprintf(stderr, "uc mapping stack failed\n");
        return 1;
    }
    printf("stack is at %p\n", stackTop+STACK_SIZE);

    
    // setup data area
    dataAddr = mmap(NULL, DATA_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT, -1, 0);
    if(dataAddr == MAP_FAILED) {
        perror("mapping data");
        return 1;
    }
    if(uc_mem_map_ptr(uc, dataAddr, DATA_SIZE, UC_PROT_READ | UC_PROT_WRITE, dataAddr) != UC_ERR_OK) {
        fprintf(stderr, "uc mapping data failed\n");
        return 1;
    }
    printf("data is at %p\n", dataAddr);

    // for the registers
    uint32_t reg;

    reg = stackTop+STACK_SIZE - 0x200;
    uc_reg_write(uc, UC_MIPS_REG_SP, &reg);

    reg = dataAddr;
    uc_reg_write(uc, UC_MIPS_REG_A0, &reg);

    reg = START;
    uc_reg_write(uc, UC_MIPS_REG_T9, &reg);

    reg = RA;
    uc_reg_write(uc, UC_MIPS_REG_RA, &reg);

    // alloc and save cpu context for restore
    if(uc_context_alloc(uc, &context) != UC_ERR_OK) {
        fprintf(stderr, "uc_context_alloc failed\n");
        return 1;
    }

    uc_context_save(uc, context);

    return 0;
}

// callback: invoked before each round of fuzzing
int uniFuzzerBeforeExec(uc_engine *uc, const uint8_t *data, size_t len) {
    // filter on input size
    if(len == 0 || len > 256) return 0;

    // reset heap base addr in preload library
    *heapBoundaryGOT = heapBase;

    // restore cpu context
    uc_context_restore(uc, context);

    // copy input to buffer
    memcpy(dataAddr, data, len);

    // uncomment the following line to ignore heap overflow in the function vuln
    // memset((char *)dataAddr+4, 0, 1);

    // uncomment the following line to ignore stack overflow in the function vuln
    // memset(dataAddr, 0x20, 1);

    uc_err err;

    // start emulation of the target function
    if((err = uc_emu_start(uc, START, END, 0, 0)) != UC_ERR_OK) {
        fprintf(stderr, "uc_emu_start failed: %s\n", uc_strerror(err));
        return 1;
    }
    else {
        return 0;
    }
}

// callback: invoked after each round of fuzzing
int uniFuzzerAfterExec(uc_engine *uc) {
    // check all heap allocations to see if there's an overflow
    
    // current boundary for used heap area
    uint32_t *boundary = *heapBoundaryGOT;

    // start addr for used heap are
    uint32_t *start = heapBase;

    size_t chunk_len;
    char *canary;

    // check canary for all chunks
    while(start < boundary) {
        chunk_len = *start;
        canary = (char *)start + chunk_len + 4;// with header

        // overflow
        if(*(uint32_t *)canary != HEAP_CANARY) {
            fprintf(stderr, "heap overflow!\n");
            return 1;
        }

        start = (char *)start + chunk_len + 8;
    }

    return 0;
}

#include <stddef.h>
#include <stdint.h>

#define HEAP_CANARY 0xdeadbeef


// very simple allocator that just cut and return memory from mmap-ed area
// | chunk size   | chunk            | canary  |
// |--------------|------------------|---------|
// | 4 bytes      | ...              | 4 bytes |

void *malloc(size_t size) {
    static char *heap_boundary = 0x05000000;
    size_t chunk_len = ((size+7)/8)*8;

    *((uint32_t *)heap_boundary) = chunk_len; // header
    *((uint32_t *)(heap_boundary+4+chunk_len)) = HEAP_CANARY;

    void *chunk = heap_boundary + 4;

    heap_boundary += chunk_len + 8; // with header and canary

    return chunk;
}

void free(void *ptr) {
}

int printf() {
    return 0;
}

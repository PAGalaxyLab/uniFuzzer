#include <stddef.h>

#define HEAP_CANARY 0xdeadbeef

void perror(const char *s) {
}

void *malloc(size_t size) {
    static char *heap_base = 0x05000000;
    size_t alignedSize = ((size+7)/8)*8;
    *((uint32_t *)heap_base) = alignedSize; // header
    *((uint32_t *)(heap_base+4+alignedSize)) = HEAP_CANARY;
    void *res = heap_base + 4;
    heap_base += alignedSize + 8; // with header and canary
    return res;
}

size_t send(int sockfd, const void *buf, size_t len, int flags) {
    return len;
}

int pthread_mutex_lock(void *lock) {
    return 0;
}

int pthread_mutex_unlock(void *lock) {
    return 0;
}

void free(void *ptr) {
    uint32_t *base = ((uint32_t *)ptr) - 1;
    char *canary = (*((char *)base)) + 4 + (*base);
    // overflow
    if(*(uint32_t *)canary != HEAP_CANARY) {
        // trigger segfault
        uint32_t *invalid_addr = 0xffffffff;
        *invalid_addr = 0;
    }
}

int printf() {
    return 0;
}

int puts() {
    return 0;
}

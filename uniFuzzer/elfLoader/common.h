#ifndef DL_COMMON_H
#define DL_COMMON_H
#include <stdio.h>

#define Elf32(TYPE) Elf32_##TYPE

#define unlikely(x)       __builtin_expect((!!(x)),0)
#define attribute_unused __attribute__((unused))
#define do_rem(result, n, base) ((result) = (n) % (base))

/* common align masks, if not specified by sysdep headers */
#define _dl_pagesize 4096
#ifndef ADDR_ALIGN
#define ADDR_ALIGN (_dl_pagesize - 1)
#endif

#ifndef PAGE_ALIGN
#define PAGE_ALIGN (~ADDR_ALIGN)
#endif

#ifndef OFFS_ALIGN
#define OFFS_ALIGN (PAGE_ALIGN & ~(1ul << (sizeof(_dl_pagesize) * 8 - 1)))
#endif

#ifdef UF_DEBUG
#define uf_debug(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define uf_debug(fmt, ...)
#endif

#endif


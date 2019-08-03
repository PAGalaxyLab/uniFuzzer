#ifndef DL_I386
#define DL_I386

#include "dl-hash.h"

int _dl_parse_relocation_information_i386(struct elf_resolve *tpnt, struct r_scope_elem *scope,
    unsigned long rel_addr, unsigned long rel_size);

#endif

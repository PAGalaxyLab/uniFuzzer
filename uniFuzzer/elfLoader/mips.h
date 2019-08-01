#ifndef DL_MIPS_H
#define DL_MIPS_H

#include "dl-hash.h"

int _dl_parse_relocation_information_mips(struct dyn_elf *xpnt,
    struct r_scope_elem *scope, unsigned long rel_addr, unsigned long rel_size);

void init_got_mips(Elf32(Addr) *GOT_BASE, struct elf_resolve *MODULE);

void _dl_perform_mips_global_got_relocations(struct elf_resolve *tpnt);

#endif

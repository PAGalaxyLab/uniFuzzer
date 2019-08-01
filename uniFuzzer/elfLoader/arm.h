#ifndef DL_ARM_H
#define DL_ARM_H

#include "dl-hash.h"

int _dl_do_reloc_arm (struct elf_resolve *tpnt,struct r_scope_elem *scope,
          ELF_RELOC *rpnt, Elf32(Sym) *symtab, char *strtab);

int _dl_parse_relocation_information_arm(struct elf_resolve *tpnt, struct r_scope_elem *scope,
      unsigned long rel_addr, unsigned long rel_size,
      int (*reloc_fnc) (struct elf_resolve *tpnt, struct r_scope_elem *scope,
                ELF_RELOC *rpnt, Elf32(Sym) *symtab, char *strtab));


#endif

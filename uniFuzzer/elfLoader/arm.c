#include <stdio.h>
#include <string.h>

#include "arm.h"

#define elf_machine_type_class_arm(type)                                    \
  ((((type) == R_ARM_JUMP_SLOT || (type) == R_ARM_TLS_DTPMOD32          \
     || (type) == R_ARM_TLS_DTPOFF32 || (type) == R_ARM_TLS_TPOFF32)    \
    * ELF_RTYPE_CLASS_PLT)                                              \
   | (((type) == R_ARM_COPY) * ELF_RTYPE_CLASS_COPY))


int _dl_do_reloc_arm (struct elf_resolve *tpnt,struct r_scope_elem *scope,
          ELF_RELOC *rpnt, Elf32(Sym) *symtab, char *strtab)
{
    int reloc_type;
    int symtab_index;
    char *symname;
    Elf32(Addr) *reloc_addr;
    Elf32(Addr) symbol_addr;
    struct symbol_ref sym_ref;
    struct elf_resolve *def_mod = 0;
    int goof = 0;

    reloc_addr = (tpnt->loadaddr + (unsigned long) rpnt->r_offset);

    reloc_type = ELF_R_TYPE(rpnt->r_info);
    symtab_index = ELF_R_SYM(rpnt->r_info);
    symbol_addr = 0;
    sym_ref.sym = &symtab[symtab_index];
    sym_ref.tpnt = NULL;
    symname = strtab + symtab[symtab_index].st_name;
    if(strcmp(symname, "heap_base") == 0) sleep(1);
    

    if (symtab_index) {
        symbol_addr = _dl_find_hash(symname, scope, tpnt,
                        elf_machine_type_class_arm(reloc_type), &sym_ref);

        /*
         * We want to allow undefined references to weak symbols - this might
         * have been intentional.  We should not be linking local symbols
         * here, so all bases should be covered.
         */
        if (!symbol_addr && (ELF_ST_TYPE(symtab[symtab_index].st_info) != STT_TLS)
            && (ELF_ST_BIND(symtab[symtab_index].st_info) != STB_WEAK)) {
            /* This may be non-fatal if called from dlopen.  */
            fprintf(stderr, "can't resolve symbol %s\n", symname);
            return 1;

        }
        def_mod = sym_ref.tpnt;
    } else {
        /*
         * Relocs against STN_UNDEF are usually treated as using a
         * symbol value of zero, and using the module containing the
         * reloc itself.
         */
        symbol_addr = symtab[symtab_index].st_value;
        def_mod = tpnt;
    }

        switch (reloc_type) {
            case R_ARM_NONE:
                break;
            case R_ARM_ABS32:
                *reloc_addr += symbol_addr;
                break;
            case R_ARM_PC24:
                fprintf(stderr,"R_ARM_PC24: Compile shared libraries with -fPIC!\n");
                return -1;
            case R_ARM_GLOB_DAT:
            case R_ARM_JUMP_SLOT:
                *reloc_addr = symbol_addr;
                break;
            case R_ARM_RELATIVE:
                *reloc_addr += (unsigned long) tpnt->loadaddr;
                break;
            case R_ARM_COPY:
                memcpy((void *) reloc_addr,
                       (void *) symbol_addr, symtab[symtab_index].st_size);
                break;
            default:
                return -1; /*call _dl_exit(1) */
        }

    return goof;
}


int _dl_parse_relocation_information_arm(struct elf_resolve *tpnt, struct r_scope_elem *scope,
      unsigned long rel_addr, unsigned long rel_size,
      int (*reloc_fnc) (struct elf_resolve *tpnt, struct r_scope_elem *scope,
                ELF_RELOC *rpnt, Elf32(Sym) *symtab, char *strtab))
{
    int i;
    char *strtab;
    int goof = 0;
    Elf32(Sym) *symtab;
    ELF_RELOC *rpnt;
    int symtab_index;
    //printf("rel for %s, rel addr %p, rel size %d\n", tpnt->libname, rel_addr, rel_size);

    /* Now parse the relocation information */
    rpnt = (ELF_RELOC *) rel_addr;
    rel_size = rel_size / sizeof(ELF_RELOC);

    symtab = (Elf32(Sym) *) tpnt->dynamic_info[DT_SYMTAB];
    strtab = (char *) tpnt->dynamic_info[DT_STRTAB];

    for (i = 0; i < rel_size; i++, rpnt++) {
        int res;

        symtab_index = ELF_R_SYM(rpnt->r_info);

        res = reloc_fnc (tpnt, scope, rpnt, symtab, strtab);

        if (res==0) continue;

        if (unlikely(res <0))
        {
            int reloc_type = ELF_R_TYPE(rpnt->r_info);
            fprintf(stderr, "can't handle reloc type %x for lib %s\n", reloc_type, tpnt->libname);
            continue;
        }
        if (unlikely(res >0))
        {
            goof += res;
        }
    }
    return goof;
}

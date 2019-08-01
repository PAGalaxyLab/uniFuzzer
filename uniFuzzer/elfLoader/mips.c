#include <stdio.h>
#include <string.h>

#include "mips.h"

extern struct elf_resolve *_dl_loaded_modules;

#define elf_machine_type_class_mips(type)                    \
  ((((type) == R_MIPS_JUMP_SLOT) * ELF_RTYPE_CLASS_PLT)            \
   | (((type) == R_MIPS_COPY) * ELF_RTYPE_CLASS_COPY))

void init_got_mips(Elf32(Addr) *GOT_BASE, struct elf_resolve *MODULE){
    unsigned long idx;
    Elf32(Addr) *pltgot;

    pltgot = (Elf32(Addr) *) MODULE->dynamic_info[DT_MIPS_PLTGOT_IDX];

    /* Add load address displacement to all local GOT entries */
    idx = 2;
    while (idx < MODULE->dynamic_info[DT_MIPS_LOCAL_GOTNO_IDX])
        GOT_BASE[idx++] += (unsigned long) MODULE->loadaddr;
}

int _dl_parse_relocation_information_mips(struct dyn_elf *xpnt,
    struct r_scope_elem *scope, unsigned long rel_addr, unsigned long rel_size)
{
    Elf32(Sym) *symtab;
    ELF_RELOC *rpnt;
    char *strtab;
    unsigned long i;
    Elf32(Addr) *got;
    unsigned long *reloc_addr=NULL;
    unsigned long symbol_addr;
    int reloc_type, symtab_index;
    struct elf_resolve *tpnt = xpnt->dyn;
    char *symname = NULL;

    struct symbol_ref sym_ref;
    /* Now parse the relocation information */
    rel_size = rel_size / sizeof(Elf32(Rel));
    rpnt = (ELF_RELOC *) rel_addr;

    symtab = (Elf32(Sym) *) (tpnt->dynamic_info[DT_SYMTAB]);
    strtab = (char *) tpnt->dynamic_info[DT_STRTAB];
    got = (Elf32(Addr) *) (tpnt->dynamic_info[DT_PLTGOT]);

    for (i = 0; i < rel_size; i++, rpnt++) {
        
        reloc_addr = (unsigned long *) (tpnt->loadaddr +
            (unsigned long) rpnt->r_offset);
        reloc_type = ELF_R_TYPE(rpnt->r_info);
        symtab_index = ELF_R_SYM(rpnt->r_info);
        symbol_addr = 0;
        symname = strtab + symtab[symtab_index].st_name;

        if (reloc_type == R_MIPS_JUMP_SLOT || reloc_type == R_MIPS_COPY) {
            sym_ref.tpnt = NULL;
            sym_ref.sym = &symtab[symtab_index];
            symbol_addr = (unsigned long)_dl_find_hash(symname,
                                   scope,
                                   tpnt,
                                   elf_machine_type_class_mips(reloc_type), &sym_ref);
            if (unlikely(!symbol_addr && ELF_ST_BIND(symtab[symtab_index].st_info) != STB_WEAK))
                return 1;
        }
        if (!symtab_index) {
            /* Relocs against STN_UNDEF are usually treated as using a
            * symbol value of zero, and using the module containing the
            * reloc itself.
            */
            symbol_addr = symtab[symtab_index].st_value;
        }

        switch (reloc_type) {
        case R_MIPS_REL32:
            if (symtab_index) {
                if (symtab_index < tpnt->dynamic_info[DT_MIPS_GOTSYM_IDX])
                    *(Elf32(Word) *)reloc_addr +=
                        symtab[symtab_index].st_value +
                        (unsigned long) tpnt->loadaddr;
                else {
                    *(Elf32(Word) *)reloc_addr += got[symtab_index + tpnt->dynamic_info[DT_MIPS_LOCAL_GOTNO_IDX] -
                        tpnt->dynamic_info[DT_MIPS_GOTSYM_IDX]];
                }
            }
            else {
                *(Elf32(Word) *)reloc_addr += (unsigned long) tpnt->loadaddr;
            }
            break;
        case R_MIPS_JUMP_SLOT:
            *(Elf32(Word) *)reloc_addr = symbol_addr;
            break;
        case R_MIPS_COPY:
            if (symbol_addr) {

                memcpy((char *)reloc_addr,
                       (char *)symbol_addr,
                       symtab[symtab_index].st_size);
            }
            break;
        case R_MIPS_NONE:
            break;
        default:
            {
                fprintf(stderr, "can't handle reloc type %x in lib '%s'\n", reloc_type, tpnt->libname);
            }
        }
    }
    return 0;
}


void _dl_perform_mips_global_got_relocations(struct elf_resolve *tpnt)
{
    Elf32(Sym) *sym;
    char *strtab;
    unsigned long i;
    Elf32(Addr) *got_entry;

    for (; tpnt ; tpnt = tpnt->next) {

        /* Setup the loop variables */
        got_entry = (Elf32(Addr) *) (tpnt->dynamic_info[DT_PLTGOT])
            + tpnt->dynamic_info[DT_MIPS_LOCAL_GOTNO_IDX];
        sym = (Elf32(Sym) *) (tpnt->dynamic_info[DT_SYMTAB])+ tpnt->dynamic_info[DT_MIPS_GOTSYM_IDX];
        strtab = (char *) tpnt->dynamic_info[DT_STRTAB];
        i = tpnt->dynamic_info[DT_MIPS_SYMTABNO_IDX] - tpnt->dynamic_info[DT_MIPS_GOTSYM_IDX];

        /* Relocate the global GOT entries for the object */
        while (i--) {
            if (sym->st_shndx == SHN_UNDEF || sym->st_shndx == SHN_COMMON) {
                *got_entry =  _dl_find_hash(strtab +
                    sym->st_name, &_dl_loaded_modules->symbol_scope, tpnt, ELF_RTYPE_CLASS_PLT, NULL);
            }
            else if (ELF_ST_TYPE(sym->st_info) == STT_SECTION) {
                if (sym->st_other == 0)
                    *got_entry += (unsigned long) tpnt->loadaddr;
            }
            else {
                struct symbol_ref sym_ref;
                sym_ref.sym = sym;
                sym_ref.tpnt = NULL;
                *got_entry = (unsigned long) _dl_find_hash(strtab +
                    sym->st_name, &_dl_loaded_modules->symbol_scope, tpnt, ELF_RTYPE_CLASS_PLT, &sym_ref);
            }

            got_entry++;
            sym++;
        }
    }
}

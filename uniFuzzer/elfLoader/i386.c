#include <stdio.h>

#include "i386.h"

/* ELF_RTYPE_CLASS_PLT iff TYPE describes relocation of a PLT entry or
   TLS variable, so undefined references should not be allowed to
   define the value.
   ELF_RTYPE_CLASS_NOCOPY iff TYPE should not be allowed to resolve to one
   of the main executable's symbols, as for a COPY reloc.  */
#define elf_machine_type_class(type) \
  ((((type) == R_386_JMP_SLOT || (type) == R_386_TLS_DTPMOD32             \
     || (type) == R_386_TLS_DTPOFF32 || (type) == R_386_TLS_TPOFF32       \
     || (type) == R_386_TLS_TPOFF) * ELF_RTYPE_CLASS_PLT)                 \
   | (((type) == R_386_COPY) * ELF_RTYPE_CLASS_COPY))


static int
reloc_fnc(struct elf_resolve *tpnt, struct r_scope_elem *scope,
	     ELF_RELOC *rpnt, Elf32(Sym) *symtab, char *strtab)
{
	int reloc_type;
	int symtab_index;
	char *symname;
	struct elf_resolve *tls_tpnt = NULL;
	unsigned long *reloc_addr;
	unsigned long symbol_addr;
#if defined (UF_DEBUG)
	unsigned long old_val;
#endif
	struct symbol_ref sym_ref;

	reloc_addr = (unsigned long *)(intptr_t)(tpnt->loadaddr + (unsigned long)rpnt->r_offset);
	reloc_type = ELF_R_TYPE(rpnt->r_info);
	symtab_index = ELF_R_SYM(rpnt->r_info);
	symbol_addr = 0;
	sym_ref.sym = &symtab[symtab_index];
	sym_ref.tpnt = NULL;
	symname = strtab + symtab[symtab_index].st_name;

	if (symtab_index) {
		symbol_addr = (unsigned long)_dl_find_hash(symname, scope, tpnt,
							   elf_machine_type_class(reloc_type), &sym_ref);

		/*
		 * We want to allow undefined references to weak symbols - this
		 * might have been intentional.  We should not be linking local
		 * symbols here, so all bases should be covered.
		 */
		if (unlikely(!symbol_addr && (ELF_ST_TYPE(symtab[symtab_index].st_info) != STT_TLS)
					&& ELF_ST_BIND(symtab[symtab_index].st_info) != STB_WEAK))
			return 1;
/*
		if (_dl_trace_prelink) {
			_dl_debug_lookup (symname, tpnt, &symtab[symtab_index],
					&sym_ref, elf_machine_type_class(reloc_type));
		}
*/
		tls_tpnt = sym_ref.tpnt;
	} else {
		symbol_addr = symtab[symtab_index].st_value;
		tls_tpnt = tpnt;
	}
	
#if defined (UF_DEBUG)
	old_val = *reloc_addr;
#endif

	switch (reloc_type) {
		case R_386_NONE:
			break;
		case R_386_32:
			*reloc_addr += symbol_addr;
			break;
		case R_386_PC32:
			*reloc_addr += symbol_addr - (unsigned long)reloc_addr;
			break;
		case R_386_GLOB_DAT:
		case R_386_JMP_SLOT:
			*reloc_addr = symbol_addr;
			break;
		case R_386_RELATIVE:
			*reloc_addr += (unsigned long)tpnt->loadaddr;
			break;
		case R_386_COPY:
			if (symbol_addr) {
                uf_debug("\n%s move %d bytes from %x to %x",
                        symname, symtab[symtab_index].st_size,
                        symbol_addr, reloc_addr);

				memcpy((char *)reloc_addr,
					   (char *)symbol_addr,
					   symtab[symtab_index].st_size);
			}
			break;
		default:
			return -1;
	}

    uf_debug("\n\tpatched: %x ==> %x @ %x\n", old_val, *reloc_addr, reloc_addr);

	return 0;
}

int _dl_parse_relocation_information_i386(struct elf_resolve *tpnt, struct r_scope_elem *scope,
    unsigned long rel_addr, unsigned long rel_size)
    //int (*reloc_fnc)(struct elf_resolve *tpnt, struct r_scope_elem *scope,
     //   ELF_RELOC *rpnt, Elf32(Sym) *symtab, char *strtab))
{
	unsigned int i;
	char *strtab;
	Elf32(Sym) *symtab;
	ELF_RELOC *rpnt;
	int symtab_index;

	/* Parse the relocation information. */
	rpnt = (ELF_RELOC *)(intptr_t)rel_addr;
	rel_size /= sizeof(ELF_RELOC);

	symtab = (Elf32(Sym) *)(intptr_t)tpnt->dynamic_info[DT_SYMTAB];
	strtab = (char *)tpnt->dynamic_info[DT_STRTAB];

	for (i = 0; i < rel_size; i++, rpnt++) {
		int res;

		symtab_index = ELF_R_SYM(rpnt->r_info);

		//debug_sym(symtab, strtab, symtab_index);
		//debug_reloc(symtab, strtab, rpnt);

		res = reloc_fnc(tpnt, scope, rpnt, symtab, strtab);

		if (res == 0)
			continue;

		if (symtab_index)
			fprintf(stderr, "symbol '%s': ",
				    strtab + symtab[symtab_index].st_name);

		if (unlikely(res < 0)) {
			int reloc_type = ELF_R_TYPE(rpnt->r_info);

			fprintf(stderr, "can't handle reloc type %x in lib '%s'\n",
				    reloc_type, tpnt->libname);
			//return res;
            continue;
		} else if (unlikely(res > 0)) {
			fprintf(stderr, "can't resolve symbol in lib '%s'.\n", tpnt->libname);
			//return res;
            continue;
		}
	}

	return 0;
}

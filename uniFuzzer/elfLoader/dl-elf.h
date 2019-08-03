/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2000-2005 by Erik Andersen <andersen@codepoet.org>
 *
 * GNU Lesser General Public License version 2.1 or later.
 */

#ifndef LINUXELF_H
#define LINUXELF_H

#include <elf.h>
#include <link.h>

#include "common.h"

/*
 * Bitsize related settings for things Elf32()
 * does not handle already
 */

# define ELF_ST_BIND(val) ELF32_ST_BIND(val)
# define ELF_ST_TYPE(val) ELF32_ST_TYPE(val)
# define ELF_R_SYM(i)     ELF32_R_SYM(i)
# define ELF_R_TYPE(i)    ELF32_R_TYPE(i)
# ifndef ELF_CLASS
#  define ELF_CLASS ELFCLASS32
# endif

/*
 * Datatype of a relocation on this platform
 */
#ifdef ELF_USES_RELOCA
# define ELF_RELOC	Elf32(Rela)
# define DT_RELOC_TABLE_ADDR	DT_RELA
# define DT_RELOC_TABLE_SIZE	DT_RELASZ
# define DT_RELOCCOUNT		DT_RELACOUNT
# define UNSUPPORTED_RELOC_TYPE	DT_REL
# define UNSUPPORTED_RELOC_STR	"REL"
#else
# define ELF_RELOC	Elf32(Rel)
# define DT_RELOC_TABLE_ADDR	DT_REL
# define DT_RELOC_TABLE_SIZE	DT_RELSZ
# define DT_RELOCCOUNT		DT_RELCOUNT
# define UNSUPPORTED_RELOC_TYPE	DT_RELA
# define UNSUPPORTED_RELOC_STR	"RELA"
#endif

/* OS and/or GNU dynamic extensions */

#define OS_NUM_BASE 1			/* for DT_RELOCCOUNT */

# define OS_NUM_GNU_HASH	1

# define OS_NUM_PRELINK	0

#define OS_NUM	  (OS_NUM_BASE + OS_NUM_GNU_HASH + OS_NUM_PRELINK)

#define ARCH_NUM 4

#define DYNAMIC_SIZE (DT_NUM + OS_NUM + ARCH_NUM)
/* Keep ARCH specific entries into dynamic section at the end of the array */
#define DT_RELCONT_IDX (DYNAMIC_SIZE - OS_NUM - ARCH_NUM)

#define DT_GNU_HASH_IDX (DT_RELCONT_IDX + 1)

#define DT_MIPS_GOTSYM_IDX	(DT_NUM + OS_NUM)
#define DT_MIPS_LOCAL_GOTNO_IDX	(DT_NUM + OS_NUM +1)
#define DT_MIPS_SYMTABNO_IDX	(DT_NUM + OS_NUM +2)
#define DT_MIPS_PLTGOT_IDX	(DT_NUM + OS_NUM +3)

unsigned int _dl_parse_dynamic_info(Elf32(Dyn) *dpnt, unsigned long dynamic_info[],
                                       Elf32(Addr) load_off);



/* Reloc type classes as returned by elf_machine_type_class().
   ELF_RTYPE_CLASS_PLT means this reloc should not be satisfied by
   some PLT symbol, ELF_RTYPE_CLASS_COPY means this reloc should not be
   satisfied by any symbol in the executable.  Some architectures do
   not support copy relocations.  In this case we define the macro to
   zero so that the code for handling them gets automatically optimized
   out.  */
#ifdef DL_NO_COPY_RELOCS
# define ELF_RTYPE_CLASS_COPY	(0x0)
#else
# define ELF_RTYPE_CLASS_COPY	(0x2)
#endif
#define ELF_RTYPE_CLASS_PLT	(0x1)

/* dlsym() calls _dl_find_hash with this value, that enables
   DL_FIND_HASH_VALUE to return something different than the symbol
   itself, e.g., a function descriptor.  */
#define ELF_RTYPE_CLASS_DLSYM 0x80000000


/* Convert between the Linux flags for page protections and the
   ones specified in the ELF standard. */
#define LXFLAGS(X) ( (((X) & PF_R) ? PROT_READ : 0) | \
		    (((X) & PF_W) ? PROT_WRITE : 0) | \
		    (((X) & PF_X) ? PROT_EXEC : 0))


#endif	/* LINUXELF_H */

/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2000-2006 by Erik Andersen <andersen@codepoet.org>
 *
 * GNU Lesser General Public License version 2.1 or later.
 */

#ifndef _LD_HASH_H_
#define _LD_HASH_H_

#include "common.h"
#include "dl-elf.h"

#ifndef RTLD_NEXT
#define RTLD_NEXT	((void*)-1)
#endif

struct init_fini_list {
	struct init_fini_list *next;
	struct elf_resolve *tpnt;
};

struct init_fini {
	struct elf_resolve **init_fini;
	unsigned long nlist; /* Number of entries in init_fini */
};

struct dyn_elf {
  struct elf_resolve * dyn;
  struct dyn_elf * next_handle;  /* Used by dlopen et al. */
  struct init_fini init_fini;
  struct dyn_elf * next;
  struct dyn_elf * prev;
};

struct symbol_ref {
  const Elf32(Sym) *sym;
  struct elf_resolve *tpnt;
};

/* Structure to describe a single list of scope elements.  The lookup
   functions get passed an array of pointers to such structures.  */
struct r_scope_elem {
  struct elf_resolve **r_list; /* Array of maps for the scope.  */
  unsigned int r_nlist;        /* Number of entries in the scope.  */
  struct r_scope_elem *next;
};

struct elf_resolve {
  /* These entries must be in this order to be compatible with the interface used
     by gdb to obtain the list of symbols. */
  Elf32(Addr) loadaddr;	/* Base address shared object is loaded at.  */
  char *libname;		/* Absolute file name object was found in.  */
  Elf32(Dyn) *dynamic_addr;	/* Dynamic section of the shared object.  */
  struct elf_resolve * next;
  struct elf_resolve * prev;
  /* Nothing after this address is used by gdb. */

  Elf32(Addr) mapaddr;

  /* Store the entry point from the ELF header (e_entry) */
  Elf32(Addr) l_entry;

  enum {elf_lib, elf_executable,program_interpreter, loaded_file} libtype;
  /* This is the local scope of the shared object */
  struct r_scope_elem symbol_scope;
  unsigned short usage_count;
  unsigned short int init_flag;
  unsigned long rtld_flags; /* RTLD_GLOBAL, RTLD_NOW etc. */
  Elf_Symndx nbucket;

  Elf_Symndx *elf_buckets;

  struct init_fini_list *init_fini;
  struct init_fini_list *rtld_local; /* keep tack of RTLD_LOCAL libs in same group */
  /*
   * These are only used with ELF style shared libraries
   */
  Elf_Symndx nchain;

  Elf_Symndx *chains;
  unsigned long dynamic_info[DYNAMIC_SIZE];

  unsigned long n_phent;
  Elf32(Phdr) * ppnt;

  Elf32(Addr) relro_addr;
  size_t relro_size;

  dev_t st_dev;      /* device */
  ino_t st_ino;      /* inode */

};

#define RELOCS_DONE	    0x000001
#define JMP_RELOCS_DONE	    0x000002
#define INIT_FUNCS_CALLED   0x000004
#define FINI_FUNCS_CALLED   0x000008
#define DL_OPENED	    0x000010
#define DL_RESERVED	    0x000020

struct elf_resolve * _dl_add_elf_hash_table(const char * libname,
	Elf32(Addr) loadaddr, unsigned long * dynamic_info,
	unsigned long dynamic_addr, unsigned long dynamic_size);

char *_dl_find_hash(const char *name, struct r_scope_elem *scope,
		struct elf_resolve *mytpnt, int type_class,
		struct symbol_ref *symbol);

#define LD_ERROR_NOFILE 1
#define LD_ERROR_NOZERO 2
#define LD_ERROR_NOTELF 3
#define LD_ERROR_NOTMAGIC 4
#define LD_ERROR_NOTDYN 5
#define LD_ERROR_MMAP_FAILED 6
#define LD_ERROR_NODYNAMIC 7
#define LD_ERROR_TLS_FAILED 8
#define LD_WRONG_RELOCS 9
#define LD_BAD_HANDLE 10
#define LD_NO_SYMBOL 11

#endif /* _LD_HASH_H_ */

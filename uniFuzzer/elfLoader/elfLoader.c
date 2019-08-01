#include <unicorn/unicorn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stddef.h>
#include <alloca.h>
#include <sys/param.h>
#include <assert.h>

#include "common.h"

#define _dl_mmap_check_error(X) (((void *)X) == MAP_FAILED)

#define UCFLAGS(X) ((((X) & PF_R) ? UC_PROT_READ : 0) | \
            (((X) & PF_W) ? UC_PROT_WRITE : 0) | \
            (((X) & PF_X) ? UC_PROT_EXEC : 0))

#include "dl-elf.h"
#include "dl-hash.h"
#include "dl-defs.h"
#include "dl-string.h"

#include "mips.h"
#include "arm.h"

static struct elf_resolve * _dl_load_elf_shared_library(struct dyn_elf **rpnt, 
        const char *libname);
static struct elf_resolve *_dl_load_shared_library(struct dyn_elf **rpnt,
    struct elf_resolve *tpnt, char *full_libname, char *lib_path);
extern void onLibLoad(const char *libName, void *baseAddr, void *ucBaseAddr);

DL_DEF_LIB_OFFSET;

uc_engine *uc = NULL;

struct elf_resolve *_dl_loaded_modules = NULL;
static struct dyn_elf *_dl_symbol_tables = NULL;
static struct elf_resolve **scope_elem_list = NULL;

/* Used to return error codes back to dlopen et. al.  */
static unsigned long _dl_error_number;
static unsigned long _dl_internal_error_number;

static int e_machine = EM_NONE;


static struct elf_resolve *
search_for_named_library(const char *name, const char *path_list,
    struct dyn_elf **rpnt)
{
    char *path, *path_n, *mylibname;
    struct elf_resolve *tpnt;
    int done;

    if (path_list==NULL)
        return NULL;

    /* We need a writable copy of this string, but we don't
     * need this allocated permanently since we don't want
     * to leak memory, so use alloca to put path on the stack */
    done = strlen(path_list);
    path = alloca(done + 1);

    /* another bit of local storage */
    mylibname = alloca(2050);

    memcpy(path, path_list, done+1);

    /* Unlike ldd.c, don't bother to eliminate double //s */

    /* Replace colons with zeros in path_list */
    /* : at the beginning or end of path maps to CWD */
    /* :: anywhere maps CWD */
    /* "" maps to CWD */
    done = 0;
    path_n = path;
    do {
        if (*path == 0) {
            *path = ':';
            done = 1;
        }
        if (*path == ':') {
            *path = 0;
            if (*path_n)
                strcpy(mylibname, path_n);
            else
                strcpy(mylibname, "."); /* Assume current dir if empty path */
            strcat(mylibname, "/");
            strcat(mylibname, name);
            if ((tpnt = _dl_load_elf_shared_library(rpnt, mylibname)) != NULL)
                return tpnt;
            path_n = path+1;
        }
        path++;
    } while (!done);
    return NULL;
}


static void *
map_writeable (int infile, Elf32(Phdr) *ppnt, int piclib, int flags,
           unsigned long libaddr)
{
    int prot_flags = ppnt->p_flags | PF_W;
    char *status, *retval;
    char *tryaddr;
    ssize_t size;
    unsigned long map_size;
    char *cpnt;
    uc_err err;

    tryaddr = ((char *) (piclib ? libaddr : DL_GET_LIB_OFFSET()) +
           (ppnt->p_vaddr & PAGE_ALIGN));

    size = (ppnt->p_vaddr & ADDR_ALIGN) + ppnt->p_filesz;

    /* For !MMU, mmap to fixed address will fail.
       So instead of desperately call mmap and fail,
       we set status to MAP_FAILED to save a call
       to mmap ().  */
    status = (char *) mmap
        (tryaddr, size, LXFLAGS(prot_flags),
         flags, infile, ppnt->p_offset & OFFS_ALIGN);

    if((err = uc_mem_map_ptr(uc, 
                   tryaddr - (piclib ? 0 : DL_GET_LIB_OFFSET()),
                   (size+ADDR_ALIGN) & PAGE_ALIGN,
                   UCFLAGS(prot_flags),
                   status))
            != UC_ERR_OK) {
        fprintf(stderr, "uc_mem_map_ptr failed: %d\n", err);
        return 0;
    }
    uf_debug("uc mem map %p size 0x%x at %p with prop %d\n",
            tryaddr - (piclib ? 0 : DL_GET_LIB_OFFSET()),
            (size+ADDR_ALIGN) & PAGE_ALIGN, status, prot_flags);

    if (_dl_mmap_check_error(status) || (tryaddr && tryaddr != status))
        return 0;

    retval = status;

    /* Now we want to allocate and zero-out any data from the end
       of the region we mapped in from the file (filesz) to the
       end of the loadable segment (memsz).  We may need
       additional pages for memsz, that we map in below, and we
       can count on the kernel to zero them out, but we have to
       zero out stuff in the last page that we mapped in from the
       file.  However, we can't assume to have actually obtained
       full pages from the kernel, since we didn't ask for them,
       and uClibc may not give us full pages for small
       allocations.  So only zero out up to memsz or the end of
       the page, whichever comes first.  */

    /* CPNT is the beginning of the memsz portion not backed by
       filesz.  */
    cpnt = (char *) (status + size);

    /* MAP_SIZE is the address of the
       beginning of the next page.  */
    map_size = (ppnt->p_vaddr + ppnt->p_filesz
            + ADDR_ALIGN) & PAGE_ALIGN;

    memset (cpnt, 0,
            MIN (map_size
             - (ppnt->p_vaddr
                + ppnt->p_filesz),
             ppnt->p_memsz
             - ppnt->p_filesz));

    if (map_size < ppnt->p_vaddr + ppnt->p_memsz) {
        tryaddr = map_size + (char*)(piclib ? libaddr : DL_GET_LIB_OFFSET());
        size = ppnt->p_vaddr + ppnt->p_memsz - map_size;
        status = (char *) mmap(tryaddr, size,
                       LXFLAGS(prot_flags),
                       flags | MAP_ANONYMOUS, -1, 0);
        if (_dl_mmap_check_error(status) || tryaddr != status)
            return NULL;

        if((err = uc_mem_map_ptr(uc, 
                       map_size + (char*)(piclib ? libaddr : 0),
                       (size+ADDR_ALIGN) & PAGE_ALIGN,
                       UCFLAGS(prot_flags),
                       status))
                != UC_ERR_OK) {
            fprintf(stderr, "uc_mem_map_ptr failed: %d\n", err);
            return NULL;
        }
        uf_debug("uc mem map %p size 0x%x at %p with prop %d\n",
                map_size + (char*)(piclib ? libaddr : 0),
                (size+ADDR_ALIGN) & PAGE_ALIGN, status, prot_flags);
}
    return retval;
}

unsigned int _dl_parse_dynamic_info(Elf32(Dyn) *dpnt, unsigned long dynamic_info[],
                                    DL_LOADADDR_TYPE load_off)
{
    unsigned int rtld_flags = 0;

    for (; dpnt->d_tag; dpnt++) {
        if (dpnt->d_tag < DT_NUM) {
            dynamic_info[dpnt->d_tag] = dpnt->d_un.d_val;
            if (dpnt->d_tag == DT_TEXTREL)
                dynamic_info[DT_TEXTREL] = 1;
        } else if (dpnt->d_tag < DT_LOPROC) {
            if (dpnt->d_tag == DT_RELOCCOUNT)
                dynamic_info[DT_RELCONT_IDX] = dpnt->d_un.d_val;
        }
        else if(e_machine == EM_MIPS) {
            switch(dpnt->d_tag) {
                case DT_MIPS_GOTSYM:
                    dynamic_info[DT_MIPS_GOTSYM_IDX] = dpnt->d_un.d_val;
                    break;
                case DT_MIPS_LOCAL_GOTNO:
                    dynamic_info[DT_MIPS_LOCAL_GOTNO_IDX] = dpnt->d_un.d_val;
                    break;
                case DT_MIPS_SYMTABNO:
                    dynamic_info[DT_MIPS_SYMTABNO_IDX] = dpnt->d_un.d_val;
                    break;
                case DT_MIPS_PLTGOT:
                    dynamic_info[DT_MIPS_PLTGOT_IDX] = dpnt->d_un.d_val;
                    break;
                default:
                    break;
            }
        }
    }

#define ADJUST_DYN_INFO(tag, load_off) \
    do { \
        if (dynamic_info[tag]) \
            dynamic_info[tag] = (unsigned long) DL_RELOC_ADDR(load_off, dynamic_info[tag]); \
    } while (0)
    /* Don't adjust .dynamic unnecessarily.  For FDPIC targets,
       we'd have to walk all the loadsegs to find out if it was
       actually unnecessary, so skip this optimization.  */
    if (load_off != 0)
    {
        ADJUST_DYN_INFO(DT_HASH, load_off);
        ADJUST_DYN_INFO(DT_PLTGOT, load_off);
        ADJUST_DYN_INFO(DT_STRTAB, load_off);
        ADJUST_DYN_INFO(DT_SYMTAB, load_off);
        ADJUST_DYN_INFO(DT_RELOC_TABLE_ADDR, load_off);
        ADJUST_DYN_INFO(DT_JMPREL, load_off);
    }

    return rtld_flags;
}



static struct elf_resolve *_dl_load_elf_shared_library(struct dyn_elf **rpnt, const char *libname)
{
    Elf32(Ehdr) *epnt;
    unsigned long dynamic_addr = 0;
    Elf32(Dyn) *dpnt;
    struct elf_resolve *tpnt;
    Elf32(Phdr) *ppnt;
    char *status, *header;
    unsigned long dynamic_info[DYNAMIC_SIZE];
    Elf32(Addr) *lpnt;
    unsigned long libaddr;
    unsigned long minvma = 0xffffffff, maxvma = 0;
    unsigned int rtld_flags;
    int i, flags, piclib, infile;
    Elf32(Addr) relro_addr = 0;
    size_t relro_size = 0;
    struct stat st;
    unsigned char *ident;
    DL_LOADADDR_TYPE lib_loadaddr;
    DL_INIT_LOADADDR_EXTRA_DECLS

    libaddr = 0;
    infile = open(libname, O_RDONLY, 0);
    if (infile < 0) {
        _dl_internal_error_number = LD_ERROR_NOFILE;
        return NULL;
    }

    if (fstat(infile, &st) < 0) {
        _dl_internal_error_number = LD_ERROR_NOFILE;
        close(infile);
        return NULL;
    }

    /* Check if file is already loaded */
    for (tpnt = _dl_loaded_modules; tpnt; tpnt = tpnt->next) {
        if (tpnt->st_dev == st.st_dev && tpnt->st_ino == st.st_ino) {
            /* Already loaded */
            tpnt->usage_count++;
            close(infile);
            return tpnt;
        }
    }

    header = mmap((void *) 0, _dl_pagesize, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (_dl_mmap_check_error(header)) {
        fprintf(stderr, "can't map '%s'\n", libname);
        _dl_internal_error_number = LD_ERROR_MMAP_FAILED;
        close(infile);
        return NULL;
    }

    read(infile, header, _dl_pagesize);
    epnt = (Elf32(Ehdr) *) header;
    ident = epnt->e_ident;
    if (memcmp(ident, ELFMAG, 4)) {
        fprintf(stderr, "'%s' is not an ELF file\n", libname);
        _dl_internal_error_number = LD_ERROR_NOTELF;
        close(infile);
        munmap(header, _dl_pagesize);
        return NULL;
    }

    if(ident[EI_CLASS] != ELFCLASS32) {
        fprintf(stderr, "unsupported elf class: %d\n", ident[EI_CLASS]);
        return NULL;
    }
    
    if(e_machine == EM_NONE) 
        e_machine = epnt->e_machine;
    else if(e_machine != epnt->e_machine) {
        fprintf(stderr, "inconsistent machines: %d and %d\n", e_machine, epnt->e_machine);
        return NULL;
    }

    uc_mode mode = (ident[EI_DATA] == ELFDATA2LSB) ? 
                    UC_MODE_LITTLE_ENDIAN :
                    UC_MODE_BIG_ENDIAN;

    if(uc == NULL) {
        switch(e_machine) {
            case EM_MIPS:
                uc_open(UC_ARCH_MIPS, mode | UC_MODE_MIPS32, &uc);
                break;
            case EM_ARM:
                uc_open(UC_ARCH_ARM, mode | UC_MODE_ARM, &uc);
                break;
            case EM_386:
                uc_open(UC_ARCH_X86, mode | UC_MODE_32, &uc);
                break;
            default:
                fprintf(stderr, "unsupported machine: %d\n", e_machine);
                return NULL;
        }
    }

    if (epnt->e_type != ET_DYN && epnt->e_type != ET_EXEC) {
        fprintf(stderr, "unsupported type: %d\n", epnt->e_type);
        close(infile);
        munmap(header, _dl_pagesize);
        return NULL;
    }

    ppnt = (Elf32(Phdr) *) & header[epnt->e_phoff];

    piclib = 1;
    for (i = 0; i < epnt->e_phnum; i++) {

        if (ppnt->p_type == PT_DYNAMIC) {
            if (dynamic_addr)
                fprintf(stderr, "'%s' has more than one dynamic section\n", libname);
            dynamic_addr = ppnt->p_vaddr;
        }

        if (ppnt->p_type == PT_LOAD) {
            /* See if this is a PIC library. */
            if (minvma == 0xffffffff && ppnt->p_vaddr > 0x1000000) {
                piclib = 0;
                minvma = ppnt->p_vaddr;
            }
            if (piclib && ppnt->p_vaddr < minvma) {
                minvma = ppnt->p_vaddr;
            }
            if (((unsigned long) ppnt->p_vaddr + ppnt->p_memsz) > maxvma) {
                maxvma = ppnt->p_vaddr + ppnt->p_memsz;
            }
        }
        if (ppnt->p_type == PT_TLS) {
            fprintf(stderr, "'%s' library contains unsupported TLS\n", libname);
        }
        ppnt++;
    }

    if (epnt->e_type == ET_EXEC)
        piclib = 0;

    maxvma = (maxvma + ADDR_ALIGN) & PAGE_ALIGN;
    minvma = minvma & ~ADDR_ALIGN;

    flags = MAP_32BIT|MAP_PRIVATE /*| MAP_DENYWRITE */ ;

    status = (char *) mmap((char *) (piclib ? 0 : minvma),
            maxvma - minvma, PROT_NONE, flags | MAP_ANONYMOUS, -1, 0);
    if (_dl_mmap_check_error(status)) {
    cant_map:
        fprintf(stderr, "can't map '%s'\n", libname);
        _dl_internal_error_number = LD_ERROR_MMAP_FAILED;
        close(infile);
        munmap(header, _dl_pagesize);
        return NULL;
    }
    libaddr = (unsigned long) status;
    flags |= MAP_FIXED;

    /* Get the memory to store the library */
    ppnt = (Elf32(Phdr) *) & header[epnt->e_phoff];

    DL_INIT_LOADADDR(lib_loadaddr, libaddr - minvma, ppnt, epnt->e_phnum);

    /* Set _dl_library_offset to lib_loadaddr or 0. */
    DL_SET_LIB_OFFSET(lib_loadaddr);

    for (i = 0; i < epnt->e_phnum; i++) {
        if (ppnt->p_type == PT_GNU_RELRO) {
            relro_addr = ppnt->p_vaddr;
            relro_size = ppnt->p_memsz;
        }
        if (ppnt->p_type == PT_LOAD) {
            char *tryaddr;
            ssize_t size;

            if (ppnt->p_flags & PF_W) {
                status = map_writeable (infile, ppnt, piclib, flags, libaddr);
                if (status == NULL)
                    goto cant_map;
            } else {
                tryaddr = (char *) (ppnt->p_vaddr & PAGE_ALIGN)
                       + (piclib ? libaddr : DL_GET_LIB_OFFSET());
                size = (ppnt->p_vaddr & ADDR_ALIGN) + ppnt->p_filesz;
                status = (char *) mmap
                       (tryaddr, size, LXFLAGS(ppnt->p_flags),
                        flags, infile, ppnt->p_offset & OFFS_ALIGN);
                if (_dl_mmap_check_error(status)
                    || (tryaddr && tryaddr != status))
                  goto cant_map;
                uc_err err;
                //printf("tryaddr: %p, piclib: %d, offset: %x, size: %x, real addr %p\n", tryaddr, piclib, DL_GET_LIB_OFFSET(), size, status);
                if((err = uc_mem_map_ptr(uc, 
                               tryaddr - (piclib ? 0 : DL_GET_LIB_OFFSET()),
                               (size+ADDR_ALIGN) & PAGE_ALIGN,
                               UCFLAGS(ppnt->p_flags),
                               status))
                        != UC_ERR_OK) {
                    fprintf(stderr, "uc_mem_map_ptr failed: %d\n", err);
                    goto cant_map;
                }
                uf_debug("uc mem map %p size 0x%x at %p with prop %d\n",
                        tryaddr - (piclib ? 0 : DL_GET_LIB_OFFSET()),
                        (size+ADDR_ALIGN) & PAGE_ALIGN, status, ppnt->p_flags);
            }
        }
        ppnt++;
    }

    /*
     * The dynamic_addr must be take into acount lib_loadaddr value, to note
     * it is zero when the SO has been mapped to the elf's physical addr
     */
    dynamic_addr = (unsigned long) DL_RELOC_ADDR(lib_loadaddr, dynamic_addr);

    /*
     * OK, the ELF library is now loaded into VM in the correct locations
     * The next step is to go through and do the dynamic linking (if needed).
     */

    /* Start by scanning the dynamic section to get all of the pointers */

    if (!dynamic_addr) {
        _dl_internal_error_number = LD_ERROR_NODYNAMIC;
        fprintf(stderr, "'%s' is missing a dynamic section\n", libname);
        munmap(header, _dl_pagesize);
        close(infile);
        return NULL;
    }

    dpnt = (Elf32(Dyn) *) dynamic_addr;
    memset(dynamic_info, 0, sizeof(dynamic_info));

    rtld_flags = _dl_parse_dynamic_info(dpnt, dynamic_info, lib_loadaddr);

    /* If the TEXTREL is set, this means that we need to make the pages
       writable before we perform relocations.  Do this now. They get set
       back again later. */

    if (dynamic_info[DT_TEXTREL]) {
        ppnt = (Elf32(Phdr) *)(intptr_t) & header[epnt->e_phoff];
        for (i = 0; i < epnt->e_phnum; i++, ppnt++) {
            if (ppnt->p_type == PT_LOAD && !(ppnt->p_flags & PF_W)) {
                mprotect((void *) ((piclib ? libaddr : DL_GET_LIB_OFFSET()) +
                            (ppnt->p_vaddr & PAGE_ALIGN)),
                        (ppnt->p_vaddr & ADDR_ALIGN) + (unsigned long) ppnt->p_filesz,
                        PROT_READ | PROT_WRITE | PROT_EXEC);
            }
        }
    }

    close(infile);

    tpnt = _dl_add_elf_hash_table(libname, lib_loadaddr, dynamic_info,
            dynamic_addr, 0);
    tpnt->mapaddr = libaddr;
    tpnt->relro_addr = relro_addr;
    tpnt->relro_size = relro_size;
    tpnt->st_dev = st.st_dev;
    tpnt->st_ino = st.st_ino;
    tpnt->ppnt = (Elf32(Phdr) *)
        DL_RELOC_ADDR(DL_GET_RUN_ADDR(tpnt->loadaddr, tpnt->mapaddr),
        epnt->e_phoff);
    tpnt->n_phent = epnt->e_phnum;
    tpnt->rtld_flags |= rtld_flags;
    tpnt->l_entry = epnt->e_entry;


    /*
     * Add this object into the symbol chain
     */
    if (*rpnt
        /* Do not create a new chain entry for the main executable */
        && (*rpnt)->dyn
        ) {
        (*rpnt)->next = malloc(sizeof(struct dyn_elf));
        memset((*rpnt)->next, 0, sizeof(struct dyn_elf));
        (*rpnt)->next->prev = (*rpnt);
        *rpnt = (*rpnt)->next;
    }
    /* When statically linked, the first time we dlopen a DSO
     * the *rpnt is NULL, so we need to allocate memory for it,
     * and initialize the _dl_symbol_table.
     */
    else if(*rpnt == NULL) {
        *rpnt = _dl_symbol_tables = malloc(sizeof(struct dyn_elf));
        memset(*rpnt, 0, sizeof(struct dyn_elf));
    }
    (*rpnt)->dyn = tpnt;
    tpnt->usage_count++;
    tpnt->libtype = (epnt->e_type == ET_DYN) ? elf_lib : elf_executable;

    /*
     * OK, the next thing we need to do is to insert the dynamic linker into
     * the proper entry in the GOT so that the PLT symbols can be properly
     * resolved.
     */

    lpnt = (Elf32(Addr) *) dynamic_info[DT_PLTGOT];

    if (lpnt && piclib && e_machine == EM_MIPS) {
            init_got_mips(lpnt, tpnt);
    }

    onLibLoad(libname, tpnt->mapaddr, tpnt->mapaddr - (piclib ? 0 : lib_loadaddr));
    munmap(header, _dl_pagesize);

    return tpnt;
}

static struct elf_resolve *_dl_load_shared_library(struct dyn_elf **rpnt,
    struct elf_resolve *tpnt, char *full_libname, char *lib_path)
{
    char *pnt;
    struct elf_resolve *tpnt1;
    char *libname;

    _dl_internal_error_number = 0;
    libname = full_libname;

    /* quick hack to ensure mylibname buffer doesn't overflow.  don't
       allow full_libname or any directory to be longer than 1024. */
    if (strlen(full_libname) > 1024)
        goto goof;

    /* Skip over any initial initial './' and '/' stuff to
     * get the short form libname with no path garbage */
    pnt = strrchr(libname, '/');
    if (pnt) {
        libname = pnt + 1;
    }

    /* If the filename has any '/', try it straight and leave it at that.
       For IBCS2 compatibility under linux, we substitute the string
       /usr/i486-sysv4/lib for /usr/lib in library names. */

    if (libname != full_libname) {
        tpnt1 = _dl_load_elf_shared_library(rpnt, full_libname);
        if (tpnt1) {
            return tpnt1;
        }
    }

    /* Lastly, search the standard list of paths for the library.
       This list must exactly match the list in uClibc/ldso/util/ldd.c */
    tpnt1 = search_for_named_library(libname, lib_path, rpnt);
    if (tpnt1 != NULL)
        return tpnt1;

goof:
    /* Well, we shot our wad on that one.  All we can do now is punt */
    if (_dl_internal_error_number)
        _dl_error_number = _dl_internal_error_number;
    else
        _dl_error_number = LD_ERROR_NOFILE;
    fprintf(stderr, "Bummer: could not find '%s'!\n", libname);
    return NULL;
}

static ptrdiff_t _dl_build_local_scope (struct elf_resolve **list,
                                        struct elf_resolve *map)
{
    struct elf_resolve **p = list;
    struct init_fini_list *q;

    *p++ = map;
    map->init_flag |= DL_RESERVED;
    if (map->init_fini)
        for (q = map->init_fini; q; q = q->next)
            if (! (q->tpnt->init_flag & DL_RESERVED))
                p += _dl_build_local_scope (p, q->tpnt);
    return p - list;
}


/* Relocate the global GOT entries for the object */

static int _dl_parse_relocation_information(struct dyn_elf *rpnt,
    struct r_scope_elem *scope, unsigned long rel_addr, unsigned long rel_size) {
    int res = 1;
    switch(e_machine) {
        case EM_MIPS:
            res = _dl_parse_relocation_information_mips(rpnt, scope, rel_addr, rel_size);
            break;
        case EM_ARM:
            res = _dl_parse_relocation_information_arm(rpnt->dyn, scope, rel_addr, rel_size, _dl_do_reloc_arm);
            break;
        case EM_386:
            res = _dl_parse_relocation_information_i386(rpnt->dyn, scope, rel_addr, rel_size);//, _dl_do_reloc_i386);
            break;
        default:
            fprintf(stderr, "unsupported arch for _dl_parse_relocation_information: %d\n", e_machine);
            break;
    }
    return res;
}

static int _dl_fixup(struct dyn_elf *rpnt, struct r_scope_elem *scope, attribute_unused int now_flag)
{
    int goof = 0;
    struct elf_resolve *tpnt;
    Elf32(Word) reloc_size, relative_count;
    Elf32(Addr) reloc_addr;

    if (rpnt->next)
        goof = _dl_fixup(rpnt->next, scope, now_flag);
    tpnt = rpnt->dyn;

    if (unlikely(tpnt->dynamic_info[UNSUPPORTED_RELOC_TYPE])) {
        fprintf(stderr, "%s: can't handle %s relocation records\n",
                tpnt->libname, UNSUPPORTED_RELOC_STR);
        goof++;
    }

    reloc_size = tpnt->dynamic_info[DT_RELOC_TABLE_SIZE];
/* On some machines, notably SPARC & PPC, DT_REL* includes DT_JMPREL in its
   range.  Note that according to the ELF spec, this is completely legal! */
#ifdef ELF_MACHINE_PLTREL_OVERLAP
    reloc_size -= tpnt->dynamic_info [DT_PLTRELSZ];
#endif

    if (tpnt->dynamic_info[DT_RELOC_TABLE_ADDR] &&
        !(tpnt->init_flag & RELOCS_DONE)) {
        reloc_addr = tpnt->dynamic_info[DT_RELOC_TABLE_ADDR];
        relative_count = tpnt->dynamic_info[DT_RELCONT_IDX];
        if (relative_count) { /* Optimize the XX_RELATIVE relocations if possible */
            reloc_size -= relative_count * sizeof(ELF_RELOC);
            reloc_addr += relative_count * sizeof(ELF_RELOC);
        }
        goof += _dl_parse_relocation_information(rpnt, scope,
                reloc_addr,
                reloc_size);
        tpnt->init_flag |= RELOCS_DONE;
    }

    if (tpnt->dynamic_info[DT_JMPREL] &&
        (!(tpnt->init_flag & JMP_RELOCS_DONE))) {
        goof += _dl_parse_relocation_information(rpnt, scope,
                tpnt->dynamic_info[DT_JMPREL],
                tpnt->dynamic_info[DT_PLTRELSZ]);
        tpnt->init_flag |= JMP_RELOCS_DONE;
    }

    return goof;
}

uc_engine *loadELF(const char *target, char *preload, char *libPath) {
    if(target == NULL || libPath == NULL) {
        return NULL;
    }
    unsigned int nlist;
    int unlazy = RTLD_NOW;

    struct dyn_elf *rpnt = NULL;
    _dl_symbol_tables = rpnt = calloc(sizeof(struct dyn_elf), 1);

    struct elf_resolve *tcurr;
    char *lpntstr;
    struct elf_resolve *tpnt1;
    unsigned int i, cnt, nscope_elem;
    struct r_scope_elem *global_scope;
    struct elf_resolve **local_scope;

    struct elf_resolve app_tpnt_tmp;
    struct elf_resolve *app_tpnt = &app_tpnt_tmp;
    memset(app_tpnt, 0, sizeof(*app_tpnt));

    app_tpnt = _dl_load_elf_shared_library(&rpnt, target);

    if(app_tpnt == NULL) {
        fprintf(stderr, "failed to load target ELF %s: %ld\n", target, _dl_internal_error_number);
        return NULL;
    }

    app_tpnt->rtld_flags = RTLD_NOW | RTLD_GLOBAL;

    if (preload) {
        char c, *str, *str2;

        str = preload;
        while (*str == ':' || *str == ' ' || *str == '\t')
            str++;

        while (*str) {
            str2 = str;
            while (*str2 && *str2 != ':' && *str2 != ' ' && *str2 != '\t')
                str2++;
            c = *str2;
            *str2 = '\0';

            tpnt1 = _dl_load_shared_library(&rpnt, NULL, str, "./");
            if (!tpnt1) {
                fprintf(stderr, "can't preload library %s\n", str);
                return NULL;
            } else {
                tpnt1->rtld_flags = RTLD_NOW | RTLD_GLOBAL;
            }

            *str2 = c;
            str = str2;
            while (*str == ':' || *str == ' ' || *str == '\t')
                str++;
        }
    }

    nlist = 0;
    for (tcurr = _dl_loaded_modules; tcurr; tcurr = tcurr->next) {
        Elf32(Dyn) *this_dpnt;

        nlist++;
        for (this_dpnt = (Elf32(Dyn) *) tcurr->dynamic_addr; this_dpnt->d_tag; this_dpnt++) {
            if (this_dpnt->d_tag == DT_NEEDED) {
                char *name;
                //struct init_fini_list *tmp;

                lpntstr = (char*) (tcurr->dynamic_info[DT_STRTAB] + this_dpnt->d_un.d_val);
                name = _dl_get_last_path_component(lpntstr);

                if (strncmp(name, "ld", 2) == 0) {
                    continue;
                } else {
                    tpnt1 = _dl_load_shared_library(&rpnt, tcurr, lpntstr, libPath);
                }

                if (!tpnt1) {
                    fprintf(stderr, "can't load needed library '%s'\n", lpntstr);
                    continue;
                }

#if 0
                tmp = alloca(sizeof(struct init_fini_list)); /* Allocates on stack, no need to free this memory */
                tmp->tpnt = tpnt1;
                tmp->next = tcurr->init_fini;
                tcurr->init_fini = tmp;
#endif

                tpnt1->rtld_flags = RTLD_NOW | RTLD_GLOBAL;

            }
        }
    }

    nscope_elem = nlist;

    if (_dl_loaded_modules->libtype == elf_executable) {
        --nlist; /* Exclude the application. */
        tcurr = _dl_loaded_modules->next;
    } else
        tcurr = _dl_loaded_modules;

    scope_elem_list = (struct elf_resolve **) malloc(nscope_elem * sizeof(struct elf_resolve *));

    for (i = 0, tcurr = _dl_loaded_modules; tcurr; tcurr = tcurr->next)
        scope_elem_list[i++] = tcurr;

    _dl_loaded_modules->symbol_scope.r_list = scope_elem_list;
    _dl_loaded_modules->symbol_scope.r_nlist = nscope_elem;

    global_scope = &_dl_loaded_modules->symbol_scope; 

    /* Build the local scope for each loaded modules. */
    local_scope = malloc(nscope_elem * sizeof(struct elf_resolve *));
    i = 1;
    for (tcurr = _dl_loaded_modules->next; tcurr; tcurr = tcurr->next) {
        unsigned int k;
        cnt = _dl_build_local_scope(local_scope, scope_elem_list[i++]);
        tcurr->symbol_scope.r_list = malloc(cnt * sizeof(struct elf_resolve *));
        tcurr->symbol_scope.r_nlist = cnt;
        memcpy (tcurr->symbol_scope.r_list, local_scope, cnt * sizeof (struct elf_resolve *));
        /* Restoring the init_flag.*/
        for (k = 1; k < nscope_elem; k++)
            scope_elem_list[k]->init_flag &= ~DL_RESERVED;
    }

    free(local_scope);

    if(e_machine == EM_MIPS) {
        _dl_perform_mips_global_got_relocations(_dl_loaded_modules);
    }

    if (_dl_symbol_tables) {
        if (_dl_fixup(_dl_symbol_tables, global_scope, unlazy)) {
            fprintf(stderr, "_dl_fixup error\n");
        }
    }

    //TODO
#if 0
    for (tpnt = _dl_loaded_modules; tpnt; tpnt = tpnt->next) {
        if (tpnt->relro_size)
            _dl_protect_relro (tpnt);
    }
#endif

    return uc;
}


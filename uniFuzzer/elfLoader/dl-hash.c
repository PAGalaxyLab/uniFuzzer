#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "dl-hash.h"
#include "dl-defs.h"

extern struct elf_resolve *_dl_loaded_modules;

static __attribute_noinline__ const Elf32(Sym) *
check_match (const Elf32(Sym) *sym, char *strtab, const char* undef_name, int type_class)
{

    if (type_class & (sym->st_shndx == SHN_UNDEF))
        /* undefined symbol itself */
        return NULL;

    if (sym->st_value == 0)
        /* No value */
        return NULL;

    if (ELF_ST_TYPE(sym->st_info) > STT_FUNC
        && ELF_ST_TYPE(sym->st_info) != STT_COMMON)
        /* Ignore all but STT_NOTYPE, STT_OBJECT, STT_FUNC
         * and STT_COMMON entries since these are no
         * code/data definitions
         */
        return NULL;
#ifdef ARCH_SKIP_RELOC
    if (ARCH_SKIP_RELOC(type_class, sym))
        return NULL;
#endif
    if (strcmp(strtab + sym->st_name, undef_name) != 0)
        return NULL;

    /* This is the matching symbol */
    return sym;
}


static __inline__ Elf_Symndx _dl_elf_hash(const unsigned char *name)
{
    unsigned long hash=0;
    unsigned long tmp;

    while (*name) {
        hash = (hash << 4) + *name++;
        tmp = hash & 0xf0000000;
        /* The algorithm specified in the ELF ABI is as follows:
           if (tmp != 0)
               hash ^= tmp >> 24;
           hash &= ~tmp;
           But the following is equivalent and a lot
           faster, especially on modern processors. */
        hash ^= tmp;
        hash ^= tmp >> 24;
    }
    return hash;
}

static __always_inline const Elf32(Sym) *
_dl_lookup_sysv_hash(struct elf_resolve *tpnt, Elf32(Sym) *symtab, unsigned long hash,  const char* undef_name, int type_class)
{
    unsigned long hn;
    char *strtab;
    const Elf32(Sym) *sym;
    Elf_Symndx symidx;

    /* Avoid calling .urem here. */
    do_rem(hn, hash, tpnt->nbucket);
    strtab = (char *) (tpnt->dynamic_info[DT_STRTAB]);

    assert(tpnt->elf_buckets != NULL);

    for (symidx = tpnt->elf_buckets[hn]; symidx != STN_UNDEF; symidx = tpnt->chains[symidx]) {
        sym = check_match (&symtab[symidx], strtab, undef_name, type_class);
        if (sym != NULL)
            /* At this point the symbol is that we are looking for */
            return sym;
    }
    /* No symbol found into the current module*/
    return NULL;
}

struct elf_resolve *_dl_add_elf_hash_table(const char *libname,
    Elf32(Addr) loadaddr, unsigned long *dynamic_info, unsigned long dynamic_addr,
    attribute_unused unsigned long dynamic_size)
{
    Elf_Symndx *hash_addr;
    struct elf_resolve *tpnt;
    int i;

    tpnt = malloc(sizeof(struct elf_resolve));
    memset(tpnt, 0, sizeof(struct elf_resolve));

    if (!_dl_loaded_modules)
        _dl_loaded_modules = tpnt;
    else {
        struct elf_resolve *t = _dl_loaded_modules;
        while (t->next)
            t = t->next;
        t->next = tpnt;
        t->next->prev = t;
        tpnt = t->next;
    }

    tpnt->next = NULL;
    tpnt->init_flag = 0;
    tpnt->libname = strdup(libname);
    tpnt->dynamic_addr = (Elf32(Dyn) *)dynamic_addr;
    tpnt->libtype = loaded_file;

    if (dynamic_info[DT_HASH] != 0) {
        hash_addr = (Elf_Symndx*)(dynamic_info[DT_HASH]);
        tpnt->nbucket = *hash_addr++;
        tpnt->nchain = *hash_addr++;
        tpnt->elf_buckets = hash_addr;
        hash_addr += tpnt->nbucket;
        tpnt->chains = hash_addr;
    }
    tpnt->loadaddr = loadaddr;
    for (i = 0; i < DYNAMIC_SIZE; i++)
        tpnt->dynamic_info[i] = dynamic_info[i];
    return tpnt;
}

char *_dl_find_hash(const char *name, struct r_scope_elem *scope, struct elf_resolve *mytpnt,
    int type_class, struct symbol_ref *sym_ref)
{
    uf_debug("finding symbol %s\n", name);
    struct elf_resolve *tpnt = NULL;
    Elf32(Sym) *symtab;
    int i = 0;

    unsigned long elf_hash_number = 0xffffffff;
    const Elf32(Sym) *sym = NULL;

    char *weak_result = NULL;
    struct r_scope_elem *loop_scope;

    if ((sym_ref) && (sym_ref->sym) && (ELF32_ST_VISIBILITY(sym_ref->sym->st_other) == STV_PROTECTED)) {
            sym = sym_ref->sym;
        if (mytpnt)
            tpnt = mytpnt;
    } else
    for (loop_scope = scope; loop_scope && !sym; loop_scope = loop_scope->next) {
        for (i = 0; i < loop_scope->r_nlist; i++) {
            tpnt = loop_scope->r_list[i];

            if (!(tpnt->rtld_flags & RTLD_GLOBAL) && mytpnt) {
                if (mytpnt == tpnt)
                    ;
                else {
                    struct init_fini_list *tmp;

                    for (tmp = mytpnt->rtld_local; tmp; tmp = tmp->next) {
                        if (tmp->tpnt == tpnt)
                            break;
                    }
                    if (!tmp)
                        continue;
                }
            }
            /* Don't search the executable when resolving a copy reloc. */
            if ((type_class &  ELF_RTYPE_CLASS_COPY) && tpnt->libtype == elf_executable)
                continue;

            /* If the hash table is empty there is nothing to do here.  */
            if (tpnt->nbucket == 0)
                continue;

            symtab = (Elf32(Sym) *) (intptr_t) (tpnt->dynamic_info[DT_SYMTAB]);

                /* Use the old SysV-style hash table */

                /* Calculate the old sysv hash number only once */
                if (elf_hash_number == 0xffffffff)
                    elf_hash_number = _dl_elf_hash((const unsigned char *)name);

                sym = _dl_lookup_sysv_hash(tpnt, symtab, elf_hash_number, name, type_class);
                if (sym != NULL)
                    /* If sym has been found, do not search further */
                    break;
        } /* End of inner for */
    }
    uf_debug("sym is %p\n", sym);

    if (sym) {
        if (sym_ref) {
            sym_ref->sym = sym;
            sym_ref->tpnt = tpnt;
        }
        /* At this point we have found the requested symbol, do binding */

        switch (ELF_ST_BIND(sym->st_info)) {
            case STB_WEAK:
            case STB_GLOBAL:
                return (char *)DL_FIND_HASH_VALUE(tpnt, type_class, sym);
            default:    /* Local symbols not handled here */
                break;
        }
    }
    return weak_result;
}

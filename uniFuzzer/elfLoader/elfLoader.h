#ifndef ELFLOADER_H
#define ELFLOADER_H

uc_engine *loadELF(const char *target, char *preload, char *libPath);

/*
uc_engine *createUE(Elf *elf, int is32bits);
int checkBits(Elf *elf);
setupMem(Elf *elf, uc_engine *uc, int is32bits, uint64_t baseAddr, int fd);
*/

#endif

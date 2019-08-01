uniFuzzer
---------

uniFuzzer is a fuzzing tool for closed-source binaries based on [Unicorn](https://github.com/unicorn-engine/unicorn) and [LibFuzzer](https://llvm.org/docs/LibFuzzer.html). Currently it supports fuzzing 32-bits LSB ELF files on ARM/MIPS, which are usually seen in IoT devices.


# Features

- very little [hack](#-hack-on-unicorn) and easy to build
- can target any specified function or code snippet
- coverage-guided fuzzing with considerable speed
- dependence resolved and loaded automatically
- library function override by PRELOAD


# Build

1. Reverse the target binary and find interesting functions for fuzzing.
2. Create a `.c` file in the directory `callback`, which should contain the following callbacks:

* `void onLibLoad(const char *libName, void *baseAddr, void *ucBaseAddr)`: It's invoked each time an dependent library is loaded in Unicorn.
* `int uniFuzzerInit(uc_engine *uc)`: It's invoked just after all the binaries been loaded in Unicorn. Stack/heap/registers can be setup up here.
* `int uniFuzzerBeforeExec(uc_engine *uc, const uint8_t *data, size_t len)`: It's invoked before each round of fuzzing execution.
* `int uniFuzzerAfterExec(uc_engine *uc)`: It's invoked after each round of fuzzing execution.

3. Run `make` and get the fuzzing tool named `uf`.


# Run

uniFuzzer uses the following environment variables as parameters:

- `UF_TARGET`: Path of the target ELF file
- `UF_PRELOAD`: Path of the preload library. Please make sure that the library has the same architecture as the target.
- `UF_LIBPATH`: Paths in which the dependent libraries reside. Use `:` to separate multiple paths.

And the fuzzing can be started using the following command:

```bash
UF_TARGET=<target> [UF_PRELOAD=<preload>] UF_LIBPATH=<libPath> ./uf
```


# Demo

There comes a demo for basic usage. The demo contains the following files:

- demo-vuln.c: This is the target for fuzzing. It contains a simple function named `vuln()` which is vulnerable to stack/heap overflow.
- demo-libcpreload.c: This is for PRELOAD hooking. It defines an empty `printf()` and simplified `malloc()/free()`.
- callback/demo-callback.c: This defines the necessary callbacks for fuzzing the demo `vuln()` function.

First, please install gcc for mipsel (package `gcc-mipsel-linux-gnu` on Debian) to build the demo:

```bash
# the target binary
# '-Xlinker --hash-style=sysv' tells gcc to use 'DT_HASH' instead of 'DT_GNU_HASH' for symbol lookup
# since currently uniFuzzer does not support 'DT_GNU_HASH'
mipsel-linux-gnu-gcc demo-vuln.c -Xlinker --hash-style=sysv -no-pie -o demo-vuln

# the preload library
mipsel-linux-gnu-gcc -shared -fPIC -nostdlib -Xlinker --hash-style=sysv demo-libcpreload.c -o demo-libcpreload.so
```

Or you can just use the file `demo-vuln` and `demo-libcpreload.so`, which are compiled using the commands above.

Next, run `make` to build uniFuzzer. Please note that if you compiled the MIPS demo by yourself, then some addresses might be different from the prebuilt one and `demo-callback.c` should be updated accordingly.

Finally, make sure that the libc library of MIPS is ready. On Debian it's in `/usr/mipsel-linux-gnu/lib/` after installing the package `libc6-mipsel-cross`, and that's what `UF_LIBPATH` should be:

```bash
UF_TARGET=<path to demo-vuln> UF_PRELOAD=<path to demo-libcpreload.so> UF_LIBPATH=<lib path for MIPS> ./uf
```

# Hack on Unicorn

Unicorn clears the JIT cache of QEMU due to this [issue](https://github.com/unicorn-engine/unicorn/issues/1043), which slows down the speed of fuzzing since the target binary would have to be JIT re-compiled during each round of execution. 

We can comment out `tb_flush(env);` as stated in that issue for performance.

# TODO

* support for syscall
* support for other architectures and binary formats
* support `GNU_HASH`
* integrate environment setup and provide APIs

CC := clang
CFLAGS := -Wall -fPIC
#CFLAGS += -O2
CFLAGS += -g -DUF_DEBUG
LDFLAGS := -fsanitize=fuzzer -lunicorn -pthread

OUT := uf
.DEFAULT_GOAL := all

SRC := $(wildcard callback/*.c) \
		$(wildcard uniFuzzer/*.c) \
		$(wildcard uniFuzzer/elfLoader/*.c)
OBJ := $(SRC:.c=.o)

MAIN_SRC := uniFuzzer/uniFuzzer.c
MAIN_OBJ := uniFuzzer/uniFuzzer.o
$(MAIN_OBJ): CFLAGS += -fsanitize=fuzzer -IuniFuzzer/elfLoader

OTHER_SRC := $(filter-out $(MAIN_SRC),$(SRC))
OTHER_OBJ := $(OTHER_SRC:.c=.o)

%.o:%.c
	$(CC) -o $@ $(CFLAGS) -c $<

all:$(OUT)

$(OUT):$(OBJ)
	$(CC) -o $@ $(LDFLAGS) $^

clean:
	rm -f $(OUT) $(OBJ)

.PHONY: all clean


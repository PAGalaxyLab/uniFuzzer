#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int vuln(unsigned char *input) {
    size_t input_len = *input;
    printf("the input size is %d\n", input_len);
    char stack_buf[128];
    char *heap_buf = malloc(60);

    // heap overflow
    strcpy(heap_buf, input+1);
    // stack overflow
    memcpy(stack_buf, input+1, input_len);
    
    free(heap_buf);
    return input_len;
}

int main(int argc, char *argv[]) {
    char input[256];
    int fin = open(argv[1], O_RDONLY);
    read(fin, input, sizeof(input));

    int res = vuln(input);
    return res;
}

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

int main(int argc, char ** argv) {
    uint32_t in;

    if (argc > 1) {
        int fd = open(argv[1], O_RDONLY);
        read(fd, &in, 4);
        close(fd);
        exit(0);
    } else {
        fprintf(stderr, "No filename provided.\n");
        exit(1);
    }
}

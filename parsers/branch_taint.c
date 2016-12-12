#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char ** argv) {
    char v1, v2, v3;

    if (argc > 1) {
        int fd = open(argv[1], O_RDONLY);
        read(fd, &v1, 1);
        if (v1 == '%') {
            read(fd, &v1, 1);
            exit(0);
        } else {
            exit(1);
        }
        close(fd);
    } else {
        fprintf(stderr, "No filename provided.\n");
        exit(1);
    }

    return 0;
}

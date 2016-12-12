#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char ** argv) {
    char v1, v2, v3;

    if (argc > 1) {
        int fd = open(argv[1], O_RDONLY);
        read(fd, &v1, 1);
        read(fd, &v2, 2);
        v3 = v1 + v2;
        close(fd);
    } else {
        fprintf(stderr, "No filename provided.\n");
    }
}

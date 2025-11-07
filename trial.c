#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <sys/resource.h>
#include <errno.h>

int main(int argc, char **argv){
    pid_t pid;
    struct timespec ts = {0, 50000000}; // 50ms
    char cwd[1024];
    char buf[128];
    int cnt = 0;

    while (1) {
        pid = getpid();
        getppid();
        getuid();
        geteuid();
        getgid();
        getegid();

        if (getcwd(cwd, sizeof(cwd)) == NULL) {}
        snprintf(buf, sizeof(buf), "iter %d pid %d\n", ++cnt, (int)pid);
        write(STDOUT_FILENO, buf, strlen(buf));

        int fdnull = open("/dev/null", O_WRONLY);
        if (fdnull >= 0) {
            write(fdnull, "x", 1);
            close(fdnull);
        }

        int fdur = open("/dev/urandom", O_RDONLY);
        if (fdur >= 0) {
            unsigned char rbuf[16];
            read(fdur, rbuf, sizeof(rbuf));
            close(fdur);
        }

        int fdtmp = open("/proc/self/stat", O_RDONLY);
        if (fdtmp >= 0) {
            char r[64];
            read(fdtmp, r, sizeof(r));
            fstat(fdtmp, &(struct stat){0});
            close(fdtmp);
        }

        struct stat st;
        stat("/", &st);
        lstat(argv[0], &st);

        void *m = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
        if (m != MAP_FAILED) {
            memset(m, 0, 16);
            munmap(m, 4096);
        }

        void *p = malloc(256);
        if (p) {
            memset(p, 1, 256);
            free(p);
        }

        struct utsname u;
        uname(&u);

        struct timeval tv;
        gettimeofday(&tv, NULL);

        int sv[2];
        if (pipe(sv) == 0) {
            write(sv[1], "p", 1);
            read(sv[0], buf, 1);
            close(sv[0]);
            close(sv[1]);
        }

        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s >= 0) {
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(0);
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            connect(s, (struct sockaddr*)&addr, sizeof(addr));
            close(s);
        }

        struct rusage ru;
        getrusage(RUSAGE_SELF, &ru);

        nanosleep(&ts, NULL);

        sleep(1);
    }

    return 0;
}


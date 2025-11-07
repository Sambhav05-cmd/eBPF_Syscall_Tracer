#include <stdio.h>
#include <string.h>

int main() {
    FILE *fp = fopen("/usr/include/asm/unistd_64.h", "r");
    if (!fp) {
        perror("fopen input");
        return 1;
    }

    FILE *out = fopen("syscall_table.txt", "w");
    if (!out) {
        perror("fopen output");
        fclose(fp);
        return 1;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "#define __NR_", 12) == 0) {
            char name[128];
            int num;
            if (sscanf(line, "#define __NR_%127s %d", name, &num) == 2) {
                for (int i = 0; name[i]; i++) {
                    if (name[i] == ' ' || name[i] == '\t') {
                        name[i] = '\0';
                        break;
                    }
                }
                fprintf(out, "%-20s -> %d\n", name, num);
            }
        }
    }

    fclose(fp);
    fclose(out);
    printf("Saved syscall mapping to syscall_table.txt\n");
    return 0;
}


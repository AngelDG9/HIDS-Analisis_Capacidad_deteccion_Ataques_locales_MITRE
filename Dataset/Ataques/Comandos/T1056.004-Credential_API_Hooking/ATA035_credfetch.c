/* ATA035 · T1056.004 Credential API Hooking — binario de laboratorio "credfetch"
 * ----------------------------------------------------------------------------
 * Proceso INOCUO del propio ataque que obtiene credenciales SIMULADAS por dos
 * vias de la API de libc:
 *   1) `getenv("SERVICE_TOKEN")`            -> variable de entorno.
 *   2) `fgets()` sobre un fichero de credenciales simulado (como un login real).
 * Con `LD_PRELOAD=hook.so`, la libreria ATA035_hook.c intercepta AMBAS llamadas
 * y registra lo capturado. NO toca procesos ni credenciales reales.
 *
 * Compilar (en la maquina con toolchain):
 *   gcc -O2 -o credfetch ATA035_credfetch.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1]
                                  : "/home/angel/lab-attack/ATA035/credencial_simulada.txt";
    char buf[256];

    const char *tok = getenv("SERVICE_TOKEN");
    printf("token_env=%s\n", tok ? tok : "(none)");

    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return 1;
    }
    if (fgets(buf, sizeof buf, f)) {
        buf[strcspn(buf, "\r\n")] = '\0';
        printf("password_file=%s\n", buf);
    }
    fclose(f);
    return 0;
}

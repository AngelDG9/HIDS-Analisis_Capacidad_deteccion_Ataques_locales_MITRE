/* ATA036 · T1565.003 Runtime Data Manipulation — proceso de laboratorio "target"
 * ----------------------------------------------------------------------------
 * Proceso INOCUO del propio ataque que mantiene un DATO EN USO en memoria
 * (`char dato[]`, segmento .data) y lo escribe periodicamente en un fichero de
 * estado. El atacante lo MANIPULA EN MEMORIA mientras corre (ver memedit).
 * NO es un proceso del sistema: es un binario de laboratorio creado para el ataque.
 *
 * Compilar (en la maquina con toolchain):
 *   gcc -O0 -o target ATA036_target.c
 *     (-O0 para que `dato` quede como variable de memoria localizable)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

volatile char dato[32] = "SALDO=1000";

int main(int argc, char **argv) {
    const char *out = (argc > 1) ? argv[1] : "/home/angel/lab-attack/ATA036/target_state.log";
    const char *pidfile = (argc > 2) ? argv[2] : "/home/angel/lab-attack/ATA036/target_pid.txt";

    /* Proceso DE LABORATORIO que se declara trazable: con yama ptrace_scope=1
       (por defecto en Ubuntu) un proceso NO padre no puede adjuntarse; el
       binario de laboratorio habilita PR_SET_PTRACER_ANY para que la
       herramienta del ataque (memedit, mismo usuario) pueda hacerlo. */
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

    FILE *pf = fopen(pidfile, "w");
    if (pf) { fprintf(pf, "%d\n", (int)getpid()); fclose(pf); }

    for (int i = 0; i < 120; i++) {
        FILE *o = fopen(out, "a");
        if (o) { fprintf(o, "%s\n", (const char *)dato); fclose(o); }
        sleep(1);
    }
    return 0;
}

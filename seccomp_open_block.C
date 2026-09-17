#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int main() {
    scmp_filter_ctx ctx;

    // Acción por defecto: permitir todo. Solo bloqueamos open/openat explícitamente.
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        fprintf(stderr, "Error al iniciar seccomp\n");
        return 1;
    }

    // Bloquear open y openat, devolviendo EACCES cuando se invoquen
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(openat), 0);

    if (seccomp_load(ctx) < 0) {
        fprintf(stderr, "Error al cargar el filtro seccomp\n");
        return 1;
    }

    printf("Filtro seccomp cargado. Intentando abrir archivo...\n");

    int fd = open("prueba.txt", O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        printf("open() fallo: %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("open() tuvo exito, fd=%d\n", fd);
        close(fd);
    }

    seccomp_release(ctx);
    return 0;
}
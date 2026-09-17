#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>

// Traduce numero de syscall (x86_64) a nombre.
// Los numeros vienen de <sys/syscall.h>, que a su vez se basa en
// /usr/include/x86_64-linux-gnu/asm/unistd_64.h (ver pregunta guia 6).
// Cubre las syscalls mas comunes; las que no estan se muestran como syscall_<numero>.
const char* syscall_name(long long num) {
    switch (num) {
        case SYS_read: return "read";
        case SYS_write: return "write";
        case SYS_open: return "open";
        case SYS_close: return "close";
        case SYS_stat: return "stat";
        case SYS_fstat: return "fstat";
        case SYS_lstat: return "lstat";
        case SYS_poll: return "poll";
        case SYS_lseek: return "lseek";
        case SYS_mmap: return "mmap";
        case SYS_mprotect: return "mprotect";
        case SYS_munmap: return "munmap";
        case SYS_brk: return "brk";
        case SYS_rt_sigaction: return "rt_sigaction";
        case SYS_rt_sigprocmask: return "rt_sigprocmask";
        case SYS_ioctl: return "ioctl";
        case SYS_access: return "access";
        case SYS_pipe: return "pipe";
        case SYS_select: return "select";
        case SYS_dup: return "dup";
        case SYS_dup2: return "dup2";
        case SYS_nanosleep: return "nanosleep";
        case SYS_getpid: return "getpid";
        case SYS_socket: return "socket";
        case SYS_connect: return "connect";
        case SYS_execve: return "execve";
        case SYS_exit: return "exit";
        case SYS_wait4: return "wait4";
        case SYS_fcntl: return "fcntl";
        case SYS_getdents: return "getdents";
        case SYS_getcwd: return "getcwd";
        case SYS_chdir: return "chdir";
        case SYS_rename: return "rename";
        case SYS_mkdir: return "mkdir";
        case SYS_rmdir: return "rmdir";
        case SYS_unlink: return "unlink";
        case SYS_readlink: return "readlink";
        case SYS_chmod: return "chmod";
        case SYS_chown: return "chown";
        case SYS_umask: return "umask";
        case SYS_getuid: return "getuid";
        case SYS_getgid: return "getgid";
        case SYS_geteuid: return "geteuid";
        case SYS_getegid: return "getegid";
        case SYS_sigaltstack: return "sigaltstack";
        case SYS_arch_prctl: return "arch_prctl";
        case SYS_gettid: return "gettid";
        case SYS_futex: return "futex";
        case SYS_set_tid_address: return "set_tid_address";
        case SYS_clock_gettime: return "clock_gettime";
        case SYS_exit_group: return "exit_group";
        case SYS_openat: return "openat";
        case SYS_newfstatat: return "newfstatat";
        case SYS_set_robust_list: return "set_robust_list";
        case SYS_prlimit64: return "prlimit64";
        case SYS_getrandom: return "getrandom";
        case SYS_statx: return "statx";
        case SYS_rseq: return "rseq";
        default: {
            static char buf[32];
            snprintf(buf, sizeof(buf), "syscall_%lld", num);
            return buf;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <programa> [argumentos...]\n", argv[0]);
        return 1;
    }

    pid_t child = fork();

    if (child == 0) {
        // Proceso hijo: se marca como trazable y ejecuta el programa pedido
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        _exit(1);
    } else {
        int status;
        struct user_regs_struct regs;
        int en_syscall = 0; // 0 = esperando ENTRADA, 1 = esperando SALIDA

        waitpid(child, &status, 0); // stop inicial provocado por el execve

        while (1) {
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            waitpid(child, &status, 0);
            if (WIFEXITED(status)) break;

            ptrace(PTRACE_GETREGS, child, NULL, &regs);

            if (en_syscall == 0) {
                printf("PID %d - ENTRADA - %-16s (num=%lld)\n",
                       child, syscall_name(regs.orig_rax), (long long)regs.orig_rax);
            } else {
                printf("PID %d - SALIDA  - %-16s (num=%lld) -> ret=%lld\n",
                       child, syscall_name(regs.orig_rax), (long long)regs.orig_rax, (long long)regs.rax);
            }
            en_syscall = !en_syscall;
        }
    }
    return 0;
}

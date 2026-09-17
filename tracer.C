# include <stdio.h>
# include <sys/ptrace.h>
# include <sys/wait.h>

# include <sys/types.h>
# include <sys/user.h>
# include <unistd.h>

int main (int argc , char * argv []) {

pid_t child = fork () ;

if ( child == 0) {
ptrace ( PTRACE_TRACEME , 0 , NULL , NULL ) ;
execvp ( argv [1] , & argv [1]) ;
} 
else
{

int status ;
struct user_regs_struct regs ;

int en_syscall = 0;


while (1) {
waitpid ( child , & status , 0) ;

if(WIFEXITED(status)) break;
ptrace(PTRACE_GETREGS, child, NULL, &regs);

if(en_syscall==0){
    printf("PID %d - ENTRADA - Syscall numero: %lld\n", child, regs.orig_rax);
} else{
    printf("PID %d - SALIDA - Syscall numero: %lld\n", child, regs.orig_rax);
}
en_syscall = !en_syscall;
ptrace(PTRACE_SYSCALL, child, NULL, NULL);
}

}
return 0;


}
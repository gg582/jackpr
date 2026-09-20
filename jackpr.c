#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>

// 8-byte packing macro
#define PACK64(a,b,c,d,e,f,g,h) \
    (((uint64_t)(a) << 56) | ((uint64_t)(b) << 48) | \
     ((uint64_t)(c) << 40) | ((uint64_t)(d) << 32) | \
     ((uint64_t)(e) << 24) | ((uint64_t)(f) << 16) | \
     ((uint64_t)(g) <<  8) | ((uint64_t)(h)))

#define CMP_STDIN  PACK64('s','t','d','i','n', 0 , 0 , 0 )
#define CMP_STDOUT PACK64('s','t','d','o','u','t', 0 , 0 )
#define CMP_STDERR PACK64('s','t','d','e','r','r', 0 , 0 )

#define TTY_PATH_MAX 256

// inject syscall
long inject(pid_t pid, struct user_regs_struct *orig, long nr, long *args) {
    struct user_regs_struct regs = *orig;
    // Syscall NR
    regs.rax = nr;
    //  | rdi(long) | rsi(long) | rdx(long) | r10(long)
    regs.rdi = args[0];
    regs.rsi = args[1];
    regs.rdx = args[2];
    regs.r10 = args[3];

    // replace the tracee's register state with the prepared syscall state
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    // execute the injected syscall instruction at the current RIP
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    // return result (RAX)
    return regs.rax;
}

/// parse a flag and return.
/// return value: 001(2): stdin
///               010(2): stdout
///               100(2): stderr
///
///               example: 011(2): stdin|stdout
///                        111(2): stdin|stdout|stderr
///                        110(2): stdout|stderr
///                        101(2): stderr|stdin
/// pack up to 8 bytes of a string into an int64; big-endian order to match PACK64
int64_t pack_flag(const char *s) {
    int64_t v = 0;
    for(int i = 0; i < 8 && s[i] != '\0'; i++) {
        v |= ((uint64_t)(unsigned char)s[i]) << (56 - i * 8);
    }
    return v;
}

int8_t parse_flag(const char *flags) {
    int8_t flag_stdin =  1<<0;
    int8_t flag_stdout = 1<<1;
    int8_t flag_stderr = 1<<2;

    /// flag to return
    int8_t final_flag = (int8_t)0;


    char *savePtr;
    char *token;
    const char *delim = "|";

    token = strtok_r((char *)flags, delim, &savePtr);

    while(token) {
        switch(pack_flag(token)) {
            case CMP_STDIN:
                final_flag |= flag_stdin;
                break;
            case CMP_STDOUT:
                final_flag |= flag_stdout;
                break;
            case CMP_STDERR:
                final_flag |= flag_stderr;
                break;
        }
        token = strtok_r(NULL, delim, &savePtr);
    }
    return final_flag;
}

void help(char *argv[]) {
    // --help: 6 bytes
    // -h: 2 bytes
    if(!strcmp("--help", (const char *)argv[1])
     ||!strcmp("-h",(const char *)argv[1])) {
        const char help[1024] = "jackpr is a minimalist utility for taking a running program and attaching it to the current terminal.\r\n"
                                   "jackpr <target_pid>: Hijack target_pid's stdin, stdout, stderr into current pty/tty.\r\n"
                                   "jackpr <target_pid> stdin: Hijack target_pid's stdin into current pty/tty.\r\n"
                                   "jackpr <target_pid> stdout: Hijack target_pid's stdout into current pty/tty.\r\n"
                                   "jackpr <target_pid> stderr: Hijack target_pid's stderr into current pty/tty.\r\n"
                                   "jackpr <target_pid> stdin|stdout: Hijack target_pid's stdin and stdout into current pty/tty.\r\n"
                                   "jackpr <target_pid> stdin|stderr: Hijack target_pid's stdin and stderr into current pty/tty.\r\n"
                                   "jackpr <target_pid> stdout|stderr: Hijack target_pid's stdout and stderr into current pty/tty.\r\n"
                                   "visit https://github.com/gg582/jackpr to see more.\r\n";
        fputs(help, stderr);
        exit(0);
    }
}

/** check if given fd is connected to the current terminal
 *
 * | ... | RIP | .... (256 bytes) |
 * there's no need to use TTY_PATH_MAX as 4096.
**/
_Bool check_io_connections(int fd, char *tty_path) {
    int result = ttyname_r(fd, tty_path, TTY_PATH_MAX);
    if(result) {
        fprintf(stderr, "%s is disconnected. (code: %d)", !fd ? "stdin" : (fd == 1 ? "stdout": "stderr"), result);
        return 0;
    }
    return 1;
}

void attach_to_pid(int pid) {
    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        fputs("error: failed to attach to a target pid.", stderr);
        exit(-1);
    }
    waitpid(pid, NULL, 0);
}

void hijack_terminal(int pid, int new_fd, struct user_regs_struct *regs, long *args, int8_t flag) {
    for(int i = 0;
            i < STDIN_FILENO + STDOUT_FILENO + STDERR_FILENO;
            i++) {
        args[0] = new_fd;
        args[1] = i;
        args[2] = args[3] = 0;
        if((flag >> i) & 1) inject(pid, regs, SYS_dup2, args);
    }
}

/// run jackpr
int run_jackpr(int argc, char *argv[])
{
    if(argc < 2) {
        fprintf(stderr, "usage: %s <pid>\n", argv[0]);
        return 1;
    }
    if(argc >= 2) {
        // help cmd
        help(argv);

        char tty_path[TTY_PATH_MAX];
        memset(tty_path, 0, TTY_PATH_MAX);

        // 111(2) == 7(10)
        int8_t flag = 7;

        if(argc == 3) {
            if(argv[2] != NULL) {
                flag = parse_flag((const char *)argv[2]);
            }
        }

        char *endptr;
        errno = 0;
        // input: 0123, result: 123
        // 0123 should not be 123(8)
        long pid = strtol(argv[1], &endptr, 10);
        if(endptr == argv[1]) {
            fputs("invalid pid", stderr);
            return -1;
        }
        if((errno == ERANGE)
        || (pid <= 0)
        || (pid > INT_MAX)) {
            fprintf(stderr, "invalid pid: %s\n", argv[1]);
            return -1;
        }

        if(*endptr) {
            fprintf(stderr, "invalid pid: %s\n", argv[1]);
            return -1;
        }

        else {
            // check if stdin, stdout, stderr are connected to the current terminal
            _Bool is_connected[STDIN_FILENO + STDOUT_FILENO + STDERR_FILENO] = { 0, 0, 0 };
            for(int i = 0;
                    i < STDIN_FILENO + STDOUT_FILENO + STDERR_FILENO;
                    i++) {

                is_connected[i] = check_io_connections(i, tty_path);
                if(!is_connected[i] && ((flag >> i) & 1)) {
                    return -1;
                }
            }

            if(!((is_connected[0] | is_connected[1]) | is_connected[2])) {
                fputs("stdin, stdout, stderr are all disconnected. cannot hijack.", stderr);
                return -1;
            }

            // take controls over target pid
            attach_to_pid(pid);

            // backup original registers
            struct user_regs_struct orig_regs;
            ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs);

            // backup original memory
            long orig_code = ptrace(PTRACE_PEEKTEXT, pid, (void *)orig_regs.rip, NULL);

            // wipe out last 2 bytes.
            // ~0xFFFF == 0xFFFFFFFFFFFF0000
            // 0xFFFFFFFFFFFF0000 & orig_code
            //
            // Op      | Result
            // 0 AND 0 | 0
            // 0 AND 1 | 0
            // 1 AND 0 | 0
            // 1 AND 1 | 1
            // 0 AND N is always zero. N = {0, 1}
            // ~0xFFFF's last 2 bytes are 0x00 and 0x00.
            // replace the instruction at RIP with the x86-64 syscall opcode.
            //   C integer: 0x050f
            //   memory:    0x0f 0x05
            // AND clears the original low 16 bits
            // OR places the syscall opcode into those bits
            // |........ ........ ........ ........| 0f 05 |
            // 0x050f is the little-endian integer representation
            // of the x86-64 syscall instruction bytes.
            long call = (orig_code & ~0xFFFF) | 0x050f;
            ptrace(PTRACE_POKETEXT, pid, (void *)orig_regs.rip, (void *)call);

            // place tty_path outside the SysV AMD64 red zone:
            //
            //                  RSP
            //                   |
            //                   v
            //   +-------------------------------+
            //   |           red zone            |
            //   |             128 B             |
            //   +-------------------------------+
            //   |                               |
            //   |         tty_path buffer       |
            //   |                               |
            //   +-------------------------------+
            //                   ^
            //                   |
            //               RSP - 256
            //
            // Keep the buffer below the 128-byte red zone;
            // we therefore use RSP - 256 rather than RSP - 128.
            unsigned long target_buf = orig_regs.rsp - 256;

            size_t len = strlen(tty_path) + 1;
            for(size_t i = 0; i < len; i += sizeof(long)) {
                long chunk = 0;
                memcpy(&chunk, tty_path + i, (len - i < sizeof(long)) ? len - i : sizeof(long));
                ptrace(PTRACE_POKETEXT, pid, (void *)(target_buf + i), (void *)chunk);
            }

            // open tty_path for reading and writing.
            long args[4] = { AT_FDCWD, target_buf, O_RDWR, 0 };
            long new_fd = inject(pid, &orig_regs, SYS_openat, (long *)args);

            if(new_fd >= 0) {
                // duplicate the tty fd onto the selected standard streams.
                hijack_terminal(pid, new_fd, &orig_regs, args, flag);
                
                // set arguments to zero before closing new_fd
                args[0] = new_fd;
                args[1] = args[2] = args[3] = 0;
                // close new_fd at the target process
                inject(pid, &orig_regs, SYS_close, args);
            }

            // restore original memory
            ptrace(PTRACE_POKETEXT, pid, (void *)orig_regs.rip, (void *)orig_code);
            // restore original registers
            ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
            // detach from the tracee and resume it.
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    return run_jackpr(argc, argv);
}

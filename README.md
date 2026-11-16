# Snort Rules for IoT Botnet Attacks (Project Code: CSL-I09)
### B.Tech VII Semester Cyber Security Lab Mini Project (Course Code: 7CS4-22 / 7CIT4-22)
**Department of Computer Science & Engineering (Internet of Things)**  
**Swami Keshvanand Institute of Technology, Management & Gramothan (SKIT), Jaipur**  
*(Affiliated to Rajasthan Technical University, Kota)*

---

## 1. Project & Student Metadata

| Metadata Field | Project Record Details |
| :--- | :--- |
| **Student Name** | **Kushal Kumar** |
| **University Roll No.** | **23ESKCY026** |
| **Branch / Specialization** | Computer Science & Engineering (Internet of Things) |
| **Class / Batch** | IoT-A-G1 |
| **Semester / Session** | VII Semester / Academic Year 2026-27 |
| **Course Name & Code** | Cyber Security Lab (7CS4-22 / 7CIT4-22) |
| **Allotted Project Title** | **Snort Rules for IoT Botnet Attacks** |
| **Project Code** | **CSL-I09** |
| **Linked Syllabus Exp.** | Experiment 7 – Intrusion Detection System (Snort NIDS) |
| **Faculty Guide** | **Vikash Dhankar**, Assistant Professor, Department of CSE, SKIT |
| **Date of Submission** | 16 November 2026 |

---

## 2. Project Executive Overview
Internet of Things (IoT) devices such as IP surveillance cameras, smart gateway routers, and environmental sensors have proliferated globally. However, due to severe hardware resource constraints, legacy software stacks, and factory default configurations, these devices are routinely exposed to automated malware families like **Mirai**, **Bashlite (Gafgyt)**, and **Hajime**.

The **CSL-I09** project delivers an end-to-end Network Intrusion Detection System (NIDS) ruleset, configuration framework, and verification pipeline utilizing **Snort 2.9.x** and **Snort 3 (Snort++)**. The project provides:
1. **10 Custom Snort Detection Rules (SIDs 1000001–1000010)** capturing every phase of the Mirai IoT attack lifecycle: network scanning, credential brute-forcing, factory credential exploitation, post-authentication payload delivery, and denial-of-service flooding.
2. **Dual-Engine Architecture**: Production-grade configurations for Snort 2.9.x (`snort.conf`) and Snort 3 (`snort.lua`), alongside a standalone Python offline evaluation engine that parses PCAP files, tracks TCP state, computes sliding-window rate filters, and outputs standard `alert_fast` logs.
3. **Pure-Python Synthetic Traffic Generator**: Employs bit-accurate raw frame construction with RFC 1071 IP and TCP checksum calculations to produce 7 test scenario PCAPs without requiring root privileges or external sniffers.
4. **Complete Verification & Validation**: Automated unit testing suite achieving **100% True Positive Rate (Sensitivity)** and **0.0% False Positive Rate (Zero Fall-out)**.

---

## 3. Isolated Virtual Lab Topology (RFC 1918)

All testing is strictly constrained to an isolated RFC 1918 virtual subnet (`192.168.56.0/24`):

```text
       +-------------------------------------------------------------------------+
       |                  Virtual Network Subnet: 192.168.56.0/24                |
       +-------------------------------------------------------------------------+
             |                     |                     |                 |
             |                     |                     |                 |
      [192.168.56.5]        [192.168.56.10]       [192.168.56.11]   [192.168.56.100]
      Admin Workstation     Target IoT Camera     Smart Home GW     Mirai Attacker
      - Clean HTTP (80)     - Telnet (23, 2323)   - MQTT (1883)     - SYN Scanning
      - Clean SSH (22)      - HTTP WebUI (80)                       - Cred Brute-Force
      - Legitimate Traffic  - Target Device                         - Payload Delivery
                                   ^
                                   |
                           [192.168.56.105]
                         Secondary Port Scanner
                         - Vertical SYN Sweeps
```

- `192.168.56.5` : Legitimate Admin Workstation (Source for normal baseline traffic)
- `192.168.56.10`: Target IoT IP Camera (Exposes Telnet 23 & 2323, HTTP 80, SSH 22)
- `192.168.56.11`: Target Smart Home MQTT Gateway (Exposes MQTT 1883)
- `192.168.56.100`: Simulated Mirai Bot / Brute-Force Attacker Node
- `192.168.56.105`: Secondary Port Scanner Node

---

## 4. Custom Snort Ruleset (SIDs 1000001–1000010)

| SID | Rule Name / Description | Protocol & Ports | Key Detection Logic | Classtype |
| :--- | :--- | :--- | :--- | :--- |
| **1000001** | Telnet Connection Attempt to Port 23 | TCP / 23 | `flags:S,12; flow:to_server;` | attempted-recon |
| **1000002** | Mirai Telnet Connection to Alt-Port 2323 | TCP / 2323 | `flags:S,12; flow:to_server;` | attempted-recon |
| **1000003** | Mirai Brute-Force Username "root" | TCP / [23,2323] | `content:"root"; nocase; within:50; flow:to_server,established;` | attempted-user |
| **1000004** | Factory Credential "root:xc3511" | TCP / [23,2323] | `content:"xc3511"; nocase; flow:to_server,established;` | attempted-user |
| **1000005** | Factory Credential "root:vizxv" | TCP / [23,2323] | `content:"vizxv"; nocase; flow:to_server,established;` | attempted-user |
| **1000006** | Post-Auth Shell Command "/bin/busybox MIRAI" | TCP / [23,2323] | `content:"/bin/busybox"; content:"MIRAI"; distance:0; within:30;` | trojan-activity |
| **1000007** | Payload Download (wget/tftp) | TCP / [23,2323] | `pcre:"/(wget\|tftp)\s+http/i"; flow:to_server,established;` | trojan-activity |
| **1000008** | TCP SYN Port Scan from Single Source | TCP / Any | `flags:S,12; detection_filter:track by_src, count 20, seconds 5;` | attempted-recon |
| **1000009** | MQTT CONNECT Flood Attack | TCP / 1883 | `content:"\|10\|"; depth:1; detection_filter:track by_src, count 30, seconds 10;` | denial-of-service |
| **1000010** | Default Credential "admin:admin" Attempt | TCP / [23,2323] | `content:"admin"; nocase; content:"admin"; distance:0; within:10;` | attempted-user |

---

## 5. Test Scenarios and Detection Validation Matrix

| TC ID | PCAP File | Description | Expected Outcome | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | `tc01_normal_baseline.pcap` | Legitimate HTTP GET request from Admin | 0 Alerts (No false positive) | 0 Alerts | **PASS (Clean)** |
| **TC-02** | `tc02_telnet_syn_scan.pcap` | 25 SYN packets on Telnet ports 23 & 2323 | SIDs 1000001, 1000002, 1000008 | 31 Alerts | **PASS (Detected)** |
| **TC-03** | `tc03_telnet_bruteforce_root.pcap` | Telnet brute-force targeting "root" | SID 1000003 | 10 Alerts | **PASS (Detected)** |
| **TC-04** | `tc04_mirai_factory_creds.pcap` | Factory credentials `xc3511` & `vizxv` | SIDs 1000004, 1000005, 1000001 | 10 Alerts | **PASS (Detected)** |
| **TC-05** | `tc05_mirai_post_auth_loader.pcap` | Shell commands `busybox MIRAI`, `wget` | SIDs 1000006, 1000007 | 6 Alerts | **PASS (Detected)** |
| **TC-06** | `tc06_vertical_port_scan.pcap` | Rapid SYN scan across ports 1–30 | SID 1000008 (Threshold) | 12 Alerts | **PASS (Detected)** |
| **TC-07** | `tc07_negative_test_encrypted_ssh.pcap` | Encrypted SSH binary traffic | 0 Alerts (No false positive) | 0 Alerts | **PASS (Clean)** |
| **FULL** | `iot_botnet_full_test_suite.pcap` | Combined multi-stage attack replay | Multi-SID alert sequence | 69 Alerts | **PASS (Detected)** |

---

## 6. Directory Structure

```text
Snort_Rules_IoT_Botnet_Attacks/
├── README.md                           # Master Project Documentation
├── requirements.txt                     # Python Dependencies (docx, reportlab, matplotlib)
├── .gitignore                           # Git Ignore Filters
├── config/
│   ├── snort.conf                       # Production Snort 2.9.x Configuration File
│   └── snort.lua                        # Production Snort 3 (Snort++) Configuration File
├── rules/
│   └── local.rules                      # 10 Custom Detection Rules (SIDs 1000001-1000010)
├── src/
│   ├── traffic_generator.py             # Pure-Python PCAP Builder (RFC 1071 Checksums)
│   ├── alert_analyzer.py                # Snort Rule Validator & Offline PCAP Engine
│   └── main.py                          # Master Pipeline Orchestrator & Dashboard
├── scripts/
│   ├── setup.sh                         # Linux/Bash Environment Setup Script
│   ├── validate_rules.sh                # Rule Syntax Validation Script
│   └── run_tests.sh                     # Automated Test Execution Script
├── tests/
│   ├── test_cases.md                    # Detailed Specifications for TC-01 to TC-07
│   └── test_alerts.py                   # Automated Python Unittest Suite (9 Tests)
├── captures/
│   ├── README.md                        # PCAP Technical Guide & Display Filters
│   ├── tc01_normal_baseline.pcap
│   ├── tc02_telnet_syn_scan.pcap
│   ├── tc03_telnet_bruteforce_root.pcap
│   ├── tc04_mirai_factory_creds.pcap
│   ├── tc05_mirai_post_auth_loader.pcap
│   ├── tc06_vertical_port_scan.pcap
│   ├── tc07_negative_test_encrypted_ssh.pcap
│   └── iot_botnet_full_test_suite.pcap
├── screenshots/
│   ├── rule_validation.png              # High-Res Console Output: Rule Validation
│   ├── alert_dashboard.png              # High-Res Console Output: Alert Dashboard
│   ├── detection_metrics.png            # 4-Quadrant Benchmark Analytics Chart
│   └── terminal_output.txt              # Captured Raw Terminal Execution Log
├── diagrams/
│   ├── network_topology.png             # Virtual Lab Network Architecture Diagram
│   ├── snort_architecture.png           # Snort IDS Multi-Layer Processing Pipeline
│   └── attack_flow.png                  # Mirai Attack Kill Chain Flowchart
├── report/
│   ├── Mini_Project_Report.docx         # Comprehensive 20+ Page Formal Academic Report
│   ├── Mini_Project_Report.pdf          # Professional Formatted PDF Project Report
│   └── Viva_Preparation.docx           # 50 Detailed Viva Questions & Model Answers
└── results/
    ├── alert.ids                        # Authentic Snort alert_fast Formatted Log
    ├── detection_summary.json           # Machine-Readable Benchmark Metrics
    ├── dashboard.txt                    # ASCII Executive Performance Dashboard
    └── test_results.md                  # Detailed Markdown Results Matrix
```

---

## 7. Quick Start & Execution Instructions

### A. Run Master Pipeline Orchestration
To generate synthetic PCAPs, validate rules, evaluate traffic, and output benchmarks:
```bash
python src/main.py
```

### B. Run Automated Unittest Suite
```bash
python -m unittest tests/test_alerts.py -v
```

### C. Replay Captured Traffic in Native Snort (Optional)
If native Snort 2.9.x is installed on the host system:
```bash
snort -T -c config/snort.conf
snort -c config/snort.conf -r captures/iot_botnet_full_test_suite.pcap -A fast -l results/
```

---

## 8. Academic References

1. Antonakakis, M., April, T., Bailey, M., Bernhard, M., Bursztein, E., Cochran, J., ... & Zhou, Y. (2017). *Understanding the Mirai Botnet*. In 26th USENIX Security Symposium (USENIX Security 17), pp. 1093-1110.
2. Roesch, M. (1999). *Snort - Lightweight Intrusion Detection for Networks*. In LISA '99: 13th Systems Administration Conference, pp. 229-238.
3. Postel, J. (1981). *Transmission Control Protocol - DARPA Internet Program Protocol Specification*. RFC 793.
4. Braden, R., Borman, D., & Partridge, C. (1988). *Computing the Internet Checksum*. RFC 1071.
5. Cisco Talos Intelligence Group. (2024). *Snort Users Manual 2.9.20*. Cisco Systems.

---

## 9. Ethical & Legal Disclaimer
This laboratory project is developed strictly for educational and academic evaluation purposes in partial fulfillment of the B.Tech degree curriculum at SKIT Jaipur. All packet captures, rule evaluations, and IP addresses belong strictly to the non-routable RFC 1918 private address space (`192.168.56.0/24`). No live malware was compiled or executed. Unauthorised packet sniffing and intrusion attempts on networks without prior written authorization are strictly illegal under the **Information Technology Act, 2000 (India)**.

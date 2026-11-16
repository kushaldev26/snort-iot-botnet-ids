# Viva Preparation — CSL-I09: Snort Rules for IoT Botnet Attacks

**Student:** Kushal Kumar | **Roll:** 23ESKCY026 | **SKIT Jaipur** | CSE-IoT VII Sem | 2026-27

---

## Section A — Snort IDS Basics (Q1–Q10)

**Q1. What is Snort? Who developed it and what is its primary purpose?**

A1. Snort is a free, open-source Network Intrusion Detection and Prevention System (NIDS/NIPS) originally developed by Martin Roesch in 1998 and now maintained by Cisco. Its primary purpose is to perform real-time traffic analysis and packet logging on IP networks. Snort can perform protocol analysis, content searching, and content matching to detect a wide variety of attacks and probes such as buffer overflows, stealth port scans, CGI attacks, SMB probes, and OS fingerprinting attempts. It supports three primary modes: sniffer mode (dumps packets to console), packet logger mode (logs packets to disk), and NIDS mode (analyzes traffic against a ruleset).

---

**Q2. What are the different types of Intrusion Detection Systems (IDS)?**

A2. IDS can be classified along two axes:
- **By placement:** (a) Host-based IDS (HIDS) — monitors a single host's logs, file system, and processes; e.g., OSSEC. (b) Network-based IDS (NIDS) — monitors network traffic at a point in the network; e.g., Snort, Suricata.
- **By detection method:** (a) Signature-based (misuse detection) — compares traffic against a database of known attack signatures; fast, low false-positives, but blind to novel attacks. (b) Anomaly-based — builds a baseline of normal behaviour and flags deviations; detects zero-days but higher false-positive rate. (c) Stateful protocol analysis — compares observed protocol behaviour against vendor-defined protocol specifications.

Snort is primarily signature-based but includes preprocessors (like sfportscan) that add anomaly detection capability.

---

**Q3. Explain the structure of a Snort rule with an example.**

A3. A Snort rule has two logical parts:
1. **Rule Header:** `action protocol src_ip src_port direction dst_ip dst_port`
2. **Rule Options:** `(keyword:value; keyword:value; ...)`

Example from this lab:
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 23 (
    msg:"Mirai Telnet Connection Attempt to IoT Device";
    flow:to_server,established;
    flags:S;
    classtype:attempted-recon;
    sid:1000001; rev:1;)
```
- **alert** — action (generate an alert and log the packet)
- **tcp** — protocol
- **$EXTERNAL_NET any** — source: any port on external network
- **-> $HOME_NET 23** — direction and destination: Telnet port 23 on home net
- **msg** — human-readable alert message
- **flow** — stream5 session state (to_server = client→server direction; established = after 3-way handshake)
- **flags:S** — only match TCP SYN packets
- **classtype** — Snort alert classification
- **sid** — unique rule identifier; **rev** — revision number

---

**Q4. What are Snort preprocessors? Name at least four used in this lab.**

A4. Preprocessors are plug-in modules that extend Snort's packet processing before the detection engine sees the data. They reassemble fragmented packets, track TCP sessions, and normalize protocols so that evasion techniques (fragmentation, session splicing) cannot bypass the detection engine.

Preprocessors used in this lab:
1. **frag3** — IP fragment reassembly; prevents fragment overlap attacks.
2. **stream5** — TCP/UDP session tracking and stream reassembly; enables `flow:` rule options. Configured for ports 23, 2323, 80, 22, 1883.
3. **sfportscan** — detects port scans (SYN, FIN, NULL, Xmas, UDP, distributed); generates pseudo-packet alerts for rule SID 1000008.
4. **http_inspect** — HTTP traffic normalization; decodes chunked encoding, URL encoding, Unicode to prevent HTTP evasion.
5. **smtp, ftp_telnet** — protocol-specific preprocessors for session tracking on Telnet and FTP sessions.

---

**Q5. What is the difference between alert, log, pass, drop, reject, and sdrop rule actions in Snort?**

A5.
| Action | Behaviour |
|--------|-----------|
| **alert** | Generate an alert using the selected alert method, then log the packet. Used in NIDS mode. |
| **log** | Log the packet only; no alert. |
| **pass** | Ignore the packet (whitelist). |
| **drop** | (Inline/NIPS only) Drop the packet and generate an alert. |
| **reject** | (Inline) Drop the packet, generate an alert, and send a TCP RST (for TCP) or ICMP port unreachable (for UDP). |
| **sdrop** | (Inline) Drop silently — no alert, no RST. |

In this lab (passive NIDS mode) only `alert` is used since we cannot drop traffic without being inline.

---

**Q6. What is the purpose of the `flow` keyword in Snort rules?**

A6. The `flow` keyword requires the stream5 preprocessor and allows rules to match only in specific session states. It has two parameter dimensions:
- **Direction:** `to_server` (client→server), `to_client` (server→client), `from_server`, `from_client`.
- **State:** `established` (after 3-way TCP handshake), `stateless` (match regardless of state), `not_established`.

Example: `flow:to_server,established` means match only on packets flowing from client to server within an established TCP session. This prevents firing on SYN packets (which have no established session) when you want to catch payload content, reducing false positives dramatically.

---

**Q7. What is the `detection_filter` keyword and how does it differ from `threshold`?**

A7. Both control alert frequency but work differently:
- **detection_filter** — a *post-match* rate filter. The rule must match the packet, and only after the match count exceeds the threshold within the time window does an alert fire. Example: `detection_filter:track by_src, count 20, seconds 5` — an alert fires only after the same source matches the rule 20+ times in 5 seconds.
- **threshold** — works similarly but is set as a separate `threshold` configuration or inline rule option. It has three types: `limit` (alert only N times per interval), `threshold` (alert every Nth match), `both` (alert once per interval after Nth match).

In SID 1000008 (port scan), `detection_filter` is used to suppress alerts for occasional SYN packets and only alert when the count signals a systematic scan.

---

**Q8. What is the `content` keyword and what modifiers can follow it?**

A8. The `content` keyword specifies a byte string to search for in the packet payload. Syntax: `content:"string"` or `content:"|hex bytes|"`.

Common modifiers (applied immediately after content):
- **nocase** — case-insensitive match.
- **depth:N** — search only the first N bytes.
- **offset:N** — start searching at byte N.
- **distance:N** — relative offset from the end of the previous match; sets search to begin N bytes after previous content match ended.
- **within:N** — the current content match must be found within N bytes of the previous match.
- **rawbytes** — search raw un-decoded bytes (bypass http_inspect normalization).

Example from SID 1000006: `content:"/bin/busybox"; content:"MIRAI"; distance:0; within:30;` — matches "/bin/busybox" then "MIRAI" within 30 bytes of it.

---

**Q9. What is the `pcre` keyword in Snort? Give an example from this lab.**

A9. `pcre` (Perl Compatible Regular Expression) allows complex pattern matching using PCRE syntax, for patterns that content keywords cannot express efficiently.

Syntax: `pcre:"/pattern/modifiers";`

Modifiers: `i` (case-insensitive), `s` (dot matches newline), `m` (multiline), `U` (match normalized URI), `P` (match normalized POST body).

From SID 1000007 in this lab:
```
pcre:"/\/(wget|tftp)\s+http/i";
```
This matches any occurrence of `/wget` or `/tftp` followed by whitespace and `http` (case-insensitive), detecting Mirai's download commands like `/bin/wget http://...` or `/usr/bin/tftp http://...`.

---

**Q10. What is the `classtype` keyword? List five common classtypes.**

A10. `classtype` assigns a category to an alert for prioritization and filtering in alert management tools. Each classtype maps to a priority (1=high, 2=medium, 3=low) defined in the `classification.config` file.

Common classtypes:
1. **attempted-recon** (priority 2) — Telnet/port scan reconnaissance.
2. **attempted-user** (priority 1) — login/credential brute force.
3. **policy-violation** (priority 2) — policy-violating command (e.g., loader).
4. **trojan-activity** (priority 1) — malware/botnet behaviour (Mirai loader).
5. **denial-of-service** (priority 2) — DoS/flood patterns (MQTT flood, port scan).

---

## Section B — IoT Security (Q11–Q20)

**Q11. What is Mirai? When was it first discovered and what damage did it cause?**

A11. Mirai is a self-propagating botnet malware that targets Linux-based IoT devices (IP cameras, routers, DVRs). It was first discovered in August 2016 by researcher MalwareMustDie and its source code was publicly released in September 2016 by its author (using the pseudonym "Anna-senpai"). In October 2016, Mirai was used to launch one of the largest DDoS attacks in history against Dyn DNS, causing major internet outages affecting Twitter, Reddit, Netflix, GitHub, and Amazon. At its peak, Mirai infected over 600,000 IoT devices. It was used in a 1.1 Tbps DDoS attack against OVH hosting and a 620 Gbps attack against security journalist Brian Krebs's website.

---

**Q12. How does Mirai propagate? Describe the full infection cycle.**

A12. Mirai uses a worm-like self-propagation mechanism:
1. **Random IP scanning:** The bot randomly generates public IPv4 addresses (excluding certain IP ranges like 10.x, 192.168.x, RFC 1918 private addresses) and attempts TCP connections to Telnet ports 23 and 2323.
2. **Credential brute-force:** If Telnet is open, Mirai cycles through a hardcoded table of 60+ default username/password pairs (root/xc3511, admin/admin, root/vizxv, etc.) common to IoT device vendors.
3. **Report to Loader:** When credentials succeed, the bot reports the victim IP, port, and credentials to a centralized Loader server.
4. **Payload delivery:** The Loader logs into the victim device via Telnet, determines its CPU architecture (MIPS, ARM, x86, etc.), and downloads the appropriate Mirai binary via `wget` or `tftp`, then executes it.
5. **C2 registration:** The newly infected device connects to the Command & Control (C2) server and awaits commands.
6. **DDoS execution:** On command, all bots simultaneously flood a target IP with UDP floods, TCP SYN floods, DNS amplification, NTP amplification, GRE floods, or HTTP floods.

---

**Q13. What are default credentials? Why are IoT devices vulnerable to default credential attacks?**

A13. Default credentials are the factory-preset username/password combinations embedded in device firmware by manufacturers. They are intended for initial setup but become a critical vulnerability when users fail to change them.

IoT devices are particularly vulnerable because:
- **No change enforcement:** Most IoT devices do not force password changes on first login.
- **Weak/no password policies:** Many devices have no minimum password strength requirement.
- **Telnet/SSH enabled by default:** Management interfaces are often exposed on the network by default.
- **Hardcoded credentials:** Some devices have credentials burned into firmware that cannot be changed.
- **Short product lifecycles:** Manufacturers prioritize time-to-market over security.
- **No OTA updates:** Many IoT devices never receive firmware security patches.

Mirai's hardcoded list includes credentials like `root:xc3511` (Xiongmai cameras), `root:vizxv` (various DVRs), `admin:admin`, `root:root`, `user:user`, and 60+ others covering a large fraction of deployed IoT devices.

---

**Q14. What ports does Mirai primarily target and why?**

A14. Mirai primarily targets:
- **Port 23 (Telnet):** The standard Telnet management port on network devices. Telnet transmits data in plaintext, making credential capture easy. Most IoT devices from low-cost manufacturers expose Telnet by default.
- **Port 2323 (Telnet alternate):** Used by some manufacturers as an alternate Telnet port, often added specifically to avoid default port security measures. Mirai scans both.
- **Port 80 (HTTP):** Web management interface for credential capture and further exploitation.
- **Port 7547 (TR-069):** Home router management protocol (not Mirai's primary vector, but used by variants).

Telnet is specifically targeted because it predates SSH, lacks encryption, is enabled by default on cheap IP cameras and DVRs, and allows easy remote command execution once credentials are obtained.

---

**Q15. What is a botnet? Distinguish between a botnet and a traditional DDoS attack.**

A15. A **botnet** is a network of internet-connected devices (bots or zombies) that have been compromised by malware and are under the control of a central operator (botmaster) via a Command & Control (C2) infrastructure.

| Feature | Botnet DDoS | Traditional DDoS |
|---------|-------------|-----------------|
| Origin | Thousands of compromised devices | Fewer, often rented servers |
| Source IPs | Distributed globally, real IPs | May use IP spoofing |
| Bandwidth | Can reach 1+ Tbps aggregate | Typically smaller |
| Attribution | Very difficult (innocent devices) | Easier to trace |
| Takedown | Requires botnet sinkholing | Block source IPs |
| Mitigation | Rate limiting, ISP cooperation | Blackhole routing |

---

**Q16. What security measures should IoT manufacturers and users implement to prevent Mirai-like attacks?**

A16.
**Manufacturers should:**
- Force unique passwords per device at factory (derived from hardware serial/MAC).
- Disable Telnet entirely; use SSH only with key-based authentication.
- Implement secure boot to prevent unauthorized firmware.
- Provide automatic OTA (Over-the-Air) security updates.
- Enable firewall rules by default to restrict management interfaces to LAN only.

**Users/administrators should:**
- Change default credentials immediately upon device setup.
- Disable Telnet and remote management ports when not needed.
- Segment IoT devices on a separate VLAN isolated from main network.
- Apply firmware updates regularly.
- Use network-level IDS/IPS (like Snort) to detect brute-force and scan activity.
- Monitor Telnet traffic with SIEM tools.

---

**Q17. What is MQTT? Why is it used in IoT and what are its security concerns?**

A17. MQTT (Message Queuing Telemetry Transport) is a lightweight publish-subscribe messaging protocol designed for constrained devices and low-bandwidth networks. It operates over TCP port 1883 (unencrypted) and 8883 (TLS encrypted). It was developed by IBM and standardized by OASIS.

**IoT use cases:** Smart home sensors, industrial control, remote telemetry, medical devices — any scenario where devices have limited processing power and need reliable message delivery with minimal overhead.

**Security concerns:**
- **No authentication by default:** MQTT v3.1 has optional username/password but no TLS mandate.
- **Plaintext credentials:** Username/password sent in MQTT CONNECT packet header unencrypted.
- **Broker enumeration:** Public MQTT brokers expose topic subscriptions to anyone.
- **CONNECT flooding (SID 1000009):** Attackers can flood the broker with CONNECT packets (starting with ``) causing denial of service.
- **Topic injection:** Malicious publishers can inject false sensor data.
- **No message integrity:** Without TLS, messages can be tampered in transit.

---

**Q18. What is network segmentation and how does it mitigate IoT botnet risks?**

A18. Network segmentation is the practice of dividing a network into isolated subnetworks (segments/VLANs) to control traffic flow between them using firewalls and ACLs.

For IoT botnet mitigation:
- IoT devices on a dedicated IoT VLAN cannot initiate connections to the internet directly (preventing C2 communication).
- If a device is compromised, the botnet cannot laterally move to corporate or personal devices on other VLANs.
- Outbound traffic from IoT VLAN can be limited to specific required services (e.g., cloud provider APIs) only.
- Telnet/SSH access to IoT devices can be restricted to only the management workstation IP.

In this lab, the virtual network `192.168.56.0/24` simulates a segmented lab environment where the Snort NIDS passively monitors all traffic at the virtual switch level.

---

**Q19. What is a Mirai C2 (Command & Control) server and how does it communicate with bots?**

A19. The C2 (Command and Control) server is the central infrastructure that the botmaster uses to issue commands to all infected bots. In Mirai's architecture:
- **Bot registration:** After infection, the bot connects to the C2 server on a hardcoded IP/domain over TCP, typically on port 48101 or similar.
- **Heartbeat:** Bots maintain a persistent TCP connection with keep-alive packets.
- **Command distribution:** The C2 sends attack commands specifying the target IP, attack vector (UDP flood, SYN flood, etc.), duration, and intensity.
- **Obfuscation:** Mirai uses XOR-encrypted strings in its binary and may use fast-flux DNS to hide C2 infrastructure.

Detection: Outbound connections from IoT devices to unknown external IPs on unusual ports, long-duration TCP sessions, and periodic small-packet heartbeat traffic are indicators of C2 communication.

---

**Q20. What is the difference between NIDS (passive) and NIPS (inline) mode? Which does this lab use?**

A20.
| Feature | NIDS (Passive) | NIPS (Inline) |
|---------|---------------|---------------|
| Placement | Passive tap / SPAN port | Inline between segments |
| Traffic flow | Traffic copy (not intercepted) | All traffic passes through |
| Response | Alert only; cannot block | Can drop/reject/modify packets |
| Latency | Near-zero (copy) | Adds processing latency |
| Failure mode | Silent (traffic unaffected) | Potential network outage |
| Use in lab | ✔ This lab (passive) | Not used |

This lab uses **NIDS passive mode**: Snort is connected to a virtual switch via a passive tap (promiscuous mode on the monitoring interface). It receives a copy of all traffic, analyzes it against `local.rules`, and generates alerts in `results/alert.ids` without interfering with actual traffic flow. This is realistic for a monitoring/detection-only deployment.

---

## Section C — Rule-Specific Questions (Q21–Q30)

**Q21. Explain SID 1000006 in detail. What attack does it detect?**

A21. SID 1000006 detects the **Mirai post-authentication loader command**:
```
alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323] (
    msg:"Mirai Post-Auth Loader Command /bin/busybox MIRAI";
    flow:to_server,established;
    content:"/bin/busybox"; nocase;
    content:"MIRAI"; nocase; distance:0; within:30;
    classtype:trojan-activity;
    sid:1000006; rev:1;)
```
After Mirai successfully brute-forces a Telnet login, it executes `/bin/busybox MIRAI` on the victim device. BusyBox is a lightweight Unix utility toolkit commonly found on embedded Linux systems. The "MIRAI" argument is used by the malware to test whether its custom BusyBox binary is already present and functional. The rule uses two sequential content matches: first `/bin/busybox`, then `MIRAI` within 30 bytes of that match (using `distance:0; within:30` to enforce proximity), requiring both strings to appear close together in the same TCP stream payload. The `flow:to_server,established` ensures the stream5 preprocessor has already tracked the session as established.

---

**Q22. What does `flow:to_server,established` mean? Why is it important?**

A22. The `flow` keyword uses the stream5 preprocessor's session state tracking:
- **`to_server`**: Match only on packets flowing from client to server (data sent by the initiating side of the TCP connection). This prevents the rule from matching server→client response packets.
- **`established`**: Match only after the TCP 3-way handshake is complete (SYN → SYN-ACK → ACK). This prevents the rule from firing on raw SYN packets before a session exists.

**Importance:**
1. **Performance:** Reduces rule evaluation to relevant packets only.
2. **Accuracy:** Content like `root` or `vizxv` could appear in many innocent contexts; restricting to established sessions to servers dramatically cuts false positives.
3. **Evasion resistance:** Without `established`, an attacker could send crafted SYN packets with rule-matching payload to trigger false alerts.
4. **Protocol fidelity:** Telnet credentials are always sent after session establishment, so `established` is the correct logical state.

---

**Q23. Explain the `detection_filter` in SID 1000008. Why is a threshold needed for port scan detection?**

A23. SID 1000008 targets TCP SYN port scanning:
```
detection_filter:track by_src, count 20, seconds 5;
```
This means: the rule first matches a TCP SYN packet (flags:S, targeting any port in the range 1–65535). But an alert is only generated once the **same source IP** matches this rule **20 or more times within 5 seconds**. The first 19 matches are silently tracked without alerting.

**Why threshold?** A single SYN packet to any port is completely normal (HTTP, DNS lookups all start with SYN). Alerting on every SYN packet would generate thousands of false positives per minute on any active network. A port scanner generates rapid SYN packets to many consecutive ports, producing 20+ matches in 5 seconds from one source. The detection_filter allows Snort to distinguish scanning behaviour from normal connection initiation statistically without needing complex state machines.

---

**Q24. What is `classtype:trojan-activity` and how does Snort prioritize it?**

A24. `classtype:trojan-activity` is a Snort alert classification defined in `classification.config` with priority **1** (highest severity). It indicates traffic that resembles known Trojan horse or malware behaviour.

Priority levels:
- **Priority 1 (High):** `trojan-activity`, `attempted-user`, `shellcode-detect`, `successful-admin`
- **Priority 2 (Medium):** `attempted-recon`, `denial-of-service`, `policy-violation`
- **Priority 3 (Low):** `not-suspicious`, `unknown`, `misc-activity`

Alert management tools (Snorby, BASE, Splunk) use these priorities to sort and colour-code the alert dashboard. Priority 1 alerts trigger immediate analyst attention and may integrate with SIEM for automatic incident creation. In this lab, SID 1000006 and 1000007 (loader commands) are classified as `trojan-activity` to flag them as the most critical phase of the Mirai infection chain.

---

**Q25. Why does SID 1000003 use `content:"root"; nocase; within:50;`? What is the risk of false positives?**

A25. SID 1000003 detects Mirai's brute-force username:
```
content:"root"; nocase; depth:50;
```
- **`nocase`:** Matches `root`, `ROOT`, `Root`, etc., covering obfuscated attempts.
- **`depth:50`:** Only searches within the first 50 bytes of the TCP payload. In a Telnet session, the first bytes sent by the client after connection are the username, so limiting depth speeds up matching and reduces false positives.

**False positive risk:** The string "root" appears in many legitimate contexts (file paths, documentation, HTML). The risk is mitigated by:
1. `flow:to_server,established` — only established Telnet sessions.
2. Destination port restricted to `[23,2323]` — Telnet ports only.
3. `depth:50` — only the initial payload.

However, an admin legitimately SSHing to a device and typing "root" in a terminal window would not trigger this rule because it's on port 22, not 23/2323.

---

**Q26. What is the purpose of the `metadata` keyword in Snort rules?**

A26. The `metadata` keyword stores additional information about a rule that is not used for packet matching but aids in alert management and rule management. Format: `metadata:key value, key value;`

Common metadata keys used in this lab:
- `service telnet` — identifies the application protocol.
- `affected_product IoT_Camera` — identifies the targeted product.
- `attack_target Server` — the type of system being targeted.
- `created_at YYYY_MM_DD` — rule creation date.
- `updated_at YYYY_MM_DD` — last update date.

Alert management systems (like Snorby, Kibana with Filebeat) can use metadata to filter, group, and correlate rules by service, affected product, or creation date, making large rulesets more manageable.

---

**Q27. What does `flags:S,12` mean in SID 1000008?**

A27. The `flags` keyword matches TCP control bits:
- `S` = SYN flag must be set.
- `,12` = flags mask — only examine bits `S` and `A` (the 12 represents the mask: `0x12` = `00010010` binary, but Snort uses a symbolic bitmask where `12` means "look at only these two flag bits").

Actually, `flags:S,12` in Snort 2.x syntax means: match packets where the **SYN flag is set** and evaluated against a mask of `12` (hex 0x12 = bits for SYN and ACK). This ensures we match SYN-only packets (pure SYN scan packets have SYN set, ACK clear) while ignoring other flag combinations. It correctly identifies TCP SYN scan packets (single SYN with no ACK = new connection attempt, not part of established handshake).

---

**Q28. What is the significance of `rev:1` in a Snort rule? When should it be incremented?**

A28. `rev` (revision number) tracks the version history of a rule with the same SID. All rules in this lab start at `rev:1` since they are original creations.

**When to increment:**
- When a rule's content, options, or logic is modified to fix a bug or improve detection.
- When a new attack variant requires rule adjustment.
- When performance tuning changes options (depth, offset, etc.).

**Importance:** When updating a ruleset, Snort compares SID + rev to determine which rules have changed. Alert management tools store (SID, rev) pairs and can track when a rule was last updated. Never reuse a SID with a different rev for a completely different attack — assign a new SID instead.

---

**Q29. How does the `content:"|10|"` in SID 1000009 work? What does the hex value represent?**

A29. In Snort, content bytes can be specified in hexadecimal using the pipe (`|`) delimiter: `content:"|10|"` matches the single byte `0x10` (decimal 16).

In the MQTT protocol, the **CONNECT** packet type has a fixed header where the first byte is the control packet type. The upper 4 bits represent the message type, and for CONNECT it is `0001` (1). The lower 4 bits are flags (0000 for CONNECT). Therefore the first byte of an MQTT CONNECT packet is `0x10` (00010000 binary).

SID 1000009 uses `content:"|10|"; depth:1;` to match any packet to port 1883 whose first byte is `0x10`, combined with `detection_filter:track by_src, count 30, seconds 10` to detect CONNECT flooding (30+ CONNECT packets from the same source in 10 seconds), indicating a denial-of-service attack against the MQTT broker.

---

**Q30. If you wanted to detect Mirai C2 heartbeat traffic, how would you write a Snort rule for it?**

A30. A hypothetical rule (not in this lab's local.rules) to detect Mirai C2 connections:
```
alert tcp $HOME_NET any -> $EXTERNAL_NET 48101 (
    msg:"Potential Mirai Bot C2 Heartbeat Connection";
    flow:to_server,established;
    dsize:<10;
    detection_filter:track by_src, count 5, seconds 60;
    metadata:service tcp, affected_product IoT_Device;
    classtype:trojan-activity;
    sid:1000011; rev:1;)
```
Key design choices:
- Destination port 48101 (Mirai's default C2 port in original source code).
- `dsize:<10` — C2 heartbeats are very small packets.
- `detection_filter` — requires 5 occurrences in 60 seconds to avoid false positives from legitimate small TCP packets.
- Outbound direction (`HOME_NET -> EXTERNAL_NET`) since infected bots initiate C2 connections.

In practice, Mirai C2 uses XOR-obfuscated traffic and varying ports, so detection often requires anomaly-based rules or threat intelligence IP feeds.

---

## Section D — TCP/IP Fundamentals (Q31–Q40)

**Q31. What are the six TCP control flags? Describe each.**

A31. TCP uses a 6-bit flags field (expanded to 9 bits in RFC 3168):
1. **URG (Urgent):** Indicates the Urgent Pointer field is significant; urgent data should be processed immediately by the receiver.
2. **ACK (Acknowledge):** Indicates the Acknowledgment Number field is valid; set in all packets except the initial SYN.
3. **PSH (Push):** Tells the receiver to push buffered data to the application immediately without waiting to fill the buffer.
4. **RST (Reset):** Resets the connection; used to refuse a connection or abort an existing one.
5. **SYN (Synchronize):** Set only during connection initiation; synchronizes sequence numbers between client and server.
6. **FIN (Finish):** Indicates the sender has finished sending data; initiates connection teardown.

Additional flags (RFC 3168): **ECE** (ECN-Echo) and **CWR** (Congestion Window Reduced) for Explicit Congestion Notification.

---

**Q32. Describe the TCP 3-way handshake step by step.**

A32. The TCP 3-way handshake establishes a reliable, bidirectional connection:

1. **SYN** (Client → Server): Client sends a segment with SYN flag set, ISN (Initial Sequence Number) = X, ACK = 0.
   `SYN, Seq=X`

2. **SYN-ACK** (Server → Client): Server acknowledges with SYN+ACK, its own ISN = Y, ACK = X+1.
   `SYN+ACK, Seq=Y, Ack=X+1`

3. **ACK** (Client → Server): Client acknowledges server's SYN, ACK = Y+1.
   `ACK, Seq=X+1, Ack=Y+1`

After step 3, the connection is **established** (stream5 marks it as such). Data transfer begins.

**Connection teardown** (4-way): FIN → ACK → FIN → ACK.

---

**Q33. What is a SYN scan (also called TCP half-open scan)? Why do attackers prefer it?**

A33. A SYN scan (or stealth scan) is a port scanning technique where the scanner:
1. Sends a TCP SYN packet to the target port.
2. If the port is **open**: target responds with SYN-ACK. The scanner then sends RST (not ACK) to abort before the connection completes. No application log entry is created.
3. If the port is **closed**: target responds with RST immediately.
4. If **filtered**: no response or ICMP unreachable.

**Why attackers prefer it:**
- **Stealth:** Since the full 3-way handshake never completes, the scan does not appear in many application-level logs (the connection was never "established").
- **Speed:** RST-abortion means no need to wait for connection teardown.
- **Accuracy:** Reliably distinguishes open/closed/filtered ports.

In this lab, Mirai uses SYN scans to discover open Telnet ports, detected by SID 1000001 and sfportscan (SID 1000008).

---

**Q34. What is the PCAP file format? What are its main header fields?**

A34. PCAP (Packet Capture) is a binary file format for storing captured network packets, used by tools like Wireshark, tcpdump, and Snort.

**Global header** (24 bytes):
| Field | Size | Description |
|-------|------|-------------|
| Magic number | 4 B | `0xA1B2C3D4` (little-endian) or `0xD4C3B2A1` (big-endian) — identifies byte order |
| Major version | 2 B | PCAP format major version (usually 2) |
| Minor version | 2 B | PCAP format minor version (usually 4) |
| Timezone offset | 4 B | GMT offset in seconds (usually 0) |
| Timestamp accuracy | 4 B | Accuracy of timestamps (usually 0) |
| Snap length | 4 B | Maximum packet length stored (e.g., 65535) |
| Link type | 4 B | Data link layer type (1 = Ethernet) |

**Per-packet header** (16 bytes): timestamp seconds, timestamp microseconds, captured length, original length. Followed by the raw packet bytes.

In this lab, `traffic_generator.py` writes PCAP files using Python's `struct` module to pack these headers in the correct binary format.

---

**Q35. What is RFC 1071 and how is it relevant to this lab?**

A35. RFC 1071 ("Computing the Internet Checksum") defines the algorithm for calculating the 16-bit ones-complement checksum used in IP, TCP, ICMP, and UDP headers.

**Algorithm:**
1. Arrange the data to be checksummed into 16-bit words.
2. Sum all 16-bit words using ones-complement addition (carry bits wrapped around).
3. Take the ones-complement (bitwise NOT) of the sum.
4. Store the result in the checksum field.

**Verification:** A receiver computes the checksum over the header+data including the checksum field. If the result is all 1s (0xFFFF), the data is intact.

**Lab relevance:** `traffic_generator.py` must compute correct IP and TCP checksums for the generated PCAP packets using this algorithm. Without correct checksums, Snort's stream5 preprocessor may reject or mis-classify packets, preventing rule matching. The pseudo-header technique (including source IP, destination IP, protocol, and segment length in the TCP checksum) is also implemented per RFC 793.

---

**Q36. What is the difference between TCP and UDP? When would IoT devices use each?**

A36.
| Feature | TCP | UDP |
|---------|-----|-----|
| Connection | Connection-oriented (3-way handshake) | Connectionless |
| Reliability | Guaranteed delivery, retransmission | Best-effort, no retransmission |
| Ordering | In-order delivery guaranteed | Packets may arrive out of order |
| Flow control | Yes (sliding window) | No |
| Error checking | Checksum + ACK-based | Checksum only |
| Overhead | Higher (headers, state) | Lower (8-byte header) |
| Use cases | Telnet, HTTP, SSH, FTP, MQTT | DNS, SNMP, NTP, CoAP, video streams |

**IoT use cases:**
- **TCP:** MQTT (reliability needed for sensor data delivery), Telnet/SSH (management), HTTP (REST APIs).
- **UDP:** CoAP (lightweight IoT protocol for constrained devices), DNS lookups, SSDP (device discovery), NTP (time sync), Mirai's DDoS flood attacks use UDP for maximum bandwidth consumption.

---

**Q37. What is ARP and how could an attacker abuse it in an IoT network?**

A37. ARP (Address Resolution Protocol) maps IPv4 addresses to MAC addresses on a local network segment. When a device wants to communicate with `192.168.56.10`, it broadcasts an ARP request ("Who has 192.168.56.10? Tell 192.168.56.5"), and the target replies with its MAC address.

**ARP spoofing/poisoning attack:**
An attacker sends gratuitous ARP replies claiming that their MAC address corresponds to a victim's IP (e.g., the router's IP). This poisons the ARP cache of other devices, redirecting their traffic through the attacker — a Man-in-the-Middle (MitM) position.

**IoT impact:**
- Intercept unencrypted MQTT traffic (plaintext sensor data, control commands).
- Intercept Telnet sessions to capture credentials.
- Inject malicious commands into IoT control channels.
- Redirect IoT devices' cloud API calls to attacker-controlled servers.

**Defence:** Dynamic ARP Inspection (DAI) on managed switches; static ARP entries for critical devices; use TLS for all IoT communications.

---

**Q38. What is the IP TTL field and how can it be used for OS fingerprinting?**

A38. The TTL (Time To Live) field in the IPv4 header is an 8-bit counter that prevents packets from looping indefinitely. Each router hop decrements TTL by 1; when TTL reaches 0, the packet is discarded and an ICMP Time Exceeded message is sent to the source.

**OS fingerprinting via TTL:**
Different operating systems use different default TTL values:
| OS | Default TTL |
|----|------------|
| Linux | 64 |
| Windows | 128 |
| Cisco IOS | 255 |
| FreeBSD/macOS | 64 |
| Embedded/IoT | 64 or 255 |

An attacker can estimate the OS by observing the TTL of received packets. If a packet arrives with TTL=118, the source likely started at 128 (Windows) and went through ~10 hops. IoT devices typically run embedded Linux (TTL=64).

Snort's `ttl` rule keyword can match specific TTL values for fingerprinting detection.

---

**Q39. Explain the concept of TCP session hijacking. How does Snort help detect it?**

A39. TCP session hijacking is an attack where an adversary takes over an established TCP session between two parties by injecting forged TCP segments with correct sequence and acknowledgment numbers.

**Attack steps:**
1. Attacker sniffs an established TCP session to learn the sequence numbers, source/dest IPs, and ports.
2. Attacker sends a forged TCP segment with the correct next expected sequence number, injecting malicious commands.
3. The server accepts the segment as legitimate since sequence numbers match.
4. The legitimate client's connection desynchronizes (RST or sequence mismatch).

**Snort detection:**
- Stream5 preprocessor detects sequence number anomalies: `stream5_global:detect_anomalies;`
- Alerts on: **TCP Overlap** (two packets claiming the same sequence space with different data), **Bad Segment** (sequence number outside window), **Session Established** but ACK doesn't match tracked state.
- Rules using `flow:established` combined with content matching can detect injected commands even mid-session.

---

**Q40. What is a VLAN and how is it used in this lab's virtual network setup?**

A40. VLAN (Virtual Local Area Network) is a logical network segmentation method implemented at Layer 2 (data link layer) using IEEE 802.1Q tagging. VLANs partition a single physical switch into multiple isolated broadcast domains without requiring separate physical hardware.

**In this lab (VirtualBox Host-Only Network):**
VirtualBox's host-only adapter (`vboxnet0` / `VirtualBox Host-Only Ethernet Adapter`) creates a virtual Layer 2 segment `192.168.56.0/24` that functions like a VLAN:
- All VMs attached to this adapter can communicate with each other and with the host.
- Traffic is completely isolated from the student's real internet connection (no internet access from this segment).
- The Snort VM can be configured in promiscuous mode to capture all inter-VM traffic at this virtual switch.

This provides a safe, isolated, fully controlled network environment for attack simulation without any risk of real-world traffic interference or legal issues.

---

## Section E — Project-Specific Questions (Q41–Q50)

**Q41. Why was a virtual lab environment chosen for this project instead of physical hardware?**

A41. A virtual lab (using VirtualBox or VMware) was chosen for several compelling reasons:
1. **Safety and ethics:** Attack simulations (Mirai scanning, brute-force, port scanning) cannot be conducted on real production networks or public internet without legal consequences. The virtual lab is completely isolated.
2. **Cost:** No physical hardware (IP cameras, routers, DVRs) required. All devices are simulated as PCAP traffic.
3. **Reproducibility:** The exact network topology can be re-created identically for demonstration, grading, or re-testing.
4. **Snapshot/rollback:** VM snapshots allow reverting to a clean state between experiments.
5. **Controlled traffic:** PCAP-based traffic generation ensures deterministic test cases — the exact same packets are replayed every time.
6. **Platform independence:** Works on any modern laptop/desktop without specialized network hardware.
7. **Academic appropriateness:** Ethical guidelines for university labs mandate no real attack traffic on real networks.

---

**Q42. How is attack traffic generated in this lab without actual malware?**

A42. Traffic is generated using `src/traffic_generator.py`, a pure Python script that writes synthetic PCAP files using Python's `struct` module to construct valid binary packet data:

1. **PCAP global header:** Written with correct magic number (`0xA1B2C3D4`), version (2.4), link type (1 = Ethernet).
2. **Ethernet frame:** 14-byte header with src/dst MAC addresses and EtherType 0x0800 (IPv4).
3. **IPv4 header:** 20-byte header with source/destination IP addresses, protocol (6=TCP, 17=UDP), TTL, and computed checksum (RFC 1071).
4. **TCP/UDP header:** 20-byte TCP header with source/dest ports, sequence/ack numbers, TCP flags (SYN, ACK, PSH+ACK), and computed checksum using TCP pseudo-header.
5. **Payload:** Realistic ASCII payloads mimicking Telnet sessions, MQTT CONNECT packets (``), Mirai commands (`/bin/busybox MIRAI`), wget commands.

The result is a valid binary PCAP file that Snort, Wireshark, and tcpdump can process identically to real network captures.

---

**Q43. What is alert_fast output format? Show an example alert line.**

A43. `alert_fast` is Snort's simplest alert output format — one line per alert, human-readable, written to a text file (configured as `../results/alert.ids` in this lab).

**Format:**
```
MM/DD-HH:MM:SS.ffffff  [**] [gid:sid:rev] msg [**] [Classification: classtype] [Priority: N] {proto} src_ip:src_port -> dst_ip:dst_port
```

**Example from this lab:**
```
11/16-09:30:01.123456  [**] [1:1000001:1] Mirai Telnet Connection Attempt to IoT Device [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.56.100:54321 -> 192.168.56.10:23
```

Fields explained:
- `11/16-09:30:01.123456` — timestamp (Month/Day-Hour:Min:Sec.microsec)
- `[1:1000001:1]` — Generator ID : SID : Rev
- `msg` — rule message
- `Classification` — derived from classtype in classification.config
- `Priority` — 1=High, 2=Medium, 3=Low
- `{TCP}` — protocol
- `192.168.56.100:54321 -> 192.168.56.10:23` — source:port → destination:port

---

**Q44. What is unified2 output format and how is it used with Barnyard2?**

A44. `unified2` is a binary alert and log format introduced in Snort 2.8 to replace the older unified format. It is significantly faster than text-based formats because binary writes are much faster than formatted text, reducing the performance impact on Snort's packet processing.

**Structure:** Each event is a binary record with a fixed-length header (record type + record length) followed by event data (timestamp, SID, priority, IP/port data) and optionally the raw packet bytes.

**Barnyard2** is a separate process that reads unified2 files asynchronously and feeds the data into databases (MySQL, PostgreSQL), SIEM systems, or sends it to Snorby (web UI) or Splunk. This decoupling means Snort never waits for database writes — it writes fast binary files and Barnyard2 handles the slow database insertion separately.

In this lab, `output unified2: filename snort.log, limit 128` in snort.conf enables this format.

---

**Q45. What is RFC 1918 and why do the lab IPs fall within it?**

A45. RFC 1918 ("Address Allocation for Private Internets") defines three IP address ranges reserved for private use — not routable on the public internet:
- `10.0.0.0/8` (10.0.0.0 – 10.255.255.255)
- `172.16.0.0/12` (172.16.0.0 – 172.31.255.255)
- `192.168.0.0/16` (192.168.0.0 – 192.168.255.255)

**Lab IPs:** The lab uses `192.168.56.0/24` — a subset of the `192.168.0.0/16` RFC 1918 block. VirtualBox specifically uses the `192.168.56.x` range for its default host-only network.

**Why RFC 1918 for the lab?**
- These addresses cannot be routed over the internet, so there is zero risk of accidentally sending attack traffic to real internet hosts.
- Routers with proper configuration drop RFC 1918 source addresses from internet-bound traffic (ingress filtering, BCP38).
- Mirai itself specifically **excludes** RFC 1918 ranges from its random scan targets — the lab simulates Mirai behaviour within a private network, which is academically representative while remaining completely contained.

---

**Q46. What is the purpose of src/alert_analyzer.py? How does it simulate Snort rule matching?**

A46. `alert_analyzer.py` is a pure Python rule matching engine that:

1. **Loads rules:** Parses `rules/local.rules` using regex to extract rule header (protocol, src/dst IP:port, direction) and options (content, pcre, flags, flow, detection_filter).
2. **Reads PCAPs:** Uses Python's `struct` module to parse PCAP binary format: global header, then per-packet headers and raw bytes.
3. **Decodes packets:** Extracts Ethernet (14 bytes), IP header (20 bytes), TCP/UDP header (20 bytes), and payload.
4. **Matches rules:** For each packet-rule pair, checks:
   - Protocol match (TCP/UDP/any).
   - IP address match against HOME_NET/EXTERNAL_NET definitions.
   - Port match (single port, list, range, any).
   - TCP flags match.
   - Content substring search (with nocase, depth, within, distance modifiers).
   - PCRE regex match.
   - detection_filter threshold tracking (per-src-IP counter with TTL).
5. **Generates alerts:** Writes alert records to `results/alert.ids` in alert_fast format.
6. **Reports metrics:** Returns detection rate, false positive rate, and per-SID counts.

---

**Q47. How does Snort handle IP fragmentation and why is this important against Mirai?**

A47. IP fragmentation occurs when a packet is larger than the network path's MTU (Maximum Transmission Unit, typically 1500 bytes for Ethernet). The sending host splits the IP datagram into multiple fragments, each with the same IP ID field. The receiving host reassembles them.

**Attack relevance:** Attackers can deliberately fragment packets so that no single fragment contains a complete content match for Snort rules. Without reassembly, `content:"root"` might be split across two fragments: fragment 1 ends with `roo`, fragment 2 starts with `t`.

**Snort's frag3 preprocessor:**
- Maintains a fragment reassembly buffer keyed by (src_IP, dst_IP, IP_ID).
- Reassembles fragments into the complete IP datagram before the detection engine sees it.
- Detects fragmentation evasion techniques: overlapping fragments, oversized fragments, teardrop attack patterns.
- Handles different OS reassembly policies (Linux, BSD, Windows) since they differ in handling overlapping fragments.

For Mirai Telnet traffic, frag3 ensures that even if Telnet payload is fragmented, Snort still matches the complete `/bin/busybox MIRAI` string in SID 1000006.

---

**Q48. What ethical considerations apply to this lab? What legal frameworks govern IDS research?**

A48. **Ethical considerations:**
1. **Isolation:** All attack traffic is confined to the `192.168.56.0/24` virtual network with no internet connectivity.
2. **No real victims:** All "targets" (IP camera, MQTT gateway) are simulated nodes — no real devices are harmed.
3. **Authorized testing:** The lab is conducted within an academic institution under course guidelines (CSL-I09).
4. **Educational purpose only:** Code and techniques must not be used outside the academic lab environment.
5. **Data minimization:** No real user data or real network traffic is captured.

**Relevant legal frameworks (India):**
- **IT Act 2000, Section 66:** Unauthorized access to computer systems is punishable by up to 3 years imprisonment and/or fine.
- **IT Act 2000, Section 66F:** Cyber terrorism (using computer systems to threaten security) carries life imprisonment.
- **IPC Section 379/426:** Criminal mischief/theft via computer systems.

**International:**
- **CFAA (USA):** Computer Fraud and Abuse Act.
- **Computer Misuse Act 1990 (UK):** Unauthorized access offences.

This lab complies with all applicable regulations as it operates exclusively within an isolated academic environment.

---

**Q49. What is Snorby and how would you use it with this lab's output?**

A49. Snorby is a modern, web-based front-end for Snort alerts built with Ruby on Rails. It provides a graphical dashboard for viewing, searching, and managing Snort alerts stored in a database.

**Integration with this lab:**
1. Configure Snort to output in `unified2` format (already in `snort.conf`).
2. Run **Barnyard2** to read unified2 files and insert records into a MySQL database.
3. Snorby connects to this MySQL database and provides:
   - Real-time alert dashboard with priority-based colouring.
   - Alert classification and severity distribution charts.
   - IP-based alert grouping (top attacking IPs).
   - Rule-based alert filtering (by SID, classtype, priority).
   - Alert acknowledgment and case management workflow.
   - Report generation (PDF/CSV export).

**Alternative tools:** BASE (Basic Analysis and Security Engine), Kibana+Elasticsearch (ELK stack with Filebeat for Snort logs), Splunk with Snort TA.

For this lab, `alert_analyzer.py` generates the equivalent output directly in Python, simulating what Snorby would display.

---

**Q50. How would you extend this lab to detect Mirai variant (Satori, Qbot, Mozi) attacks?**

A50. To extend detection for Mirai variants:

**Satori (targets port 37215/52869 — Huawei RCE):**
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 37215 (
    msg:"Satori IoT Botnet Huawei RCE Attempt";
    content:"POST"; http_method;
    content:"/ctrlt/DeviceUpgrade_1"; http_uri;
    content:"busybox"; nocase;
    classtype:trojan-activity; sid:1000011; rev:1;)
```

**Qbot/Mirai variant (uses SSH brute-force on port 22):**
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"IoT Botnet SSH Brute-Force Attempt";
    flow:to_server,established;
    detection_filter:track by_src, count 10, seconds 30;
    classtype:attempted-user; sid:1000012; rev:1;)
```

**Mozi (DHT-based P2P C2 on UDP 6881):**
```snort
alert udp $HOME_NET any -> $EXTERNAL_NET 6881 (
    msg:"Mozi IoT Botnet DHT P2P C2 Communication";
    content:"Mozi"; nocase;
    classtype:trojan-activity; sid:1000013; rev:1;)
```

**General extensions:**
- Add rules for HTTP exploit payloads targeting router admin panels (port 80/8080).
- Monitor DNS for DGA (Domain Generation Algorithm) patterns using Snort's dns preprocessor.
- Integrate threat intelligence IP feeds using Snort's reputation preprocessor.
- Add IPv6 equivalents of all existing rules.
- Deploy Suricata (Snort-compatible, multi-threaded) for high-speed environments.

---

*End of Viva Preparation Document — CSL-I09*
*Kushal Kumar | 23ESKCY026 | SKIT Jaipur | CSE-IoT VII Sem | 2026-27*

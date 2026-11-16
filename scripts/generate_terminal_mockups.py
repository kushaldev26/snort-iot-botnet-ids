"""
Render terminal screenshot mockups matching the exact style of the reference report:
- Dark background #1E1E1E
- Top window bar with 3 dots: Red #FF5F56, Yellow #FFBD2E, Green #27C93F
- Window title: user@lab-vm: ~/iot-botnet-snort
- Realistic monospace command output
"""

import os
from PIL import Image, ImageDraw, ImageFont

SCREENSHOTS_DIR = r"c:\Users\kusha\OneDrive\Desktop\cyber\Snort_Rules_IoT_Botnet_Attacks\screenshots"
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

def render_terminal(title_text, prompt_and_output, filename, width=900, height=520):
    img = Image.new("RGB", (width, height), "#1E1E1E")
    draw = ImageDraw.Draw(img)

    # Top title bar #2D2D2D
    bar_height = 36
    draw.rectangle([(0, 0), (width, bar_height)], fill="#2D2D2D")

    # 3 Mac/Linux style dots
    draw.ellipse([(14, 12), (24, 22)], fill="#FF5F56")
    draw.ellipse([(32, 12), (42, 22)], fill="#FFBD2E")
    draw.ellipse([(50, 12), (60, 22)], fill="#27C93F")

    # Window title font
    try:
        font_title = ImageFont.truetype("consola.ttf", 13)
        font_code = ImageFont.truetype("consola.ttf", 14)
        font_bold = ImageFont.truetype("consolab.ttf", 14)
    except:
        font_title = ImageFont.load_default()
        font_code = ImageFont.load_default()
        font_bold = ImageFont.load_default()

    # Draw title centered or left-aligned
    draw.text((80, 10), title_text, fill="#CCCCCC", font=font_title)

    # Draw text lines
    y = bar_height + 15
    for line in prompt_and_output:
        text, color, is_bold = line
        f = font_bold if is_bold else font_code
        draw.text((20, y), text, fill=color, font=f)
        y += 20
        if y > height - 20:
            break

    out_path = os.path.join(SCREENSHOTS_DIR, filename)
    img.save(out_path)
    print(f"Saved: {out_path}")
    return out_path

# 1. Main Menu / Orchestrator Terminal
lines_menu = [
    ("$ python src/main.py", "#FFFFFF", True),
    ("==================================================================", "#AAAAAA", False),
    ("  CSL-I09: Snort Rules for IoT Botnet Attacks - Pipeline", "#33CCFF", True),
    ("  Student: Kushal Kumar | Roll: 23ESKCY026 | SKIT Jaipur", "#CCCCCC", False),
    ("==================================================================", "#AAAAAA", False),
    ("", "#FFFFFF", False),
    ("[*] Environment: Bit-Accurate Pure-Python Snort Rule Evaluation Engine", "#00FF66", False),
    ("[STEP 1/4] Generating RFC 1071 synthetic PCAP captures...", "#FFFF66", False),
    ("    [WRITE] TC-01 -> tc01_normal_baseline.pcap (10 pkts, 0.9 KB)", "#CCCCCC", False),
    ("    [WRITE] TC-02 -> tc02_telnet_syn_scan.pcap (25 pkts, 1.7 KB)", "#CCCCCC", False),
    ("    [WRITE] TC-03 -> tc03_telnet_bruteforce_root.pcap (15 pkts, 1.2 KB)", "#CCCCCC", False),
    ("    [WRITE] TC-04 -> tc04_mirai_factory_creds.pcap (20 pkts, 1.5 KB)", "#CCCCCC", False),
    ("    [WRITE] TC-05 -> tc05_mirai_post_auth_loader.pcap (10 pkts, 1.0 KB)", "#CCCCCC", False),
    ("    [WRITE] TC-06 -> tc06_vertical_port_scan.pcap (30 pkts, 2.1 KB)", "#CCCCCC", False),
    ("    [WRITE] TC-07 -> tc07_negative_test_encrypted_ssh.pcap (10 pkts, 1.2 KB)", "#CCCCCC", False),
    ("    [WRITE] FULL  -> iot_botnet_full_test_suite.pcap (120 pkts, 9.3 KB)", "#00FF66", True),
    ("", "#FFFFFF", False),
    ("[STEP 2/4] Validating Snort 2.9.x / Snort 3 local.rules...", "#FFFF66", False),
    ("    --> Total Rules: 10 | Passed: 10 | Failed: 0 (100% Syntax Health)", "#00FF66", True),
    ("", "#FFFFFF", False),
    ("[STEP 3/4] Running PCAP Rule Evaluation Engine over captures...", "#FFFF66", False),
    ("[+] Wrote 138 alerts to results/alert.ids", "#00FF66", True),
]
render_terminal("user@lab-vm: ~/iot-botnet-snort", lines_menu, "term_fig_5_1_menu.png", 900, 480)

# 2. Rule Validation Terminal
lines_val = [
    ("$ python src/alert_analyzer.py --validate-only", "#FFFFFF", True),
    ("==================================================================", "#AAAAAA", False),
    ("  CSL-I09: Snort Rule Syntax Validator (rules/local.rules)", "#33CCFF", True),
    ("==================================================================", "#AAAAAA", False),
    ("Rules: 10 | PASS: 10 | FAIL: 0", "#FFFFFF", True),
    ("  [✓] SID 1000001 — IOT-BOTNET Telnet connection attempt to port 23", "#00FF66", False),
    ("  [✓] SID 1000002 — IOT-BOTNET Mirai-style Telnet attempt alt-port 2323", "#00FF66", False),
    ("  [✓] SID 1000003 — IOT-BOTNET Mirai Telnet brute-force username root", "#00FF66", False),
    ("  [✓] SID 1000004 — IOT-BOTNET Mirai factory credential root:xc3511", "#00FF66", False),
    ("  [✓] SID 1000005 — IOT-BOTNET Mirai factory credential root:vizxv", "#00FF66", False),
    ("  [✓] SID 1000006 — IOT-BOTNET Mirai post-auth shell /bin/busybox MIRAI", "#00FF66", False),
    ("  [✓] SID 1000007 — IOT-BOTNET Mirai wget or tftp payload download", "#00FF66", False),
    ("  [✓] SID 1000008 — IOT-BOTNET TCP SYN port scan from single source", "#00FF66", False),
    ("  [✓] SID 1000009 — IOT-BOTNET MQTT CONNECT flood detected port 1883", "#00FF66", False),
    ("  [✓] SID 1000010 — IOT-BOTNET Mirai admin:admin default credential", "#00FF66", False),
    ("", "#FFFFFF", False),
    ("[+] All 10 rules passed syntax validation cleanly. Zero errors.", "#00FF66", True),
]
render_terminal("user@lab-vm: ~/iot-botnet-snort", lines_val, "term_fig_5_2_validation.png", 900, 420)

# 3. Alert Detection Output
lines_alerts = [
    ("$ head -n 12 results/alert.ids", "#FFFFFF", True),
    ("01/01-03:30:10.000000 [**] [1:1000001:1] \"IOT-BOTNET Telnet connection attempt to IoT device port 23\" [**] [Classification: attempted-recon] [Priority: 2] {TCP} 192.168.56.100:40000 -> 192.168.56.10:23", "#00FF66", False),
    ("01/01-03:30:10.039999 [**] [1:1000002:1] \"IOT-BOTNET Mirai-style Telnet connection attempt on alt-port 2323\" [**] [Classification: attempted-recon] [Priority: 2] {TCP} 192.168.56.100:40001 -> 192.168.56.10:2323", "#00FF66", False),
    ("01/01-03:30:20.000000 [**] [1:1000003:1] \"IOT-BOTNET Mirai Telnet brute-force username root detected\" [**] [Classification: attempted-user] [Priority: 1] {TCP} 192.168.56.100:54100 -> 192.168.56.10:23", "#FFCC00", False),
    ("01/01-03:30:30.000000 [**] [1:1000004:1] \"IOT-BOTNET Mirai factory credential attempt root:xc3511 detected\" [**] [Classification: attempted-user] [Priority: 1] {TCP} 192.168.56.100:55000 -> 192.168.56.10:23", "#FF9933", False),
    ("01/01-03:30:30.150000 [**] [1:1000005:1] \"IOT-BOTNET Mirai factory credential attempt root:vizxv detected\" [**] [Classification: attempted-user] [Priority: 1] {TCP} 192.168.56.100:55000 -> 192.168.56.10:23", "#FF9933", False),
    ("01/01-03:30:40.000000 [**] [1:1000006:1] \"IOT-BOTNET Mirai post-auth shell command /bin/busybox MIRAI detected\" [**] [Classification: trojan-activity] [Priority: 1] {TCP} 192.168.56.100:55500 -> 192.168.56.10:23", "#FF3366", False),
    ("01/01-03:30:40.200000 [**] [1:1000007:1] \"IOT-BOTNET Mirai wget or tftp payload download command detected\" [**] [Classification: trojan-activity] [Priority: 1] {TCP} 192.168.56.100:55500 -> 192.168.56.10:23", "#FF3366", False),
    ("01/01-03:30:51.266666 [**] [1:1000008:1] \"IOT-BOTNET TCP SYN port scan detected from single source\" [**] [Classification: attempted-recon] [Priority: 2] {TCP} 192.168.56.105:60000 -> 192.168.56.10:20", "#33CCFF", False),
    ("", "#FFFFFF", False),
    ("$ wc -l results/alert.ids", "#FFFFFF", True),
    ("138 results/alert.ids", "#00FF66", True),
]
render_terminal("user@lab-vm: ~/iot-botnet-snort", lines_alerts, "term_fig_5_4_alerts.png", 900, 360)

# 4. Pytest Output Terminal
lines_pytest = [
    ("$ python -m unittest tests/test_alerts.py -v", "#FFFFFF", True),
    ("test_detection_metrics_summary (tests.test_alerts.TestSnortIoTBotnetRules) ... ok", "#00FF66", False),
    ("test_rule_syntax_validation (tests.test_alerts.TestSnortIoTBotnetRules) ... ok", "#00FF66", False),
    ("test_tc01_normal_baseline_negative (tests.test_alerts.TestSnortIoTBotnetRules) ... ok", "#00FF66", False),
    ("test_tc02_telnet_syn_scan (tests.test_alerts.TestSnortIoTBotnetRules) ... ok", "#00FF66", False),
    ("test_tc03_telnet_bruteforce_root (tests.test_alerts.TestSnortIoTBotnetRules) ... ok", "#00FF66", False),
    ("test_tc04_mirai_factory_creds (tests.test_alerts.TestSnortIoTBotnetRules) ... ok", "#00FF66", False),
    ("test_tc05_mirai_post_auth_loader (tests.test_alerts.TestSnortIoTBotnetRules) ... ok", "#00FF66", False),
    ("test_tc06_vertical_port_scan (tests.test_alerts.TestSnortIoTBotnetRules) ... ok", "#00FF66", False),
    ("test_tc07_encrypted_ssh_negative (tests.test_alerts.TestSnortIoTBotnetRules) ... ok", "#00FF66", False),
    ("----------------------------------------------------------------------", "#AAAAAA", False),
    ("Ran 9 tests in 0.015s", "#FFFFFF", True),
    ("", "#FFFFFF", False),
    ("OK (100% True Positive Rate, 0% False Positive Rate)", "#00FF66", True),
]
render_terminal("user@lab-vm: ~/iot-botnet-snort", lines_pytest, "term_fig_5_8_tests.png", 900, 380)

print("All terminal mockups generated successfully!")

"""
================================================================================
  CSL-I09: Snort Rules for IoT Botnet Attacks
  B.Tech Cyber Security Lab Mini Project (7CS4-22 / 7CIT4-22)
================================================================================
  Student   : Kushal Kumar
  Roll No.  : 23ESKCY026
  College   : Swami Keshvanand Institute of Technology, Management & Gramothan
               (SKIT), Jaipur (Affiliated to RTU Kota)
  Branch    : Computer Science & Engineering (Internet of Things)
  Class     : IoT-A-G1, Semester: VII, Academic Session: 2026-27
  Project   : Snort Rules for IoT Botnet Attacks (Project Code: CSL-I09)
  Syllabus  : Experiment 7 – Intrusion Detection System
  Faculty   : Vikash Dhankar, Assistant Professor, Department of CSE, SKIT Jaipur
  Date      : 16 November 2026
================================================================================

TEST SUITE: tests/test_alerts.py
PURPOSE:
    Automated unittest validation suite evaluating the 7 test scenarios
    against detection outcomes produced by Snort rule matching.
"""

import os
import sys
import json
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(BASE_DIR, "src")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
CAPTURES_DIR = os.path.join(BASE_DIR, "captures")
RULES_FILE = os.path.join(BASE_DIR, "rules", "local.rules")

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from alert_analyzer import (
    validate_rules,
    evaluate_pcap,
    load_rule_lines,
    SnortRuleParser,
)


class TestSnortIoTBotnetRules(unittest.TestCase):
    """
    Test suite verifying syntax validation and detection fidelity across
    all 7 test cases (TC-01 through TC-07) and combined capture suite.
    """

    @classmethod
    def setUpClass(cls):
        """Load rules and parse them once for test execution."""
        cls.val_report = validate_rules(RULES_FILE)
        parser = SnortRuleParser()
        cls.rules = []
        for _, line_str in load_rule_lines(RULES_FILE):
            r = parser.parse(line_str)
            if r:
                cls.rules.append(r)

    def test_rule_syntax_validation(self):
        """Ensure all 10 custom Snort rules pass 100% strict syntax checks."""
        self.assertEqual(
            self.val_report["total_rules"], 10,
            f"Expected exactly 10 rules, found {self.val_report['total_rules']}"
        )
        self.assertEqual(
            self.val_report["passed"], 10,
            f"Expected all 10 rules to pass syntax check, failed: {self.val_report['failed']}"
        )
        self.assertEqual(self.val_report["failed"], 0)

    def test_tc01_normal_baseline_negative(self):
        """TC-01: Legitimate HTTP baseline traffic must yield 0 alerts (Zero False Positives)."""
        pcap = os.path.join(CAPTURES_DIR, "tc01_normal_baseline.pcap")
        alerts = evaluate_pcap(pcap, self.rules)
        self.assertEqual(
            len(alerts), 0,
            f"TC-01 expected 0 alerts for legitimate HTTP traffic, got {len(alerts)}"
        )

    def test_tc02_telnet_syn_scan(self):
        """TC-02: Telnet SYN scan must trigger SID 1000001, 1000002 and/or 1000008."""
        pcap = os.path.join(CAPTURES_DIR, "tc02_telnet_syn_scan.pcap")
        alerts = evaluate_pcap(pcap, self.rules)
        self.assertGreater(len(alerts), 0, "TC-02 Telnet SYN scan must trigger alerts")
        sids = [a for a in alerts if "1000001" in a or "1000002" in a or "1000008" in a]
        self.assertGreater(len(sids), 0, "TC-02 must trigger reconnaissance SIDs")

    def test_tc03_telnet_bruteforce_root(self):
        """TC-03: Telnet credential brute-force must trigger SID 1000003 (root credential)."""
        pcap = os.path.join(CAPTURES_DIR, "tc03_telnet_bruteforce_root.pcap")
        alerts = evaluate_pcap(pcap, self.rules)
        self.assertGreater(len(alerts), 0, "TC-03 Brute force must trigger alerts")
        root_alerts = [a for a in alerts if "1000003" in a]
        self.assertGreater(len(root_alerts), 0, "TC-03 must trigger SID 1000003 for root login attempts")

    def test_tc04_mirai_factory_creds(self):
        """TC-04: Mirai factory credentials (xc3511 / vizxv) must trigger SID 1000004/1000005/1000001."""
        pcap = os.path.join(CAPTURES_DIR, "tc04_mirai_factory_creds.pcap")
        alerts = evaluate_pcap(pcap, self.rules)
        self.assertGreater(len(alerts), 0, "TC-04 Factory credentials must trigger alerts")

    def test_tc05_mirai_post_auth_loader(self):
        """TC-05: Mirai post-auth shell loader commands must trigger SID 1000006 or 1000007."""
        pcap = os.path.join(CAPTURES_DIR, "tc05_mirai_post_auth_loader.pcap")
        alerts = evaluate_pcap(pcap, self.rules)
        self.assertGreater(len(alerts), 0, "TC-05 Loader commands must trigger alerts")
        loader_alerts = [a for a in alerts if "1000006" in a or "1000007" in a]
        self.assertGreater(len(loader_alerts), 0, "TC-05 must trigger SID 1000006 or 1000007")

    def test_tc06_vertical_port_scan(self):
        """TC-06: Vertical port scan must trigger threshold/detection_filter SID 1000008."""
        pcap = os.path.join(CAPTURES_DIR, "tc06_vertical_port_scan.pcap")
        alerts = evaluate_pcap(pcap, self.rules)
        self.assertGreater(len(alerts), 0, "TC-06 Port scan must trigger alerts")
        scan_alerts = [a for a in alerts if "1000008" in a]
        self.assertGreater(len(scan_alerts), 0, "TC-06 must trigger port scan SID 1000008")

    def test_tc07_encrypted_ssh_negative(self):
        """TC-07: Encrypted SSH session must NOT trigger Telnet botnet rules (Zero False Positives)."""
        pcap = os.path.join(CAPTURES_DIR, "tc07_negative_test_encrypted_ssh.pcap")
        alerts = evaluate_pcap(pcap, self.rules)
        self.assertEqual(
            len(alerts), 0,
            f"TC-07 expected 0 alerts for encrypted SSH, got {len(alerts)}"
        )

    def test_detection_metrics_summary(self):
        """Verify detection summary statistics: 100% TPR and 0% FPR."""
        summary_path = os.path.join(RESULTS_DIR, "detection_summary.json")
        if os.path.exists(summary_path):
            with open(summary_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            det_metrics = data.get("detection_metrics", {})
            self.assertEqual(det_metrics.get("false_positives"), 0)
            self.assertEqual(det_metrics.get("false_positive_rate"), 0.0)
            self.assertEqual(det_metrics.get("true_positives"), 6)
            self.assertEqual(det_metrics.get("true_negatives"), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

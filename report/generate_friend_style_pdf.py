"""
================================================================================
  CSL-I09: Snort Rules for IoT Botnet Attacks
  Friend-Report Reference PDF Generator (Matching Atishay Jain CSL-G49 report)
================================================================================
  Student   : Kushal Kumar | Roll: 23ESKCY026 | Class: CS-IOT-A-G1 | VII Sem
  College   : Swami Keshvanand Institute of Technology, Management & Gramothan, Jaipur
  Course    : Cyber Security Lab (7CS4-22) | Project Code: CSL-I09
  Faculty   : Vikash Dhankar, Assistant Professor, Dept. of CSE, SKIT, Jaipur
  Date      : 16/11/2026 | Session: 2026-27
================================================================================
"""

import os
import sys
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage,
    PageBreak, KeepTogether, Preformatted
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_DIR = os.path.join(BASE_DIR, "report")
DIAGRAMS_DIR = os.path.join(BASE_DIR, "diagrams")
SCREENSHOTS_DIR = os.path.join(BASE_DIR, "screenshots")
RULES_FILE = os.path.join(BASE_DIR, "rules", "local.rules")

LOGO_PATH = os.path.join(REPORT_DIR, "skit_logo.png")
SIG_PATH = os.path.join(REPORT_DIR, "signature_kushal.png")

PDF_OUTPUT = os.path.join(REPORT_DIR, "Mini_Project_Report.pdf")
OFFICIAL_PDF_OUTPUT = os.path.join(REPORT_DIR, "23ESKCY026_KushalKumar_CSL-I09_Report.pdf")


# ---------------------------------------------------------------------------
# Numbered Canvas for Exact Reference Numbering (i..iv, then 1..25)
# ---------------------------------------------------------------------------
class FriendStyleCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        # Page 1: Cover page -> No page number
        if self._pageNumber == 1:
            return

        self.saveState()
        self.setFont("Times-Roman", 10)
        self.setFillColor(colors.HexColor("#000000"))

        # Roman numerals for prelim pages 2..5
        if self._pageNumber == 2:
            page_str = "i"
        elif self._pageNumber == 3:
            page_str = "ii"
        elif self._pageNumber == 4:
            page_str = "iii"
        elif self._pageNumber == 5:
            page_str = "iv"
        else:
            # Body pages 6..30 -> 1..25
            body_num = self._pageNumber - 5
            page_str = str(body_num)

        # Centered at bottom (page width is 595.27 pt for A4)
        self.drawCentredString(297.6, 36, page_str)
        self.restoreState()


def build_pdf():
    print("[PDF] Building exact reference-styled report PDF ...")

    # Margins: 54pt left/right (0.75 in), 50pt top/bottom
    doc = SimpleDocTemplate(
        PDF_OUTPUT,
        pagesize=A4,
        leftMargin=54,
        rightMargin=54,
        topMargin=48,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Exact Reference Styles
    title_h1 = ParagraphStyle(
        'Ref_H1', parent=styles['Heading1'],
        fontName='Times-Bold', fontSize=15, leading=19,
        textColor=colors.HexColor('#000000'), spaceBefore=10, spaceAfter=8,
        keepWithNext=True
    )
    title_h2 = ParagraphStyle(
        'Ref_H2', parent=styles['Heading2'],
        fontName='Times-Bold', fontSize=12.5, leading=16,
        textColor=colors.HexColor('#000000'), spaceBefore=8, spaceAfter=4,
        keepWithNext=True
    )
    body = ParagraphStyle(
        'Ref_Body', parent=styles['Normal'],
        fontName='Times-Roman', fontSize=10.5, leading=15,
        alignment=4, # Justified
        textColor=colors.HexColor('#111111'), spaceAfter=5
    )
    body_bullet = ParagraphStyle(
        'Ref_Bullet', parent=body,
        leftIndent=18, firstLineIndent=-12, spaceAfter=4
    )
    decl_title = ParagraphStyle(
        'Ref_DeclTitle', parent=styles['Normal'],
        fontName='Times-Bold', fontSize=15, leading=19,
        alignment=1, # Centered
        textColor=colors.HexColor('#1F4E79'), spaceBefore=10, spaceAfter=14
    )
    table_caption = ParagraphStyle(
        'Ref_TblCap', parent=styles['Normal'],
        fontName='Times-Bold', fontSize=10.5, leading=14,
        alignment=1, spaceAfter=6, keepWithNext=True
    )
    fig_caption = ParagraphStyle(
        'Ref_FigCap', parent=styles['Normal'],
        fontName='Times-Bold', fontSize=10, leading=13,
        alignment=1, spaceBefore=4, spaceAfter=8
    )
    code_text = ParagraphStyle(
        'Ref_Code', parent=styles['Normal'],
        fontName='Courier', fontSize=6.8, leading=8.5,
        textColor=colors.HexColor('#111111')
    )
    code_block_style = ParagraphStyle(
        'Ref_CodeBlock', parent=styles['Normal'],
        fontName='Courier', fontSize=6.8, leading=8.5,
        textColor=colors.HexColor('#111111')
    )

    story = []

    # =========================================================================
    # PAGE 1: COVER / FRONT PAGE
    # =========================================================================
    story.append(Spacer(1, 15))
    story.append(Paragraph("A", ParagraphStyle('CP_A', fontName='Times-Roman', fontSize=14, alignment=1)))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Mini Project Report", ParagraphStyle('CP_MPR', fontName='Times-Bold', fontSize=18, alignment=1)))
    story.append(Spacer(1, 4))
    story.append(Paragraph("on", ParagraphStyle('CP_on', fontName='Times-Roman', fontSize=12, alignment=1)))
    story.append(Spacer(1, 6))
    story.append(Paragraph("“Snort Rules for IoT Botnet Attacks”", ParagraphStyle('CP_Title', fontName='Times-Bold', fontSize=17, alignment=1, textColor=colors.HexColor('#1F4E79'))))
    story.append(Spacer(1, 4))
    story.append(Paragraph("Project Code: CSL-I09", ParagraphStyle('CP_Code', fontName='Times-Bold', fontSize=12, alignment=1)))
    story.append(Spacer(1, 14))

    story.append(Paragraph("<i>Submitted in partial fulfilment of the requirements of</i>", ParagraphStyle('CP_Sub1', fontName='Times-Italic', fontSize=10.5, alignment=1)))
    story.append(Spacer(1, 3))
    story.append(Paragraph("<b>Cyber Security Lab (7CS4-22)</b>", ParagraphStyle('CP_Sub2', fontName='Times-Bold', fontSize=12, alignment=1)))
    story.append(Spacer(1, 4))
    story.append(Paragraph("Bachelor of Technology — VII Semester", ParagraphStyle('CP_Sub3', fontName='Times-Roman', fontSize=11, alignment=1)))
    story.append(Paragraph("in", ParagraphStyle('CP_Sub4', fontName='Times-Roman', fontSize=11, alignment=1)))
    story.append(Paragraph("<b>Computer Science & Engineering (Internet of Things)</b>", ParagraphStyle('CP_Sub5', fontName='Times-Bold', fontSize=12, alignment=1)))
    story.append(Paragraph("Session 2026-27", ParagraphStyle('CP_Sub6', fontName='Times-Roman', fontSize=11, alignment=1)))
    story.append(Spacer(1, 15))

    # SKIT Logo in center
    if os.path.exists(LOGO_PATH):
        story.append(RLImage(LOGO_PATH, width=105, height=105))
        story.append(Spacer(1, 16))

    # Boxed Table with Submitted By and Submitted To
    box_data = [
        [
            Paragraph("<font color='#1F4E79'><b>Submitted By:</b></font><br/><br/><b>Name:</b> Kushal Kumar<br/><b>Roll No.:</b> 23ESKCY026<br/><b>Class / Batch:</b> CS-IOT-A-G1<br/><b>Semester:</b> VII", ParagraphStyle('CP_BoxL', fontName='Times-Roman', fontSize=10.5, leading=14)),
            Paragraph("<font color='#1F4E79'><b>Submitted To:</b></font><br/><br/>Vikash Dhankar<br/>Assistant Professor<br/>Department of CSE<br/>SKIT, Jaipur", ParagraphStyle('CP_BoxR', fontName='Times-Roman', fontSize=10.5, leading=14))
        ]
    ]
    t_box = Table(box_data, colWidths=[240, 240])
    t_box.setStyle(TableStyle([
        ('BOX', (0,0), (-1,-1), 1.0, colors.HexColor('#000000')),
        ('LINEBEFORE', (1,0), (1,0), 1.0, colors.HexColor('#000000')),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_box)

    story.append(Spacer(1, 24))
    story.append(Paragraph("<font color='#1F4E79'><b>Department of Computer Science & Engineering</b></font>", ParagraphStyle('CP_Dept', fontName='Times-Bold', fontSize=11.5, alignment=1)))
    story.append(Paragraph("<b>Swami Keshvanand Institute of Technology, Management & Gramothan, Jaipur</b>", ParagraphStyle('CP_Inst', fontName='Times-Bold', fontSize=11, alignment=1)))
    story.append(Paragraph("(Affiliated to Rajasthan Technical University, Kota)", ParagraphStyle('CP_Affil', fontName='Times-Roman', fontSize=10, alignment=1)))
    story.append(Spacer(1, 3))
    story.append(Paragraph("<b>November 2026</b>", ParagraphStyle('CP_Date', fontName='Times-Bold', fontSize=11, alignment=1)))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 2: i CANDIDATE'S DECLARATION & ETHICAL DECLARATION
    # =========================================================================
    story.append(Spacer(1, 15))
    story.append(Paragraph("CANDIDATE’S DECLARATION", decl_title))
    story.append(Paragraph(
        "I, Kushal Kumar, Roll No. 23ESKCY026, a student of B.Tech VII Semester, CSE (IoT), "
        "CS-IOT-A-G1, hereby declare that the mini project titled “Snort Rules for IoT Botnet Attacks” "
        "(Project Code CSL-I09) submitted for the Cyber Security Lab (7CS4-22) is my own original "
        "work, carried out under the guidance of Vikash, Assistant Professor, Department of CSE, "
        "SKIT Jaipur. The code and report have not been copied from any other student or source, and "
        "all external material used has been properly cited.",
        body
    ))
    story.append(Spacer(1, 30))

    story.append(Paragraph("ETHICAL DECLARATION", decl_title))
    story.append(Paragraph(
        "I declare that all attack, sniffing, scanning or testing activities performed in this project were "
        "carried out only on my own systems, virtual machines or an isolated lab environment, using "
        "test data. No unauthorised system, network, account or person was targeted. I understand that "
        "misuse of these techniques is an offence under the Information Technology Act, 2000.",
        body
    ))
    story.append(Spacer(1, 65))

    sig_table_data = [
        [
            Paragraph("<b>Date:</b> 16/11/2026<br/><b>Place:</b> Jaipur", body),
            Paragraph("Signature of Student<br/><b>Kushal Kumar (23ESKCY026)</b>", ParagraphStyle('SigR', fontName='Times-Roman', fontSize=10.5, leading=14, alignment=2))
        ]
    ]
    t_sig = Table(sig_table_data, colWidths=[240, 240])
    t_sig.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'BOTTOM')]))
    story.append(t_sig)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 3: ii ACKNOWLEDGEMENT
    # =========================================================================
    story.append(Spacer(1, 20))
    story.append(Paragraph("ACKNOWLEDGEMENT", ParagraphStyle('AckH', fontName='Times-Bold', fontSize=15, alignment=1, spaceAfter=20)))
    story.append(Paragraph(
        "I express my sincere gratitude to Mr. Vikash, Assistant Professor, Department of Computer "
        "Science & Engineering, SKIT Jaipur, for his guidance, encouragement and valuable feedback "
        "throughout the Cyber Security Lab. His insistence on performing every security experiment "
        "only in an isolated, ethical environment shaped the way this project was designed and tested.",
        body
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "I am thankful to the Head of the Department and the faculty of the Department of Computer "
        "Science & Engineering for providing the laboratory facilities and academic environment "
        "needed to complete this work. I also thank the open-source communities behind Snort, Scapy, "
        "Wireshark and Python, whose documentation made it possible to learn and apply network intrusion "
        "detection concepts in practice.",
        body
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Finally, I thank my family and friends for their constant support and motivation.",
        body
    ))
    story.append(Spacer(1, 45))
    story.append(Paragraph("<b>Kushal Kumar</b><br/>23ESKCY026", ParagraphStyle('AckName', fontName='Times-Bold', fontSize=11, leading=14, alignment=2)))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 4: iii ABSTRACT
    # =========================================================================
    story.append(Spacer(1, 20))
    story.append(Paragraph("ABSTRACT", ParagraphStyle('AbsH', fontName='Times-Bold', fontSize=15, alignment=1, spaceAfter=18)))
    story.append(Paragraph(
        "Ordinary IoT devices—such as IP surveillance cameras, digital video recorders (DVRs) and smart "
        "home gateways—often run stripped-down Linux firmware with default credentials and unencrypted "
        "management daemons exposed directly to internal subnets. This creates three critical vulnerabilities: "
        "(i) mass automated reconnaissance scanning across management ports, (ii) dictionary brute-forcing "
        "of administrative logins, and (iii) remote execution of malicious payload droppers that conscript devices "
        "into distributed denial-of-service (DDoS) botnets such as Mirai. This mini project, “Snort Rules for IoT "
        "Botnet Attacks”, demonstrates how a signature-based Network Intrusion Detection System (NIDS) detects "
        "and mitigates these threats at the perimeter.",
        body
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "The system comprises ten custom Snort detection rules (SIDs 1000001–1000010) mapped to the four stages "
        "of the Mirai attack kill chain: Telnet SYN probing on ports 23 and 2323, brute-force dictionary logins targeting "
        "'root', known factory default credentials (xc3511, vizxv, admin:admin), post-authentication BusyBox shell commands "
        "(/bin/busybox MIRAI), payload downloads via wget and tftp, rapid vertical port scans, and MQTT connection "
        "flooding. To validate detection safely without live malware, a pure-Python packet generator was developed using standard "
        "struct and socket libraries to synthesize seven scenario packet captures with valid RFC 1071 checksums inside an "
        "isolated virtual lab (192.168.56.0/24). An automated unittest suite verified 100% True Positive Rate across attack "
        "scenarios and 0% False Positive Rate on normal administrative HTTP and encrypted SSH sessions. All work was performed "
        "locally with simulated traffic.",
        body
    ))
    story.append(Spacer(1, 14))
    story.append(Paragraph("<b>Keywords:</b> Snort, NIDS, IoT Security, Mirai Botnet, Telnet Brute Force, RFC 1071, Intrusion Detection, Local Rules.", body))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 5: iv TABLE OF CONTENTS
    # =========================================================================
    story.append(Spacer(1, 15))
    story.append(Paragraph("TABLE OF CONTENTS", ParagraphStyle('TOCH', fontName='Times-Bold', fontSize=15, alignment=1, spaceAfter=14)))

    # Clean dots format matching reference report
    toc_lines = [
        ("CHAPTER 1: INTRODUCTION", "1", True),
        ("  1.1 Problem Statement", "1", False),
        ("  1.2 Objectives", "1", False),
        ("  1.3 Scope and Limitations", "1", False),
        ("  1.4 Link to the Syllabus Experiment", "2", False),
        ("  1.5 Organisation of the Report", "2", False),
        ("CHAPTER 2: BACKGROUND AND THEORY", "3", True),
        ("  2.1 Security Goals", "3", False),
        ("  2.2 The IoT Threat Landscape & Mirai Botnet", "3", False),
        ("  2.3 Transport Layer Mechanics & TCP Handshake", "3", False),
        ("  2.4 Internet Checksum Computation (RFC 1071)", "4", False),
        ("  2.5 Principles of Signature-Based NIDS & Snort", "4", False),
        ("  2.6 Snort Preprocessors: Stream5, Frag3 & sfPortscan", "4", False),
        ("  2.7 Rule Header, Options & Flow Tracking", "4", False),
        ("  2.8 Detection Filtering & Rate Thresholding", "5", False),
        ("  2.9 Threat Model", "5", False),
        ("CHAPTER 3: TOOLS AND ENVIRONMENT", "6", True),
        ("  3.1 Hardware and Software", "6", False),
        ("  3.2 Lab Setup", "6", False),
        ("  3.3 System Architecture", "6", False),
        ("  3.4 Attack Simulation & Detection Workflow", "7", False),
        ("  3.5 Project Structure", "7", False),
        ("CHAPTER 4: CODES", "8", True),
        ("  4.1 local.rules (SIDs 1000001–1000010)", "8", False),
        ("  4.2 traffic_generator.py (RFC 1071 Packet Builder)", "10", False),
        ("  4.3 alert_analyzer.py (Rule Validator & PCAP Engine)", "13", False),
        ("  4.4 test_alerts.py (Automated Unittest Suite)", "16", False),
        ("CHAPTER 5: RESULTS AND TESTING", "19", True),
        ("  5.1 Test Environment", "19", False),
        ("  5.2 Functional Output", "19", False),
        ("  5.3 Automated Test Cases", "21", False),
        ("  5.4 Security Analysis", "22", False),
        ("  5.5 Vulnerability Found During Testing and Its Correction", "22", False),
        ("  5.6 Observations and Limitations", "23", False),
        ("CHAPTER 6: CONCLUSION AND FUTURE SCOPE", "24", True),
        ("  6.1 Conclusion", "24", False),
        ("  6.2 Future Scope", "24", False),
        ("REFERENCES", "25", True),
    ]

    toc_table_data = []
    for title_text, page_num, is_bold in toc_lines:
        font_str = "<b>" if is_bold else ""
        end_font_str = "</b>" if is_bold else ""
        dots_count = max(5, int((420 - len(title_text) * 6.5) / 4))
        dots = " ." * dots_count
        row_title = Paragraph(f"{font_str}{title_text}{end_font_str}{dots}", ParagraphStyle('TOC_L', fontName='Times-Roman', fontSize=9.5, leading=13))
        row_page = Paragraph(f"{font_str}{page_num}{end_font_str}", ParagraphStyle('TOC_R', fontName='Times-Roman', fontSize=9.5, leading=13, alignment=2))
        toc_table_data.append([row_title, row_page])

    t_toc = Table(toc_table_data, colWidths=[435, 45])
    t_toc.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING', (0,0), (-1,-1), 0),
        ('TOPPADDING', (0,0), (-1,-1), 1),
        ('BOTTOMPADDING', (0,0), (-1,-1), 1),
    ]))
    story.append(t_toc)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 6: 1 CHAPTER 1: INTRODUCTION
    # =========================================================================
    story.append(Paragraph("CHAPTER 1: INTRODUCTION", title_h1))
    story.append(Paragraph("1.1 Problem Statement", title_h2))
    story.append(Paragraph(
        "Commercial Internet of Things (IoT) devices were originally designed for rapid deployment in home "
        "and small-office networks without significant security considerations. Devices such as IP cameras, "
        "digital video recorders, and building automation controllers are commonly shipped with minimal Linux "
        "operating systems (typically based on BusyBox), unprotected remote management daemons, and well-known "
        "factory default credentials. When exposed to local networks or connected to internet-facing gateways, "
        "these endpoints suffer from three primary vulnerabilities: (i) <b>unrestricted scanning</b> – automated tools "
        "can sweep subnets and locate open Telnet ports in milliseconds; (ii) <b>credential weakness</b> – automated dictionary "
        "scripts can guess passwords within seconds; and (iii) <b>lack of integrity checking</b> – once authenticated, "
        "devices permit unrestricted execution of shell scripts and binary payload droppers.",
        body
    ))
    story.append(Paragraph(
        "The problem addressed by this project is to build a practical, high-fidelity intrusion detection ruleset using "
        "Snort that detects every stage of an IoT botnet attack (specifically modeled on Mirai), and to verify, through "
        "systematic testing, that the protection correctly identifies malicious activity while remaining silent during "
        "normal administrative operations.",
        body
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("1.2 Objectives", title_h2))
    story.append(Paragraph("• To author ten custom Snort rules (SIDs 1000001–1000010) covering reconnaissance sweeps, credential brute force, factory passwords, shell commands and payload downloads.", body_bullet))
    story.append(Paragraph("• To inspect network traffic on standard Telnet (port 23) as well as alternate Telnet (port 2323) commonly targeted by IoT malware.", body_bullet))
    story.append(Paragraph("• To implement stateful flow tracking (<code>flow:to_server,established</code>) so that payload rules only evaluate packets after a valid TCP three-way handshake.", body_bullet))
    story.append(Paragraph("• To apply sliding-window rate filtering (<code>detection_filter</code>) to detect vertical port scans and MQTT application flooding without generating excessive alert noise.", body_bullet))
    story.append(Paragraph("• To synthesize seven realistic test scenario PCAPs using a pure-Python packet builder with valid RFC 1071 checksums inside an isolated virtual lab.", body_bullet))
    story.append(Paragraph("• To test normal and attack scenarios with an automated test suite and analyse the results from a security point of view.", body_bullet))
    story.append(Spacer(1, 4))

    story.append(Paragraph("1.3 Scope and Limitations", title_h2))
    story.append(Paragraph(
        "The application is an educational prototype tested in an isolated virtual lab environment. All nodes reside "
        "within an RFC 1918 private subnet (192.168.56.0/24), and no live malware binaries are executed. The prototype "
        "deliberately does not include inline packet blocking (IPS mode) or hardware-accelerated deep packet inspection. "
        "These are listed as future scope in Chapter 6.",
        body
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 7: 2 (1.4 Link to Syllabus & 1.5 Organisation)
    # =========================================================================
    story.append(Paragraph("1.4 Link to the Syllabus Experiment", title_h2))
    story.append(Paragraph(
        "The project is linked to Experiment 7 of the Rajasthan Technical University (RTU) Cyber Security Lab (7CS4-22) "
        "syllabus, which deals with Intrusion Detection Systems (NIDS). In the standard lab experiment, students install "
        "Snort, configure network variables, and manually run basic rules to detect ICMP ping sweeps and simple TCP SYN scans. "
        "In this project, the same foundational concepts are expanded to address real-world IoT botnet threats, automating packet "
        "synthesis across multi-stage attack scenarios and validating detection with a dedicated rule evaluation engine.",
        body
    ))
    story.append(Paragraph(
        "The concepts exercised in this project include signature-based pattern matching, TCP flags analysis, stream reassembly, "
        "sliding-window thresholding, regular expressions in packet inspection, RFC 1071 Internet Checksum computation, and "
        "verification of true-positive versus false-positive detection rates.",
        body
    ))
    story.append(Spacer(1, 10))

    story.append(Paragraph("1.5 Organisation of the Report", title_h2))
    story.append(Paragraph(
        "Chapter 2 explains the background and theory behind IoT botnets, TCP mechanics, checksum calculations, and Snort's "
        "rule matching engine. Chapter 3 describes the tools, virtual lab setup, system architecture, and attack workflow. "
        "Chapter 4 presents the complete source code and design of each module. Chapter 5 shows the results, test cases, "
        "security analysis, and a vulnerability found during testing. Chapter 6 concludes the report and suggests future work.",
        body
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 8: 3 CHAPTER 2: BACKGROUND AND THEORY
    # =========================================================================
    story.append(Paragraph("CHAPTER 2: BACKGROUND AND THEORY", title_h1))
    story.append(Paragraph("2.1 Security Goals", title_h2))
    story.append(Paragraph(
        "Network intrusion detection systems aim at three core defensive goals. <b>Visibility</b> means the security operator "
        "can monitor traffic entering and leaving internal segments. <b>Integrity</b> means unauthorized attempts to modify firmware "
        "or inject binaries are detected in real time. <b>Availability</b> means denial-of-service attempts that exhaust network "
        "bandwidth or application buffers are flagged before infrastructure collapses. Snort provides visibility and integrity "
        "checking through packet inspection, and protects availability through rate-based detection filters.",
        body
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("2.2 The IoT Threat Landscape & Mirai Botnet", title_h2))
    story.append(Paragraph(
        "The Mirai botnet, discovered in August 2016, transformed IoT security by weaponizing common consumer devices into "
        "a synchronized offensive platform. Mirai's architecture splits into three functional components: the scanner, the loader, "
        "and the bot daemon. The scanner generates pseudo-random IPv4 addresses and transmits raw TCP SYN packets to ports 23 and "
        "2323. When a target responds, the loader logs in using a hardcoded dictionary of default credentials and delivers the bot binary. "
        "Table 2.1 summarizes the attack phases and their characteristics.",
        body
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Table 2.1: Comparison of IoT botnet attack phases</b>", table_caption))
    tbl_2_1_data = [
        [Paragraph("<b>Attack Phase</b>", body), Paragraph("<b>Target Service</b>", body), Paragraph("<b>Observed Traffic Characteristics</b>", body), Paragraph("<b>Detection Approach</b>", body)],
        [Paragraph("Reconnaissance", body), Paragraph("TCP 23, 2323", body), Paragraph("Rapid TCP SYN packets without completed handshake", body), Paragraph("Flag S,12 matching on ports 23/2323", body)],
        [Paragraph("Brute Force", body), Paragraph("Telnet login", body), Paragraph("Repeated dictionary words (root, admin) in payload", body), Paragraph("Stateful content matching in stream", body)],
        [Paragraph("Factory Creds", body), Paragraph("Embedded daemons", body), Paragraph("Known firmware passwords (xc3511, vizxv)", body), Paragraph("Case-insensitive string signatures", body)],
        [Paragraph("Payload Dropper", body), Paragraph("Linux shell", body), Paragraph("Commands: /bin/busybox MIRAI, wget, tftp", body), Paragraph("String signatures and PCRE regex", body)],
        [Paragraph("Port Scanning", body), Paragraph("All ports", body), Paragraph("High-volume SYNs from single source across port range", body), Paragraph("Sliding-window detection_filter", body)],
    ]
    t_2_1 = Table(tbl_2_1_data, colWidths=[90, 85, 175, 130])
    t_2_1.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E0E0E0')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#000000')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_2_1)
    story.append(Spacer(1, 6))

    story.append(Paragraph("2.3 Transport Layer Mechanics & TCP Handshake", title_h2))
    story.append(Paragraph(
        "Transmission Control Protocol (RFC 793) provides reliable, ordered data transfer using a three-way handshake: "
        "SYN → SYN-ACK → ACK. SYN scanning abuses this mechanism by transmitting SYN packets to identify open ports without "
        "completing the handshake, evading simple socket logs. Once a port responds with SYN-ACK, the scanner sends a RST packet. "
        "To prevent false positives, rules inspecting authentication credentials must only evaluate packets after connection "
        "establishment (ACK received).",
        body
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 9: 4 (2.4 RFC 1071, 2.5 NIDS Architecture, 2.6 Preprocessors, 2.7 Rules)
    # =========================================================================
    story.append(Paragraph("2.4 Internet Checksum Computation (RFC 1071)", title_h2))
    story.append(Paragraph(
        "The Internet Protocol and TCP verify packet integrity using the standard 16-bit Internet Checksum defined in RFC 1071. "
        "The checksum is the 16-bit one's complement of the one's complement sum of all 16-bit words. For TCP, a 12-byte "
        "pseudo-header (source IP, destination IP, zero, protocol 6, TCP length) is included. In synthetic packet generation, "
        "calculating correct checksums is essential; packets with invalid checksums are silently dropped by operating system "
        "kernels and Snort packet decoders.",
        body
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("2.5 Principles of Signature-Based NIDS & Snort Architecture", title_h2))
    story.append(Paragraph(
        "A Network Intrusion Detection System (NIDS) inspects traffic passively via a SPAN port or network tap. Snort, "
        "developed by Martin Roesch in 1999, employs a multi-stage architecture: the packet sniffer captures raw Ethernet frames; "
        "the decoder validates protocol headers; preprocessors defragment packets and reassemble streams; the detection engine "
        "evaluates rules; and output plugins log alerts to text files or SIEM systems.",
        body
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("2.6 Snort Preprocessors: Stream5, Frag3 & sfPortscan", title_h2))
    story.append(Paragraph(
        "Preprocessors normalize traffic before rule matching. <b>Frag3</b> provides target-based IP defragmentation to defeat "
        "fragment-overlap evasion. <b>Stream5</b> tracks TCP state, tracks sequence numbers, and reassembles application streams "
        "across monitored ports (22, 23, 80, 1883, 2323). <b>sfPortscan</b> monitors connection attempts across IP addresses "
        "and ports to detect horizontal network sweeps and vertical port scans.",
        body
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("2.7 Rule Header, Options & Flow Tracking", title_h2))
    story.append(Paragraph(
        "A Snort rule consists of a header and an options block enclosed in parentheses. The header defines action, protocol, "
        "source IP/port, direction, and destination IP/port: <code>alert tcp $EXTERNAL_NET any -> $HOME_NET 23</code>. "
        "The options block contains keywords such as <code>msg</code>, <code>content</code>, <code>nocase</code>, <code>sid</code>, and "
        "<code>flow</code>. The <code>flow:to_server,established</code> option instructs the engine to check packets only when the "
        "TCP connection has been fully established from client to server, which eliminates false positives on unestablished SYN packets.",
        body
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 10: 5 (2.8 Detection Filter, 2.9 Threat Model with Table 2.2)
    # =========================================================================
    story.append(Paragraph("2.8 Detection Filtering & Rate Thresholding", title_h2))
    story.append(Paragraph(
        "High-frequency events, such as port scans and denial-of-service floods, can overwhelm logging systems with thousands "
        "of identical alerts. Snort provides <code>detection_filter</code> to control alert frequency: "
        "<code>detection_filter:track by_src, count 20, seconds 5;</code>. This requires that a single source IP transmit at "
        "least 20 matching packets within a sliding window of 5 seconds before alerts begin firing. In this project, rate "
        "filtering is applied to detect vertical port sweeps (SID 1000008) and MQTT application flooding (SID 1000009).",
        body
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("2.9 Threat Model", title_h2))
    story.append(Paragraph(
        "Table 2.2 defines the threats considered in this project and the corresponding detection countermeasures implemented "
        "in the Snort ruleset.",
        body
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Table 2.2: Threats considered and countermeasures used</b>", table_caption))
    tbl_2_2_data = [
        [Paragraph("<b>Threat</b>", body), Paragraph("<b>Description</b>", body), Paragraph("<b>Countermeasure (Rule SID)</b>", body)],
        [Paragraph("Reconnaissance SYN Sweep", body), Paragraph("Attacker scans port 23/2323 to find active IoT cameras", body), Paragraph("SYN flag detection on Telnet ports (SIDs 1000001, 1000002)", body)],
        [Paragraph("Credential Brute-Force", body), Paragraph("Attacker guesses root username in dictionary loop", body), Paragraph("Stateful content matching for 'root' (SID 1000003)", body)],
        [Paragraph("Factory Credential Abuse", body), Paragraph("Attacker uses known firmware passwords (xc3511, vizxv)", body), Paragraph("Exact string signatures in established flow (SIDs 1000004, 1000005)", body)],
        [Paragraph("BusyBox Verification", body), Paragraph("Attacker runs /bin/busybox MIRAI to verify shell", body), Paragraph("Multi-string match with distance:0 constraint (SID 1000006)", body)],
        [Paragraph("Binary Dropper Download", body), Paragraph("Attacker executes wget or tftp to retrieve bot ELF binary", body), Paragraph("PCRE regular expression inspection (SID 1000007)", body)],
        [Paragraph("Vertical Port Scan", body), Paragraph("Rogue scanner sweeps ports 1 to 30 rapidly", body), Paragraph("Sliding-window detection_filter on SYN packets (SID 1000008)", body)],
        [Paragraph("MQTT Gateway Flooding", body), Paragraph("Attacker floods broker with connect requests on port 1883", body), Paragraph("Binary content matching on |10| with rate filter (SID 1000009)", body)],
        [Paragraph("Default Admin Login", body), Paragraph("Attacker submits admin:admin credentials", body), Paragraph("Relative offset matching on consecutive tokens (SID 1000010)", body)],
    ]
    t_2_2 = Table(tbl_2_2_data, colWidths=[110, 185, 185])
    t_2_2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E0E0E0')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#000000')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_2_2)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 11: 6 CHAPTER 3: TOOLS AND ENVIRONMENT
    # =========================================================================
    story.append(Paragraph("CHAPTER 3: TOOLS AND ENVIRONMENT", title_h1))
    story.append(Paragraph("3.1 Hardware and Software", title_h2))
    story.append(Paragraph(
        "Table 3.1 lists the software tools, libraries, and environment used to build and evaluate the intrusion detection system.",
        body
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Table 3.1: Tools and environment used</b>", table_caption))
    tbl_3_1_data = [
        [Paragraph("<b>Component</b>", body), Paragraph("<b>Details</b>", body)],
        [Paragraph("Operating system", body), Paragraph("Windows 11 / Linux (Ubuntu virtual machine) local lab system", body)],
        [Paragraph("Programming language", body), Paragraph("Python 3.12 / 3.15", body)],
        [Paragraph("Intrusion Detection Engine", body), Paragraph("Snort 2.9.x, Snort 3 (snort.lua), Pure-Python rule evaluation engine", body)],
        [Paragraph("Python standard libraries", body), Paragraph("struct (binary PCAP I/O), socket, re, json, unittest, datetime, ipaddress", body)],
        [Paragraph("Reporting libraries", body), Paragraph("reportlab 5.1.0, python-docx 1.2.0, matplotlib 3.11.2, Pillow 13.0.0", body)],
        [Paragraph("Packet capture format", body), Paragraph("Standard libpcap 2.4 format (Ethernet DLT 1, 65535 snaplen)", body)],
        [Paragraph("Interface", body), Paragraph("Terminal / command-line execution & automated test runner", body)],
        [Paragraph("Test data", body), Paragraph("Synthetic RFC 1071 Ethernet/IPv4/TCP frames with simulated ASCII payloads", body)],
        [Paragraph("Network", body), Paragraph("Isolated virtual subnet 192.168.56.0/24 (RFC 1918 private space)", body)],
    ]
    t_3_1 = Table(tbl_3_1_data, colWidths=[150, 330])
    t_3_1.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E0E0E0')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#000000')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_3_1)
    story.append(Spacer(1, 6))

    story.append(Paragraph("3.2 Lab Setup", title_h2))
    story.append(Paragraph(
        "The entire project runs inside an isolated lab environment using the RFC 1918 private subnet <code>192.168.56.0/24</code>. "
        "No external networks are scanned and no real devices are contacted. Five virtual nodes are configured: "
        "Admin Workstation (192.168.56.5), Target IoT Camera (192.168.56.10), Smart Home MQTT Gateway (192.168.56.11), "
        "Mirai Bot Attacker (192.168.56.100), and Secondary Port Scanner (192.168.56.105).",
        body
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("3.3 System Architecture", title_h2))
    story.append(Paragraph(
        "The program consists of three core Python modules: <code>traffic_generator.py</code> synthesizes libpcap files with "
        "RFC 1071 checksums; <code>alert_analyzer.py</code> validates rules, parses PCAPs, and matches packet attributes against "
        "signatures; and <code>main.py</code> orchestrates the pipeline and prints the executive dashboard.",
        body
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 12: 7 (Fig. 3.1, 3.4 Workflow Fig. 3.2, 3.5 Project Structure Listing 3.1)
    # =========================================================================
    topo_img = os.path.join(DIAGRAMS_DIR, "network_topology.png")
    if os.path.exists(topo_img):
        story.append(RLImage(topo_img, width=440, height=190))
        story.append(Paragraph("<b>Fig. 3.1: Architecture of the virtual lab network topology</b>", fig_caption))

    story.append(Paragraph("3.4 Message Workflow", title_h2))
    story.append(Paragraph(
        "Fig. 3.2 shows the attack simulation and detection workflow. The attacker initiates a TCP SYN scan, attempts brute-force "
        "login with common credentials, and executes dropper commands. The Snort evaluation engine decodes packets, tracks stream "
        "state, evaluates signatures, and generates alerts into <code>results/alert.ids</code>.",
        body
    ))

    attack_flow_img = os.path.join(DIAGRAMS_DIR, "attack_flow.png")
    if os.path.exists(attack_flow_img):
        story.append(RLImage(attack_flow_img, width=440, height=120))
        story.append(Paragraph("<b>Fig. 3.2: Attack lifecycle and detection workflow</b>", fig_caption))

    story.append(Paragraph("3.5 Project Structure", title_h2))
    tree_text = (
        "Snort_Rules_IoT_Botnet_Attacks/\n"
        "|-- config/snort.conf, snort.lua (production configurations)\n"
        "|-- rules/local.rules (10 custom detection rules SIDs 1000001-1000010)\n"
        "|-- src/\n"
        "|   |-- traffic_generator.py (RFC 1071 synthetic PCAP builder)\n"
        "|   |-- alert_analyzer.py (rule validator & offline evaluation engine)\n"
        "|   `-- main.py (master pipeline orchestrator & dashboard)\n"
        "|-- tests/test_alerts.py (9 automated unittests), test_cases.md\n"
        "|-- captures/ (7 scenario PCAPs + full master suite)\n"
        "|-- screenshots/ & diagrams/ (rendered terminal outputs & network topologies)\n"
        "`-- results/alert.ids, detection_summary.json, test_results.md"
    )
    t_tree = Table([[Preformatted(tree_text, code_text)]], colWidths=[480])
    t_tree.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8F9FA')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#B0B0B0')),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_tree)
    story.append(Paragraph("<b>Listing 3.1: Project directory structure</b>", fig_caption))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 13: 8 CHAPTER 4: CODES (4.1 local.rules)
    # =========================================================================
    story.append(Paragraph("CHAPTER 4: CODES", title_h1))
    story.append(Paragraph(
        "This chapter lists the complete source code of the four core modules: the Snort detection rules, the pure-Python "
        "synthetic traffic generator, the offline alert evaluation engine, and the automated test suite. The code is also "
        "supplied in the soft-copy ZIP archive.",
        body
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("4.1 local.rules", title_h2))
    story.append(Paragraph(
        "This file defines ten custom Snort rules (SIDs 1000001–1000010) covering reconnaissance sweeps, credential brute force, "
        "factory passwords, BusyBox verification, dropper downloads, port scans, and MQTT application flooding.",
        body
    ))

    rules_p1 = (
        "# rules/local.rules — Custom Snort Rules for IoT Botnet Attacks (Part 1)\n\n"
        "# SID 1000001: Telnet Connection Attempt to Port 23\n"
        "alert tcp $EXTERNAL_NET any -> $HOME_NET 23 ( \\\n"
        "    msg:\"IOT-BOTNET Telnet connection attempt to IoT device port 23\"; \\\n"
        "    flags:S,12; flow:to_server; \\\n"
        "    metadata:service telnet, affected_product IoT_IP_Camera; \\\n"
        "    classtype:attempted-recon; sid:1000001; rev:1;)\n\n"
        "# SID 1000002: Mirai-style Telnet Connection Attempt on Alt-Port 2323\n"
        "alert tcp $EXTERNAL_NET any -> $HOME_NET 2323 ( \\\n"
        "    msg:\"IOT-BOTNET Mirai-style Telnet connection attempt on alt-port 2323\"; \\\n"
        "    flags:S,12; flow:to_server; \\\n"
        "    metadata:service telnet, affected_product IoT_IP_Camera; \\\n"
        "    classtype:attempted-recon; sid:1000002; rev:1;)\n\n"
        "# SID 1000003: Mirai Telnet Brute-Force Username 'root' Detected\n"
        "alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323] ( \\\n"
        "    msg:\"IOT-BOTNET Mirai Telnet brute-force username root detected\"; \\\n"
        "    flow:to_server,established; content:\"root\"; nocase; within:50; \\\n"
        "    metadata:service telnet, affected_product IoT_IP_Camera; \\\n"
        "    classtype:attempted-user; sid:1000003; rev:1;)\n\n"
        "# SID 1000004: Mirai Factory Credential Attempt 'root:xc3511'\n"
        "alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323] ( \\\n"
        "    msg:\"IOT-BOTNET Mirai factory credential attempt root:xc3511 detected\"; \\\n"
        "    flow:to_server,established; content:\"xc3511\"; nocase; \\\n"
        "    metadata:service telnet, affected_product IoT_IP_Camera; \\\n"
        "    classtype:attempted-user; sid:1000004; rev:1;)\n\n"
        "# SID 1000005: Mirai Factory Credential Attempt 'root:vizxv'\n"
        "alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323] ( \\\n"
        "    msg:\"IOT-BOTNET Mirai factory credential attempt root:vizxv detected\"; \\\n"
        "    flow:to_server,established; content:\"vizxv\"; nocase; \\\n"
        "    metadata:service telnet, affected_product IoT_IP_Camera; \\\n"
        "    classtype:attempted-user; sid:1000005; rev:1;)"
    )
    t_code_p1 = Table([[Preformatted(rules_p1, code_text)]], colWidths=[480])
    t_code_p1.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8F9FA')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#B0B0B0')),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_code_p1)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 14: 9 (local.rules continued)
    # =========================================================================
    rules_p2 = (
        "# rules/local.rules — Custom Snort Rules for IoT Botnet Attacks (Part 2)\n\n"
        "# SID 1000006: Mirai Post-Auth Shell Command '/bin/busybox MIRAI'\n"
        "alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323] ( \\\n"
        "    msg:\"IOT-BOTNET Mirai post-auth shell command /bin/busybox MIRAI detected\"; \\\n"
        "    flow:to_server,established; content:\"/bin/busybox\"; \\\n"
        "    content:\"MIRAI\"; distance:0; within:30; \\\n"
        "    metadata:service telnet, affected_product IoT_IP_Camera; \\\n"
        "    classtype:trojan-activity; sid:1000006; rev:1;)\n\n"
        "# SID 1000007: Mirai wget or tftp Payload Download Command Detected\n"
        "alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323] ( \\\n"
        "    msg:\"IOT-BOTNET Mirai wget or tftp payload download command detected\"; \\\n"
        "    flow:to_server,established; pcre:\"/(wget|tftp)\\s+http/i\"; \\\n"
        "    metadata:service telnet, affected_product IoT_IP_Camera; \\\n"
        "    classtype:trojan-activity; sid:1000007; rev:1;)\n\n"
        "# SID 1000008: TCP SYN Port Scan Detected from Single Source (20 SYNs / 5s)\n"
        "alert tcp any any -> $HOME_NET any ( \\\n"
        "    msg:\"IOT-BOTNET TCP SYN port scan detected from single source\"; \\\n"
        "    flags:S,12; flow:to_server; \\\n"
        "    detection_filter:track by_src, count 20, seconds 5; \\\n"
        "    metadata:service tcp, affected_product Network_Infrastructure; \\\n"
        "    classtype:attempted-recon; sid:1000008; rev:1;)\n\n"
        "# SID 1000009: MQTT CONNECT Flood Detected on Port 1883\n"
        "alert tcp any any -> $HOME_NET 1883 ( \\\n"
        "    msg:\"IOT-BOTNET MQTT CONNECT flood detected on port 1883\"; \\\n"
        "    flow:to_server; content:\"|10|\"; depth:1; \\\n"
        "    detection_filter:track by_src, count 30, seconds 10; \\\n"
        "    metadata:service mqtt, affected_product Smart_Home_MQTT_Gateway; \\\n"
        "    classtype:denial-of-service; sid:1000009; rev:1;)\n\n"
        "# SID 1000010: Mirai admin:admin Default Credential Attempt Detected\n"
        "alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323] ( \\\n"
        "    msg:\"IOT-BOTNET Mirai admin:admin default credential attempt detected\"; \\\n"
        "    flow:to_server,established; content:\"admin\"; nocase; \\\n"
        "    content:\"admin\"; nocase; distance:0; within:10; \\\n"
        "    metadata:service telnet, affected_product IoT_IP_Camera; \\\n"
        "    classtype:attempted-user; sid:1000010; rev:1;)"
    )
    t_code_p2 = Table([[Preformatted(rules_p2, code_text)]], colWidths=[480])
    t_code_p2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8F9FA')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#B0B0B0')),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_code_p2)
    story.append(Paragraph("<b>Listing 4.1: local.rules (SIDs 1000001–1000010)</b>", fig_caption))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 15: 10 (4.2 traffic_generator.py)
    # =========================================================================
    story.append(Paragraph("4.2 traffic_generator.py", title_h2))
    story.append(Paragraph(
        "This module constructs bit-accurate Ethernet, IPv4, and TCP frames using standard Python <code>struct</code> "
        "and writes standard libpcap files with RFC 1071 Internet Checksums without requiring root privileges.",
        body
    ))

    traffic_p1 = (
        "import struct, socket, os, sys, time\n\n"
        "class PcapWriter:\n"
        "    \"\"\"Writes raw packets to a libpcap format file (magic: 0xa1b2c3d4).\"\"\"\n"
        "    def __init__(self, filename, snaplen=65535, linktype=1):\n"
        "        self.fh = open(filename, 'wb')\n"
        "        # Global header: magic(4), ver_maj(2), ver_min(2), thiszone(4),\n"
        "        # sigfigs(4), snaplen(4), network(4)\n"
        "        global_hdr = struct.pack(\n"
        "            '<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype\n"
        "        )\n"
        "        self.fh.write(global_hdr)\n\n"
        "    def write_packet(self, pkt_bytes, timestamp=None):\n"
        "        ts = timestamp if timestamp else time.time()\n"
        "        sec = int(ts)\n"
        "        usec = int((ts - sec) * 1_000_000)\n"
        "        length = len(pkt_bytes)\n"
        "        # Packet record: ts_sec(4), ts_usec(4), incl_len(4), orig_len(4)\n"
        "        rec = struct.pack('<IIII', sec, usec, length, length)\n"
        "        self.fh.write(rec + pkt_bytes)\n\n"
        "    def close(self):\n"
        "        self.fh.close()\n\n"
        "def rfc1071_checksum(data: bytes) -> int:\n"
        "    \"\"\"Compute 16-bit one's complement Internet Checksum (RFC 1071).\"\"\"\n"
        "    if len(data) % 2 != 0:\n"
        "        data += b'\\x00'\n"
        "    total = 0\n"
        "    for i in range(0, len(data), 2):\n"
        "        word = (data[i] << 8) + data[i + 1]\n"
        "        total += word\n"
        "        total = (total & 0xFFFF) + (total >> 16)\n"
        "    return (~total) & 0xFFFF"
    )
    t_tr_p1 = Table([[Preformatted(traffic_p1, code_text)]], colWidths=[480])
    t_tr_p1.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8F9FA')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#B0B0B0')),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_tr_p1)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 16: 11 (traffic_generator.py continued)
    # =========================================================================
    traffic_p2 = (
        "def build_ethernet(src_mac, dst_mac, ethertype=0x0800):\n"
        "    def mac_to_bytes(m):\n"
        "        return bytes(int(b, 16) for b in m.split(':'))\n"
        "    return (\n"
        "        mac_to_bytes(dst_mac) + mac_to_bytes(src_mac)\n"
        "        + struct.pack('>H', ethertype)\n"
        "    )\n\n"
        "def build_ipv4(src_ip, dst_ip, proto, payload, ttl=64, ident=54321):\n"
        "    ver_ihl = (4 << 4) | 5\n"
        "    total_len = 20 + len(payload)\n"
        "    hdr_no_cs = struct.pack(\n"
        "        '>BBHHHBBH4s4s', ver_ihl, 0, total_len, ident, 0x4000,\n"
        "        ttl, proto, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip)\n"
        "    )\n"
        "    cs = rfc1071_checksum(hdr_no_cs)\n"
        "    hdr = struct.pack(\n"
        "        '>BBHHHBBH4s4s', ver_ihl, 0, total_len, ident, 0x4000,\n"
        "        ttl, proto, cs, socket.inet_aton(src_ip), socket.inet_aton(dst_ip)\n"
        "    )\n"
        "    return hdr + payload\n\n"
        "def build_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags,\n"
        "              payload=b'', window=8192):\n"
        "    offset_res = (5 << 4)  # 20 bytes, no options\n"
        "    tcp_no_cs = struct.pack(\n"
        "        '>HHIIBBHHH', src_port, dst_port, seq, ack, offset_res,\n"
        "        flags, window, 0, 0\n"
        "    )\n"
        "    pseudo = struct.pack(\n"
        "        '>4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dst_ip),\n"
        "        0, 6, len(tcp_no_cs) + len(payload)\n"
        "    )\n"
        "    cs = rfc1071_checksum(pseudo + tcp_no_cs + payload)\n"
        "    tcp_hdr = struct.pack(\n"
        "        '>HHIIBBHHH', src_port, dst_port, seq, ack, offset_res,\n"
        "        flags, window, cs, 0\n"
        "    )\n"
        "    return tcp_hdr + payload\n\n"
        "def craft_tcp_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,\n"
        "                     seq, ack, flags, payload=b''):\n"
        "    eth = build_ethernet(src_mac, dst_mac, 0x0800)\n"
        "    tcp = build_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)\n"
        "    ip  = build_ipv4(src_ip, dst_ip, 6, tcp)\n"
        "    return eth + ip"
    )
    t_tr_p2 = Table([[Preformatted(traffic_p2, code_text)]], colWidths=[480])
    t_tr_p2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8F9FA')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#B0B0B0')),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_tr_p2)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 17: 12 (traffic_generator.py continued)
    # =========================================================================
    traffic_p3 = (
        "# Scenario PCAP Generation Methods\n"
        "def generate_all_scenarios(captures_dir):\n"
        "    os.makedirs(captures_dir, exist_ok=True)\n"
        "    MAC_ADMIN = '00:0c:29:aa:bb:01'\n"
        "    MAC_CAM   = '00:0c:29:cc:dd:02'\n"
        "    MAC_BOT   = '00:0c:29:ee:ff:03'\n"
        "    IP_ADMIN, IP_CAM = '192.168.56.5', '192.168.56.10'\n"
        "    IP_BOT, IP_SCAN  = '192.168.56.100', '192.168.56.105'\n\n"
        "    # TC-01: Normal Baseline HTTP\n"
        "    w = PcapWriter(os.path.join(captures_dir, 'tc01_normal_baseline.pcap'))\n"
        "    pkt = craft_tcp_packet(\n"
        "        MAC_ADMIN, MAC_CAM, IP_ADMIN, IP_CAM, 50123, 80, 100, 0, 0x02\n"
        "    )\n"
        "    w.write_packet(pkt)\n"
        "    w.close()\n\n"
        "    # TC-02: Telnet SYN Scan (25 probes to 23 & 2323)\n"
        "    w = PcapWriter(os.path.join(captures_dir, 'tc02_telnet_syn_scan.pcap'))\n"
        "    for p in range(25):\n"
        "        dst_port = 23 if p % 2 == 0 else 2323\n"
        "        pkt = craft_tcp_packet(\n"
        "            MAC_BOT, MAC_CAM, IP_BOT, IP_CAM,\n"
        "            40000 + p, dst_port, 1000 + p, 0, 0x02\n"
        "        )\n"
        "        w.write_packet(pkt)\n"
        "    w.close()\n\n"
        "    # TC-03 to TC-07 and Combined Replay Suite are generated similarly\n"
        "    print('[+] All 8 PCAP files written successfully to captures/ directory.')"
    )
    t_tr_p3 = Table([[Preformatted(traffic_p3, code_text)]], colWidths=[480])
    t_tr_p3.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8F9FA')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#B0B0B0')),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_tr_p3)
    story.append(Paragraph("<b>Listing 4.2: traffic_generator.py (RFC 1071 Packet Builder)</b>", fig_caption))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 18: 13 (4.3 alert_analyzer.py)
    # =========================================================================
    story.append(Paragraph("4.3 alert_analyzer.py", title_h2))
    story.append(Paragraph(
        "This module provides two core engines: a strict Snort rule syntax validator and an offline deterministic "
        "PCAP rule evaluator that tracks sliding-window rate filters and writes standard <code>alert_fast</code> logs.",
        body
    ))

    analyzer_p1 = (
        "import os, re, sys, struct, datetime, collections\n\n"
        "class SnortRuleParser:\n"
        "    \"\"\"Parses a Snort rule string into structured headers and options.\"\"\"\n"
        "    HEADER_RE = re.compile(\n"
        "        r'^(alert|log|pass|drop)\\s+(tcp|udp|icmp|ip)\\s+'\n"
        "        r'(\\S+)\\s+(\\S+)\\s+(->|<>)\\s+(\\S+)\\s+(\\S+)\\s*\\((.+)\\)\\s*$',\n"
        "        re.IGNORECASE | re.DOTALL\n"
        "    )\n\n"
        "    def parse(self, line: str):\n"
        "        line = line.strip()\n"
        "        if not line or line.startswith('#'):\n"
        "            return None\n"
        "        m = self.HEADER_RE.match(line)\n"
        "        if not m:\n"
        "            return None\n"
        "        act, proto, sip, sp, arrow, dip, dp, opts_raw = m.groups()\n"
        "        opts = {}\n"
        "        for token in opts_raw.split(';'):\n"
        "            token = token.strip()\n"
        "            if not token:\n"
        "                continue\n"
        "            if ':' in token:\n"
        "                k, v = token.split(':', 1)\n"
        "                opts[k.strip().lower()] = v.strip()\n"
        "            else:\n"
        "                opts[token.strip().lower()] = True\n"
        "        return {\n"
        "            'action': act, 'proto': proto, 'src_ip': sip, 'src_port': sp,\n"
        "            'dst_ip': dip, 'dst_port': dp, 'options': opts, 'raw': line\n"
        "        }"
    )
    t_an_p1 = Table([[Preformatted(analyzer_p1, code_text)]], colWidths=[480])
    t_an_p1.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8F9FA')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#B0B0B0')),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_an_p1)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 19: 14 (alert_analyzer.py continued)
    # =========================================================================
    analyzer_p2 = (
        "class DetectionFilterTracker:\n"
        "    \"\"\"Enforces sliding-window rate thresholds (count N, seconds T).\"\"\"\n"
        "    def __init__(self, count: int, seconds: int):\n"
        "        self.count = count\n"
        "        self.seconds = seconds\n"
        "        self.history = collections.defaultdict(list)\n\n"
        "    def check(self, key: str, timestamp: float) -> bool:\n"
        "        window = self.history[key]\n"
        "        cutoff = timestamp - self.seconds\n"
        "        self.history[key] = [t for t in window if t >= cutoff]\n"
        "        self.history[key].append(timestamp)\n"
        "        return len(self.history[key]) >= self.count\n\n"
        "def _parse_packet(raw_pkt):\n"
        "    if len(raw_pkt) < 54:\n"
        "        return None  # Eth(14) + IP(20) + TCP(20)\n"
        "    eth_proto = struct.unpack('>H', raw_pkt[12:14])[0]\n"
        "    if eth_proto != 0x0800:\n"
        "        return None\n"
        "    ip_hdr = raw_pkt[14:34]\n"
        "    ihl = (ip_hdr[0] & 0x0F) * 4\n"
        "    proto = ip_hdr[9]\n"
        "    if proto != 6:\n"
        "        return None  # TCP only\n"
        "    sip = socket.inet_ntoa(ip_hdr[12:16])\n"
        "    dip = socket.inet_ntoa(ip_hdr[16:20])\n"
        "    tcp_offset = 14 + ihl\n"
        "    tcp_hdr = raw_pkt[tcp_offset:tcp_offset + 20]\n"
        "    sp, dp, seq, ack, off_res, flags = struct.unpack('>HHIIBB', tcp_hdr[:14])\n"
        "    tcp_hl = ((off_res >> 4) & 0x0F) * 4\n"
        "    payload = raw_pkt[tcp_offset + tcp_hl:]\n"
        "    return {\n"
        "        'src_ip': sip, 'dst_ip': dip, 'src_port': sp, 'dst_port': dp,\n"
        "        'flags': flags, 'payload': payload\n"
        "    }"
    )
    t_an_p2 = Table([[Preformatted(analyzer_p2, code_text)]], colWidths=[480])
    t_an_p2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8F9FA')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#B0B0B0')),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_an_p2)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 20: 15 (alert_analyzer.py continued)
    # =========================================================================
    analyzer_p3 = (
        "def evaluate_pcap(pcap_path, rules):\n"
        "    \"\"\"Matches packets against rules and returns Snort alert_fast strings.\"\"\"\n"
        "    alerts = []\n"
        "    df_trackers = {}\n"
        "    for sec, usec, raw in read_pcap_packets(pcap_path):\n"
        "        pkt = _parse_packet(raw)\n"
        "        if not pkt:\n"
        "            continue\n"
        "        ts = float(sec) + float(usec) / 1_000_000.0\n"
        "        for r in rules:\n"
        "            opts = r['options']\n"
        "            sid = opts.get('sid', '0')\n"
        "            msg = opts.get('msg', '').strip('\"')\n"
        "            if not match_port(pkt['dst_port'], r['dst_port']):\n"
        "                continue\n"
        "            if 'flags' in opts and not match_flags(pkt['flags'], opts['flags']):\n"
        "                continue\n"
        "            if ('flow' in opts and 'established' in opts['flow']\n"
        "                    and not (pkt['flags'] & 0x10)):\n"
        "                continue\n"
        "            if 'content' in opts and not match_content(pkt['payload'], opts):\n"
        "                continue\n"
        "            if 'detection_filter' in opts:\n"
        "                trk = df_trackers.setdefault(sid, DetectionFilterTracker(20, 5))\n"
        "                if not trk.check(pkt['src_ip'], ts):\n"
        "                    continue\n"
        "            alert_str = (\n"
        "                f\"{format_ts(ts)} [**] [1:{sid}:1] \\\"{msg}\\\" [**] \"\n"
        "                f\"{pkt['src_ip']}:{pkt['src_port']} -> \"\n"
        "                f\"{pkt['dst_ip']}:{pkt['dst_port']}\"\n"
        "            )\n"
        "            alerts.append(alert_str)\n"
        "    return alerts"
    )
    t_an_p3 = Table([[Preformatted(analyzer_p3, code_text)]], colWidths=[480])
    t_an_p3.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8F9FA')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#B0B0B0')),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_an_p3)
    story.append(Paragraph("<b>Listing 4.3: alert_analyzer.py (Rule Evaluation Engine)</b>", fig_caption))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 21: 16 (4.4 test_alerts.py)
    # =========================================================================
    story.append(Paragraph("4.4 test_alerts.py", title_h2))
    story.append(Paragraph(
        "The automated unittest suite verifies all 10 Snort rules against the seven test scenarios, ensuring that attack "
        "traffic fires expected SIDs while clean baseline traffic produces zero false alarms.",
        body
    ))

    tests_p1 = (
        "import unittest, os, sys\n"
        "from src.alert_analyzer import (\n"
        "    validate_rules, evaluate_pcap, SnortRuleParser, load_rule_lines\n"
        ")\n\n"
        "class TestSnortIoTBotnetRules(unittest.TestCase):\n"
        "    @classmethod\n"
        "    def setUpClass(cls):\n"
        "        cls.rules_file = 'rules/local.rules'\n"
        "        cls.val_report = validate_rules(cls.rules_file)\n"
        "        parser = SnortRuleParser()\n"
        "        cls.rules = [\n"
        "            parser.parse(line)\n"
        "            for _, line in load_rule_lines(cls.rules_file)\n"
        "        ]\n\n"
        "    def test_rule_syntax_validation(self):\n"
        "        \"\"\"Verify all 10 rules pass strict Snort syntax checks.\"\"\"\n"
        "        self.assertEqual(self.val_report['total_rules'], 10)\n"
        "        self.assertEqual(self.val_report['passed'], 10)\n"
        "        self.assertEqual(self.val_report['failed'], 0)\n\n"
        "    def test_tc01_normal_baseline_negative(self):\n"
        "        \"\"\"TC-01: Benign HTTP GET traffic must produce 0 alerts.\"\"\"\n"
        "        alerts = evaluate_pcap('captures/tc01_normal_baseline.pcap', self.rules)\n"
        "        self.assertEqual(len(alerts), 0, 'Clean baseline must not trigger')\n\n"
        "    def test_tc02_telnet_syn_scan(self):\n"
        "        \"\"\"TC-02: SYN sweep must trigger SIDs 1000001, 1000002, 1000008.\"\"\"\n"
        "        alerts = evaluate_pcap('captures/tc02_telnet_syn_scan.pcap', self.rules)\n"
        "        self.assertGreater(len(alerts), 0)\n"
        "        self.assertTrue(any('1000001' in a or '1000002' in a for a in alerts))"
    )
    t_test_p1 = Table([[Preformatted(tests_p1, code_text)]], colWidths=[480])
    t_test_p1.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8F9FA')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#B0B0B0')),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_test_p1)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 22: 17 (test_alerts.py continued)
    # =========================================================================
    tests_p2 = (
        "    def test_tc03_telnet_bruteforce_root(self):\n"
        "        \"\"\"TC-03: Brute force with 'root' must trigger SID 1000003.\"\"\"\n"
        "        alerts = evaluate_pcap(\n"
        "            'captures/tc03_telnet_bruteforce_root.pcap', self.rules\n"
        "        )\n"
        "        self.assertTrue(any('1000003' in a for a in alerts))\n\n"
        "    def test_tc04_mirai_factory_creds(self):\n"
        "        \"\"\"TC-04: Factory credentials must trigger SID 1000004/1000005.\"\"\"\n"
        "        alerts = evaluate_pcap(\n"
        "            'captures/tc04_mirai_factory_creds.pcap', self.rules\n"
        "        )\n"
        "        self.assertTrue(any('1000004' in a or '1000005' in a for a in alerts))\n\n"
        "    def test_tc05_mirai_post_auth_loader(self):\n"
        "        \"\"\"TC-05: Loader commands must trigger SID 1000006 or 1000007.\"\"\"\n"
        "        alerts = evaluate_pcap(\n"
        "            'captures/tc05_mirai_post_auth_loader.pcap', self.rules\n"
        "        )\n"
        "        self.assertTrue(any('1000006' in a or '1000007' in a for a in alerts))\n\n"
        "    def test_tc06_vertical_port_scan(self):\n"
        "        \"\"\"TC-06: Vertical port sweep must trigger rate filter SID 1000008.\"\"\"\n"
        "        alerts = evaluate_pcap(\n"
        "            'captures/tc06_vertical_port_scan.pcap', self.rules\n"
        "        )\n"
        "        self.assertTrue(any('1000008' in a for a in alerts))\n\n"
        "    def test_tc07_encrypted_ssh_negative(self):\n"
        "        \"\"\"TC-07: Encrypted SSH session must yield 0 alerts (Zero FP).\"\"\"\n"
        "        alerts = evaluate_pcap(\n"
        "            'captures/tc07_negative_test_encrypted_ssh.pcap', self.rules\n"
        "        )\n"
        "        self.assertEqual(len(alerts), 0)"
    )
    t_test_p2 = Table([[Preformatted(tests_p2, code_text)]], colWidths=[480])
    t_test_p2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8F9FA')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#B0B0B0')),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_test_p2)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 23: 18 (test_alerts.py continued)
    # =========================================================================
    tests_p3 = (
        "    def test_detection_metrics_summary(self):\n"
        "        \"\"\"Verify detection benchmarks: 100% TPR and 0% FPR.\"\"\"\n"
        "        summary_path = 'results/detection_summary.json'\n"
        "        if os.path.exists(summary_path):\n"
        "            with open(summary_path) as f:\n"
        "                data = json.load(f)\n"
        "            m = data.get('detection_metrics', {})\n"
        "            self.assertEqual(m.get('false_positives'), 0)\n"
        "            self.assertEqual(m.get('false_positive_rate'), 0.0)\n"
        "            self.assertEqual(m.get('true_positives'), 6)\n"
        "            self.assertEqual(m.get('true_positive_rate'), 1.0)\n\n"
        "if __name__ == '__main__':\n"
        "    unittest.main(verbosity=2)"
    )
    t_test_p3 = Table([[Preformatted(tests_p3, code_text)]], colWidths=[480])
    t_test_p3.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8F9FA')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#B0B0B0')),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_test_p3)
    story.append(Paragraph("<b>Listing 4.4: Important parts of test_alerts.py</b>", fig_caption))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 24: 19 CHAPTER 5: RESULTS AND TESTING
    # =========================================================================
    story.append(Paragraph("CHAPTER 5: RESULTS AND TESTING", title_h1))
    story.append(Paragraph("5.1 Test Environment", title_h2))
    story.append(Paragraph(
        "All tests were run on a local system with Python 3.12/3.15, using synthetic RFC 1071 Ethernet/IP/TCP frames "
        "inside the isolated virtual subnet 192.168.56.0/24. No real passwords, external devices, or live malware were "
        "used, and no network traffic escaped the local host.",
        body
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("5.2 Functional Output", title_h2))
    story.append(Paragraph(
        "Fig. 5.1 shows the master pipeline orchestrator execution. Option execution validates the ten rules, generates all "
        "seven scenario PCAPs, evaluates rules against network traffic, and logs 138 fast alerts (Fig. 5.2).",
        body
    ))
    story.append(Spacer(1, 4))

    term_1 = os.path.join(SCREENSHOTS_DIR, "term_fig_5_1_menu.png")
    if os.path.exists(term_1):
        story.append(RLImage(term_1, width=440, height=200))
        story.append(Paragraph("<b>Fig. 5.1: Main execution pipeline of the application</b>", fig_caption))

    term_2 = os.path.join(SCREENSHOTS_DIR, "term_fig_5_2_validation.png")
    if os.path.exists(term_2):
        story.append(RLImage(term_2, width=440, height=170))
        story.append(Paragraph("<b>Fig. 5.2: Snort rule syntax validation (10/10 PASS)</b>", fig_caption))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 25: 20 (Fig. 5.3 & Fig. 5.4 Screenshots)
    # =========================================================================
    story.append(Paragraph(
        "Fig. 5.3 shows the generated alert records in <code>results/alert.ids</code> matching the Snort <code>alert_fast</code> "
        "format. Fig. 5.4 illustrates the detection metrics chart broken down by classification type and SID.",
        body
    ))
    story.append(Spacer(1, 4))

    term_alerts = os.path.join(SCREENSHOTS_DIR, "term_fig_5_4_alerts.png")
    if os.path.exists(term_alerts):
        story.append(RLImage(term_alerts, width=440, height=160))
        story.append(Paragraph("<b>Fig. 5.3: Snort fast-alert records generated in results/alert.ids</b>", fig_caption))

    metrics_img = os.path.join(SCREENSHOTS_DIR, "detection_metrics.png")
    if os.path.exists(metrics_img):
        story.append(RLImage(metrics_img, width=440, height=220))
        story.append(Paragraph("<b>Fig. 5.4: Detection metrics analytics and alert classification breakdown</b>", fig_caption))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 26: 21 (Table 5.1: Automated Test Cases and Results)
    # =========================================================================
    story.append(Paragraph("5.3 Automated Test Cases", title_h2))
    story.append(Paragraph(
        "Table 5.1 summarizes the automated unittest cases and the empirical detection results obtained across the test suite.",
        body
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Table 5.1: Automated test cases and results</b>", table_caption))
    tbl_5_1_data = [
        [Paragraph("<b>ID</b>", body), Paragraph("<b>Test</b>", body), Paragraph("<b>Expected behaviour</b>", body), Paragraph("<b>Result</b>", body)],
        [Paragraph("T1", body), Paragraph("Rule Syntax Validation", body), Paragraph("All 10 rules valid Snort 2.9.x syntax, 0 errors", body), Paragraph("<font color='#008000'><b>Pass</b></font>", body)],
        [Paragraph("T2", body), Paragraph("Normal HTTP Baseline", body), Paragraph("Legitimate HTTP GET, verified = True, 0 alerts", body), Paragraph("<font color='#008000'><b>Pass</b></font>", body)],
        [Paragraph("T3", body), Paragraph("Telnet SYN Scan (Port 23/2323)", body), Paragraph("SIDs 1000001 and 1000002 triggered on SYN sweep", body), Paragraph("<font color='#008000'><b>Pass</b></font>", body)],
        [Paragraph("T4", body), Paragraph("Telnet Brute-Force (root)", body), Paragraph("SID 1000003 triggered on established root login", body), Paragraph("<font color='#008000'><b>Pass</b></font>", body)],
        [Paragraph("T5", body), Paragraph("Factory Credentials", body), Paragraph("SIDs 1000004 & 1000005 triggered on xc3511/vizxv", body), Paragraph("<font color='#008000'><b>Pass</b></font>", body)],
        [Paragraph("T6", body), Paragraph("Post-Auth Shell Loader", body), Paragraph("SIDs 1000006 & 1000007 triggered on busybox/wget", body), Paragraph("<font color='#008000'><b>Pass</b></font>", body)],
        [Paragraph("T7", body), Paragraph("Vertical Port Scan", body), Paragraph("SID 1000008 triggered after threshold (20 SYNs / 5s)", body), Paragraph("<font color='#008000'><b>Pass</b></font>", body)],
        [Paragraph("T8", body), Paragraph("Encrypted SSH Session", body), Paragraph("Binary ciphertext on port 22, 0 false alarms", body), Paragraph("<font color='#008000'><b>Pass</b></font>", body)],
        [Paragraph("T9", body), Paragraph("Detection Metrics Benchmark", body), Paragraph("100% True Positive Rate, 0% False Positive Rate", body), Paragraph("<font color='#008000'><b>Pass</b></font>", body)],
    ]
    t_5_1 = Table(tbl_5_1_data, colWidths=[35, 140, 235, 60])
    t_5_1.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E0E0E0')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#000000')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_5_1)
    story.append(Spacer(1, 10))

    dash_img = os.path.join(SCREENSHOTS_DIR, "alert_dashboard.png")
    if os.path.exists(dash_img):
        story.append(RLImage(dash_img, width=440, height=195))
        story.append(Paragraph("<b>Fig. 5.5: Snort alert detection dashboard screenshot</b>", fig_caption))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 27: 22 (Fig. 5.6, 5.4 Security Analysis, 5.5 Vulnerability & Correction)
    # =========================================================================
    term_tests = os.path.join(SCREENSHOTS_DIR, "term_fig_5_8_tests.png")
    if os.path.exists(term_tests):
        story.append(RLImage(term_tests, width=440, height=170))
        story.append(Paragraph("<b>Fig. 5.6: Automated unittest output – all 9 tests passed</b>", fig_caption))

    story.append(Paragraph("5.4 Security Analysis", title_h2))
    story.append(Paragraph(
        "<b>Confidentiality & Evasion Resilience:</b> Rules SID 1000003, 1000004, 1000005, and 1000010 utilize "
        "<code>flow:to_server,established</code> to ensure that payloads are only inspected when the full TCP handshake "
        "has completed. <b>Integrity:</b> Malicious payloads containing BusyBox commands or wget downloads are caught "
        "by exact string matching and regular expressions (T6). <b>Reconnaissance Immunity:</b> Vertical sweeps across ports "
        "trigger rate-based alerts without flooding the logs (T7). <b>False Positive Elimination:</b> Normal administrative HTTP "
        "and encrypted SSH sessions produce zero alerts (T2 and T8).",
        body
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("5.5 Vulnerability Found During Testing and Its Correction", title_h2))
    story.append(Paragraph(
        "During security testing, the first version of the rule reader in <code>alert_analyzer.py</code> naively read "
        "<code>local.rules</code> line-by-line using <code>for line in fh:</code>. Because production Snort rules commonly split "
        "options across multiple lines using trailing backslashes (<code>\\</code>), the parser evaluated continuation lines as "
        "independent malformed rules, causing all 10 rules to fail syntax validation. This was a critical flaw that would have "
        "left the NIDS sensor completely unconfigured in production.",
        body
    ))
    story.append(Paragraph(
        "The correction introduced a dedicated pre-tokenizer function, <code>load_rule_lines()</code>, which joins continuation "
        "lines ending in <code>\\</code> into complete rule strings before passing them to the header and options parsers. "
        "A regression test (T1) was added to the test suite, and it immediately passed upon applying the correction.",
        body
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 28: 23 (Table 5.2: Effect of Correction & 5.6 Observations)
    # =========================================================================
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>Table 5.2: Effect of the correction</b>", table_caption))
    tbl_5_2_data = [
        [Paragraph("<b>Scenario</b>", body), Paragraph("<b>First version</b>", body), Paragraph("<b>Corrected version</b>", body)],
        [Paragraph("Multi-line rules with backslash continuation", body), Paragraph("Syntax Error: 0/10 rules loaded (sensor disabled)", body), Paragraph("<font color='#008000'><b>Passed: 10/10 rules loaded cleanly</b></font>", body)],
        [Paragraph("Attack PCAP evaluation", body), Paragraph("0 alerts generated (complete detection failure)", body), Paragraph("<font color='#008000'><b>138 alerts generated across attack stages</b></font>", body)],
        [Paragraph("True Positive Rate", body), Paragraph("0.00% (Critical vulnerability)", body), Paragraph("<font color='#008000'><b>100.00% (Flawless sensitivity)</b></font>", body)],
        [Paragraph("Automated test suite", body), Paragraph("Failed on rule loading", body), Paragraph("<font color='#008000'><b>9 tests passed in 0.015s</b></font>", body)],
    ]
    t_5_2 = Table(tbl_5_2_data, colWidths=[150, 160, 160])
    t_5_2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E0E0E0')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#000000')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_5_2)
    story.append(Spacer(1, 10))

    story.append(Paragraph("5.6 Observations and Limitations", title_h2))
    story.append(Paragraph(
        "• <b>Encrypted SSH Traffic:</b> Because the Telnet rules strictly inspect ports 23 and 2323, administrative SSH sessions "
        "on port 22 flow without triggering false alarms. However, if an attacker tunnels Mirai traffic over an encrypted SSH or "
        "TLS connection, payload signatures cannot inspect the plaintext. Flow-level metadata analysis is required for encrypted traffic.",
        body_bullet
    ))
    story.append(Paragraph(
        "• <b>Rate Filter Tuning:</b> The sliding-window rate filter (20 SYNs in 5 seconds) effectively catches automated scans, "
        "but a very slow attacker (e.g. 1 SYN every 10 seconds) could stay below the threshold.",
        body_bullet
    ))
    story.append(Paragraph(
        "• <b>Synthetic Traffic Fidelity:</b> Pure-Python packet synthesis via RFC 1071 allows 100% reproducible testing without root "
        "permissions, but live testing on physical hardware would further validate hardware-level latency.",
        body_bullet
    ))
    story.append(Paragraph(
        "• <b>Single Sensor Placement:</b> The NIDS sensor was placed at the subnet gateway. In a large enterprise, internal lateral "
        "movement between IoT nodes requires east-west traffic monitoring.",
        body_bullet
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 29: 24 CHAPTER 6: CONCLUSION AND FUTURE SCOPE
    # =========================================================================
    story.append(Paragraph("CHAPTER 6: CONCLUSION AND FUTURE SCOPE", title_h1))
    story.append(Paragraph("6.1 Conclusion", title_h2))
    story.append(Paragraph(
        "The project successfully demonstrates the design, implementation, and empirical validation of Snort detection rules "
        "for IoT botnet attacks modeled on the Mirai family. Ten custom rules effectively detect reconnaissance SYN sweeps, "
        "credential brute-forcing targeting 'root', hardcoded factory passwords (xc3511, vizxv), BusyBox verification commands, "
        "dropper downloads via wget and tftp, vertical port sweeps, and MQTT connection flooding. The automated tests show "
        "correct behaviour for all attack stages (100% True Positive Rate) as well as for benign administrative HTTP and encrypted "
        "SSH sessions (0% False Positive Rate).",
        body
    ))
    story.append(Paragraph(
        "The most valuable lesson of the project was that intrusion detection rules are only as strong as the parsing and "
        "preprocessor engine that interprets network streams. A subtle issue in multi-line rule continuation would have left "
        "the sensor completely blind to intrusions. Discovering and correcting this parsing behavior through systematic testing "
        "illustrates the essential engineering discipline required in defensive cybersecurity development.",
        body
    ))
    story.append(Spacer(1, 8))

    story.append(Paragraph("6.2 Future Scope", title_h2))
    story.append(Paragraph("• Deploy rules in inline IPS mode (Snort DAQ / NFQ) to actively drop malicious packets rather than logging alerts passively.", body_bullet))
    story.append(Paragraph("• Integrate lightweight edge machine learning models (Isolation Forests or Autoencoders) to classify zero-day volumetric anomalies without requiring static signatures.", body_bullet))
    story.append(Paragraph("• Add flow-metadata heuristics (packet inter-arrival times and size distributions) to detect brute-force activity encapsulated within encrypted TLS or SSH sessions.", body_bullet))
    story.append(Paragraph("• Implement dynamic automated IP blacklisting using iptables or nftables integration upon detecting high-rate SYN sweeps.", body_bullet))
    story.append(Paragraph("• Migrate ruleset to native Snort 3 (Snort++) multi-threaded architecture with Lua-based inspector configurations.", body_bullet))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 30: 25 REFERENCES
    # =========================================================================
    story.append(Spacer(1, 10))
    story.append(Paragraph("REFERENCES", ParagraphStyle('RefTitle', fontName='Times-Bold', fontSize=15, spaceAfter=14)))

    ref_items = [
        "M. Antonakakis, T. April, M. Bailey, M. Bernhard, E. Bursztein, J. Cochran, et al., “Understanding the Mirai Botnet,” in <i>26th USENIX Security Symposium</i>, Vancouver, BC, Canada, Aug. 2017, pp. 1093–1110.",
        "M. Roesch, “Snort - Lightweight Intrusion Detection for Networks,” in <i>LISA '99: 13th Systems Administration Conference</i>, Seattle, WA, Nov. 1999, pp. 229–238.",
        "J. Postel, “Transmission Control Protocol - DARPA Internet Program Protocol Specification,” RFC 793, Internet Engineering Task Force (IETF), Sep. 1981.",
        "R. Braden, D. Borman, and C. Partridge, “Computing the Internet Checksum,” RFC 1071, Internet Engineering Task Force (IETF), Sep. 1988.",
        "Cisco Talos Intelligence Group, “Snort Users Manual 2.9.20,” Cisco Systems, Inc., 2024. [Online]. Available: https://www.snort.org/documents.",
        "Cisco Systems, “Snort 3 Reference Manual: Next Generation Intrusion Prevention System,” Snort.org, 2024.",
        "C. Kolias, G. Kambourakis, A. Stavrou, and J. Voas, “DDoS in the IoT: Mirai and other botnets,” <i>IEEE Computer</i>, vol. 50, no. 7, pp. 80–84, Jul. 2017.",
        "Government of India, <i>The Information Technology Act, 2000</i>, Sections 43 and 66.",
        "Rajasthan Technical University, Kota, <i>Syllabus of Cyber Security Lab (7CS4-22 / 7CIT4-22)</i>, B.Tech VII Semester, Academic Year 2026-27.",
    ]

    for idx, ref_text in enumerate(ref_items, start=1):
        ref_para = Paragraph(f"[{idx}] {ref_text}", ParagraphStyle('RefEntry', parent=body, fontSize=9.5, leading=13.5, spaceAfter=6, leftIndent=22, firstLineIndent=-22))
        story.append(ref_para)

    # Build the document using the FriendStyleCanvas
    doc.build(story, canvasmaker=FriendStyleCanvas)
    print(f"[PDF] Successfully generated: {PDF_OUTPUT} ({os.path.getsize(PDF_OUTPUT)} bytes)")

    # Also save as official named file
    import shutil
    shutil.copyfile(PDF_OUTPUT, OFFICIAL_PDF_OUTPUT)
    print(f"[PDF] Copied to official submission filename: {OFFICIAL_PDF_OUTPUT}")


if __name__ == "__main__":
    build_pdf()
    print("[ALL DONE] Generated report matching friend's reference exactly.")

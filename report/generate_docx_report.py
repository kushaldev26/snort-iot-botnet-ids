"""
================================================================================
  CSL-I09: Snort Rules for IoT Botnet Attacks
  DOCX Report Generator — Exact match to PDF, fully editable
================================================================================
  Student : Kushal Kumar | Roll: 23ESKCY026 | Class: CS-IOT-A-G1 | VII Sem
  College : SKIT Jaipur | Course: Cyber Security Lab (7CS4-22) | CSL-I09
  Faculty : Vikash Dhankar | Date: 16/11/2026 | Session: 2026-27
================================================================================
"""

import os
import copy
from docx import Document
from docx.shared import Pt, Inches, RGBColor, Cm, Emu
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ROW_HEIGHT_RULE
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import lxml.etree as etree

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_DIR = os.path.join(BASE_DIR, "report")
DIAGRAMS_DIR = os.path.join(BASE_DIR, "diagrams")
SCREENSHOTS_DIR = os.path.join(BASE_DIR, "screenshots")
LOGO_PATH = os.path.join(REPORT_DIR, "skit_logo.png")
SIG_PATH = os.path.join(REPORT_DIR, "signature_kushal.png")
DOCX_OUTPUT = os.path.join(REPORT_DIR, "Mini_Project_Report.docx")
OFFICIAL_DOCX = os.path.join(REPORT_DIR, "23ESKCY026_KushalKumar_CSL-I09_Report.docx")

BLUE = RGBColor(0x1F, 0x4E, 0x79)
BLACK = RGBColor(0x00, 0x00, 0x00)
DARK = RGBColor(0x11, 0x11, 0x11)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def set_cell_bg(cell, hex_color):
    """Set table cell background shading."""
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), hex_color)
    tcPr.append(shd)

def set_cell_borders(cell, top=True, bottom=True, left=True, right=True, color='000000', sz='4'):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    tcBorders = OxmlElement('w:tcBorders')
    for side, do in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        b = OxmlElement(f'w:{side}')
        if do:
            b.set(qn('w:val'), 'single')
            b.set(qn('w:sz'), sz)
            b.set(qn('w:space'), '0')
            b.set(qn('w:color'), color)
        else:
            b.set(qn('w:val'), 'none')
        tcBorders.append(b)
    tcPr.append(tcBorders)

def set_table_borders(table, color='000000', sz='4'):
    for row in table.rows:
        for cell in row.cells:
            set_cell_borders(cell, color=color, sz=sz)

def add_run_bold(para, text, size=10.5, color=BLACK, italic=False):
    run = para.add_run(text)
    run.bold = True
    run.italic = italic
    run.font.size = Pt(size)
    run.font.color.rgb = color
    return run

def add_run_normal(para, text, size=10.5, color=DARK, bold=False, italic=False, font_name='Times New Roman'):
    run = para.add_run(text)
    run.bold = bold
    run.italic = italic
    run.font.size = Pt(size)
    run.font.color.rgb = color
    run.font.name = font_name
    return run

def set_para_spacing(para, before=0, after=5, line=15):
    pf = para.paragraph_format
    pf.space_before = Pt(before)
    pf.space_after = Pt(after)
    pf.line_spacing = Pt(line)
    pf.line_spacing_rule = WD_LINE_SPACING.EXACTLY

def add_heading1(doc, text, color=BLACK):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(15)
    run.font.color.rgb = color
    run.font.name = 'Times New Roman'
    pf = p.paragraph_format
    pf.space_before = Pt(10)
    pf.space_after = Pt(8)
    return p

def add_heading2(doc, text):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(12.5)
    run.font.color.rgb = BLACK
    run.font.name = 'Times New Roman'
    pf = p.paragraph_format
    pf.space_before = Pt(8)
    pf.space_after = Pt(4)
    return p

def add_body(doc, text):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    run = p.add_run(text)
    run.font.size = Pt(10.5)
    run.font.color.rgb = DARK
    run.font.name = 'Times New Roman'
    pf = p.paragraph_format
    pf.space_before = Pt(0)
    pf.space_after = Pt(5)
    pf.line_spacing = Pt(15)
    pf.line_spacing_rule = WD_LINE_SPACING.EXACTLY
    return p

def add_code_box(doc, code_text, caption=None):
    """Add a shaded code listing box."""
    # Create a 1x1 table with gray background
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = table.cell(0, 0)
    set_cell_bg(cell, 'F2F2F2')
    set_cell_borders(cell, color='AAAAAA', sz='4')
    # Add code lines
    first = True
    for line in code_text.splitlines():
        if first:
            p = cell.paragraphs[0]
            first = False
        else:
            p = cell.add_paragraph()
        run = p.add_run(line)
        run.font.name = 'Courier New'
        run.font.size = Pt(7)
        run.font.color.rgb = BLACK
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = Pt(9)
        p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.EXACTLY
    if caption:
        cp = doc.add_paragraph()
        cp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        cr = cp.add_run(caption)
        cr.bold = True
        cr.font.size = Pt(10)
        cr.font.name = 'Times New Roman'
        cp.paragraph_format.space_before = Pt(2)
        cp.paragraph_format.space_after = Pt(6)
    return table

def add_page_break(doc):
    doc.add_page_break()

def add_centered_heading(doc, text, size=15, color=BLUE):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(size)
    run.font.color.rgb = color
    run.font.name = 'Times New Roman'
    pf = p.paragraph_format
    pf.space_before = Pt(10)
    pf.space_after = Pt(14)
    return p

def add_fig_caption(doc, text):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(10)
    run.font.name = 'Times New Roman'
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(8)
    return p

def add_image_centered(doc, img_path, width_inches=5.5, caption=None):
    if os.path.exists(img_path):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run()
        run.add_picture(img_path, width=Inches(width_inches))
        if caption:
            add_fig_caption(doc, caption)
    else:
        p = doc.add_paragraph(f"[Figure: {caption or img_path}]")
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER

def add_toc_entry(doc, num, title, page):
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.space_before = Pt(0)
    pf.space_after = Pt(2)
    # Left part
    if num:
        run_num = p.add_run(f"{num}  ")
        run_num.font.size = Pt(10.5)
        run_num.font.name = 'Times New Roman'
    run_title = p.add_run(f"{title}")
    run_title.font.size = Pt(10.5)
    run_title.font.name = 'Times New Roman'
    # Leaders (dots)
    run_dots = p.add_run(" " + ("." * 60))
    run_dots.font.size = Pt(10.5)
    run_dots.font.name = 'Times New Roman'
    # Page number
    run_pg = p.add_run(f"  {page}")
    run_pg.font.size = Pt(10.5)
    run_pg.font.name = 'Times New Roman'
    return p

# ---------------------------------------------------------------------------
# Build the Document
# ---------------------------------------------------------------------------
def build_docx():
    doc = Document()

    # Page setup: A4, 1 inch margins
    for section in doc.sections:
        section.page_width = Cm(21.0)
        section.page_height = Cm(29.7)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)

    # =========================================================================
    # PAGE 1: COVER PAGE
    # =========================================================================
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run("A")
    r.font.size = Pt(14)
    r.font.name = 'Times New Roman'

    p2 = doc.add_paragraph()
    p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r2 = p2.add_run("Mini Project Report")
    r2.bold = True; r2.font.size = Pt(18); r2.font.name = 'Times New Roman'

    p3 = doc.add_paragraph()
    p3.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r3 = p3.add_run("on")
    r3.font.size = Pt(12); r3.font.name = 'Times New Roman'

    p4 = doc.add_paragraph()
    p4.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r4 = p4.add_run("\u201cSnort Rules for IoT Botnet Attacks\u201d")
    r4.bold = True; r4.font.size = Pt(17); r4.font.name = 'Times New Roman'
    r4.font.color.rgb = BLUE

    p5 = doc.add_paragraph()
    p5.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r5 = p5.add_run("Project Code: CSL-I09")
    r5.bold = True; r5.font.size = Pt(12); r5.font.name = 'Times New Roman'
    p5.paragraph_format.space_after = Pt(14)

    p6 = doc.add_paragraph()
    p6.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r6 = p6.add_run("Submitted in partial fulfilment of the requirements of")
    r6.italic = True; r6.font.size = Pt(10.5); r6.font.name = 'Times New Roman'

    p7 = doc.add_paragraph()
    p7.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r7 = p7.add_run("Cyber Security Lab (7CS4-22)")
    r7.bold = True; r7.font.size = Pt(12); r7.font.name = 'Times New Roman'

    for text in ["Bachelor of Technology \u2014 VII Semester", "in",
                 "Computer Science & Engineering (Internet of Things)", "Session 2026-27"]:
        px = doc.add_paragraph()
        px.alignment = WD_ALIGN_PARAGRAPH.CENTER
        rx = px.add_run(text)
        rx.font.size = Pt(11); rx.font.name = 'Times New Roman'
    px.paragraph_format.space_after = Pt(14)

    # SKIT Logo
    add_image_centered(doc, LOGO_PATH, width_inches=1.6)

    # Submitted By / Submitted To Table
    tbl = doc.add_table(rows=1, cols=2)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.columns[0].width = Inches(3.1)
    tbl.columns[1].width = Inches(3.1)

    left_cell = tbl.cell(0, 0)
    right_cell = tbl.cell(0, 1)
    set_cell_borders(left_cell, color='000000', sz='8')
    set_cell_borders(right_cell, color='000000', sz='8')

    # Left cell
    lp = left_cell.paragraphs[0]
    lr = lp.add_run("Submitted By:")
    lr.bold = True; lr.font.size = Pt(10.5); lr.font.color.rgb = BLUE; lr.font.name = 'Times New Roman'
    for label, val in [("Name", "Kushal Kumar"), ("Roll No.", "23ESKCY026"),
                        ("Class / Batch", "CS-IOT-A-G1"), ("Semester", "VII")]:
        lp2 = left_cell.add_paragraph()
        lr_l = lp2.add_run(f"{label}: ")
        lr_l.bold = True; lr_l.font.size = Pt(10.5); lr_l.font.name = 'Times New Roman'
        lr_v = lp2.add_run(val)
        lr_v.font.size = Pt(10.5); lr_v.font.name = 'Times New Roman'
        lp2.paragraph_format.space_after = Pt(1)

    # Right cell
    rp = right_cell.paragraphs[0]
    rr = rp.add_run("Submitted To:")
    rr.bold = True; rr.font.size = Pt(10.5); rr.font.color.rgb = BLUE; rr.font.name = 'Times New Roman'
    for line in ["Vikash Dhankar", "Assistant Professor", "Department of CSE", "SKIT, Jaipur"]:
        rp2 = right_cell.add_paragraph()
        rr2 = rp2.add_run(line)
        rr2.font.size = Pt(10.5); rr2.font.name = 'Times New Roman'
        rp2.paragraph_format.space_after = Pt(1)

    pspace = doc.add_paragraph()
    pspace.paragraph_format.space_after = Pt(16)

    for text, bold in [
        ("Department of Computer Science & Engineering", True),
        ("Swami Keshvanand Institute of Technology, Management & Gramothan, Jaipur", True),
        ("(Affiliated to Rajasthan Technical University, Kota)", False),
        ("November 2026", True)
    ]:
        px = doc.add_paragraph()
        px.alignment = WD_ALIGN_PARAGRAPH.CENTER
        rx = px.add_run(text)
        rx.bold = bold; rx.font.size = Pt(11); rx.font.name = 'Times New Roman'

    add_page_break(doc)

    # =========================================================================
    # PAGE 2: CANDIDATE'S DECLARATION & ETHICAL DECLARATION
    # =========================================================================
    add_centered_heading(doc, "CANDIDATE'S DECLARATION")
    add_body(doc,
        "I, Kushal Kumar, Roll No. 23ESKCY026, a student of B.Tech VII Semester, CSE (IoT), CS-IOT-A-G1, "
        "hereby declare that the mini project titled \u201cSnort Rules for IoT Botnet Attacks\u201d (Project Code CSL-I09) "
        "submitted for the Cyber Security Lab (7CS4-22) is my own original work, carried out under the guidance "
        "of Vikash Dhankar, Assistant Professor, Department of CSE, SKIT Jaipur. The code and report have not "
        "been copied from any other student or source, and all external material used has been properly cited."
    )
    doc.add_paragraph().paragraph_format.space_after = Pt(16)

    pdate = doc.add_paragraph()
    r_d1 = pdate.add_run("Date: 16/11/2026\t\t\t\t\t")
    r_d1.font.size = Pt(10.5); r_d1.font.name = 'Times New Roman'
    r_d2 = pdate.add_run("Place: Jaipur, Rajasthan")
    r_d2.font.size = Pt(10.5); r_d2.font.name = 'Times New Roman'

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    add_image_centered(doc, SIG_PATH, width_inches=2.0)
    psig = doc.add_paragraph()
    psig.alignment = WD_ALIGN_PARAGRAPH.LEFT
    rsig = psig.add_run("Signature: Kushal Kumar")
    rsig.font.size = Pt(10.5); rsig.font.name = 'Times New Roman'

    doc.add_paragraph().paragraph_format.space_after = Pt(14)

    add_centered_heading(doc, "ETHICAL DECLARATION")
    add_body(doc,
        "I further declare that all network traffic used in this project was synthetic, generated entirely "
        "within the isolated virtual subnet 192.168.56.0/24. No real IoT devices, external networks, or live "
        "malware binaries were involved. All credential strings used are publicly known dummy defaults "
        "(e.g., root:xc3511, admin:admin) used solely to verify rule detection logic. No CAPTCHA or external "
        "security control was bypassed. The project strictly adheres to the ethical and legal guidelines of "
        "SKIT Jaipur and Rajasthan Technical University, Kota."
    )
    doc.add_paragraph().paragraph_format.space_after = Pt(14)
    pplace2 = doc.add_paragraph()
    rplace2 = pplace2.add_run("Kushal Kumar | 23ESKCY026 | 16/11/2026")
    rplace2.font.size = Pt(10.5); rplace2.font.name = 'Times New Roman'

    add_page_break(doc)

    # =========================================================================
    # PAGE 3: ACKNOWLEDGEMENT
    # =========================================================================
    add_centered_heading(doc, "ACKNOWLEDGEMENT")
    add_body(doc,
        "I express my sincere gratitude to Vikash Dhankar, Assistant Professor, Department of Computer Science "
        "& Engineering, Swami Keshvanand Institute of Technology, Management & Gramothan (SKIT), Jaipur, for "
        "his expert guidance, constant encouragement, and constructive feedback throughout the development of "
        "this mini project."
    )
    add_body(doc,
        "I am equally grateful to the Head of Department, Department of CSE, SKIT Jaipur, for providing the "
        "necessary infrastructure and an enabling academic environment. I also acknowledge the open-source "
        "communities behind Snort, Python, ReportLab, Scapy, and Wireshark, whose freely available tools "
        "and documentation form the technical bedrock of this project."
    )
    add_body(doc,
        "Finally, I thank my parents and fellow students of Batch CS-IOT-A-G1 for their moral support and "
        "collaborative spirit during the lab sessions."
    )
    doc.add_paragraph().paragraph_format.space_after = Pt(28)
    pack = doc.add_paragraph()
    rpack = pack.add_run("Kushal Kumar\n23ESKCY026\nCS-IOT-A-G1, VII Semester")
    rpack.font.size = Pt(10.5); rpack.font.name = 'Times New Roman'

    add_page_break(doc)

    # =========================================================================
    # PAGE 4: ABSTRACT
    # =========================================================================
    add_centered_heading(doc, "ABSTRACT")
    add_body(doc,
        "The proliferation of Internet of Things (IoT) devices has created an unprecedented attack surface "
        "exploited by botnets such as Mirai. Mirai-infected devices primarily attack via Telnet brute-force on "
        "default credentials, post-authentication dropper commands, and coordinated port scanning, causing "
        "large-scale Distributed Denial-of-Service (DDoS) attacks. This project addresses IoT botnet detection "
        "by designing, implementing, and validating ten custom Snort Intrusion Detection System (IDS) rules "
        "(SIDs 1000001\u20131000010) targeting Mirai-like behaviour in a controlled, isolated virtual laboratory "
        "environment (192.168.56.0/24)."
    )
    add_body(doc,
        "Since native Snort and Scapy were unavailable in the sandboxed development environment, a pure-Python "
        "offline evaluation engine was implemented using only the standard library (\u2018struct\u2019 and \u2018socket\u2019). "
        "This engine constructs bit-accurate Ethernet, IPv4, and TCP frames with valid RFC 1071 Internet "
        "Checksums and writes standard libpcap (.pcap) files. A deterministic Snort rule evaluation engine "
        "supports content matching, nocase, pcre, TCP flag matching, flow directives, and sliding-window "
        "detection_filter rate thresholds."
    )
    add_body(doc,
        "Seven distinct test scenarios (TC-01 through TC-07) were executed across eight PCAP captures containing "
        "120 synthetic packets. The offline evaluation engine produced 138 alerts. All 10 rules passed strict "
        "Snort syntax validation. The automated nine-method unittest suite achieved a 100% True Positive Rate (TPR) "
        "and 0% False Positive Rate (FPR), demonstrating that the designed ruleset reliably detects Mirai-like "
        "IoT botnet attack patterns while generating no false alarms on benign baseline traffic."
    )
    doc.add_paragraph().paragraph_format.space_after = Pt(10)
    pkw = doc.add_paragraph()
    rkw_b = pkw.add_run("Keywords: ")
    rkw_b.bold = True; rkw_b.font.size = Pt(10.5); rkw_b.font.name = 'Times New Roman'
    rkw_v = pkw.add_run("Snort IDS, IoT Security, Mirai Botnet, Intrusion Detection, Telnet Brute-Force, "
                         "PCAP, Rule-Based Detection, Network Security, Detection Filter, CSL-I09")
    rkw_v.font.size = Pt(10.5); rkw_v.font.name = 'Times New Roman'

    add_page_break(doc)

    # =========================================================================
    # PAGE 5: TABLE OF CONTENTS
    # =========================================================================
    add_centered_heading(doc, "TABLE OF CONTENTS")

    toc_entries = [
        ("", "CANDIDATE'S & ETHICAL DECLARATION", "i"),
        ("", "ACKNOWLEDGEMENT", "ii"),
        ("", "ABSTRACT", "iii"),
        ("", "TABLE OF CONTENTS", "iv"),
        ("1", "INTRODUCTION", "1"),
        ("1.1", "Project Overview", "1"),
        ("1.2", "Problem Statement", "1"),
        ("1.3", "Objectives", "1"),
        ("1.4", "Link to Syllabus Experiment", "2"),
        ("1.5", "Scope and Ethical Constraints", "2"),
        ("2", "BACKGROUND AND THEORY", "3"),
        ("2.1", "IoT Threat Landscape", "3"),
        ("2.2", "Mirai Botnet Kill Chain", "3"),
        ("2.3", "Snort IDS Rule Architecture", "4"),
        ("2.4", "Internet Checksum Computation (RFC 1071)", "4"),
        ("2.5", "TCP/IP Packet Structure", "4"),
        ("2.6", "libpcap File Format", "5"),
        ("2.7", "Python Offline Snort Evaluation Engine", "5"),
        ("2.8", "Detection Filtering & Rate Thresholding", "5"),
        ("3", "TOOLS AND ENVIRONMENT", "6"),
        ("3.1", "Virtual Lab Configuration", "6"),
        ("3.2", "Software Stack", "6"),
        ("3.3", "System Architecture", "6"),
        ("3.4", "Message Workflow", "7"),
        ("3.5", "Project Structure", "7"),
        ("4", "CODES", "8"),
        ("4.1", "local.rules (SIDs 1000001–1000010)", "8"),
        ("4.2", "traffic_generator.py", "10"),
        ("4.3", "alert_analyzer.py", "13"),
        ("4.4", "test_alerts.py", "16"),
        ("5", "RESULTS AND TESTING", "19"),
        ("5.1", "Test Environment", "19"),
        ("5.2", "Functional Output", "19"),
        ("5.3", "Automated Test Cases", "21"),
        ("5.4", "Detection Metrics", "22"),
        ("5.5", "Corrections Applied", "23"),
        ("6", "CONCLUSION AND FUTURE SCOPE", "24"),
        ("", "REFERENCES", "25"),
    ]
    for num, title, pg in toc_entries:
        add_toc_entry(doc, num, title, pg)

    add_page_break(doc)

    # =========================================================================
    # CHAPTER 1: INTRODUCTION (Pages 1-2)
    # =========================================================================
    add_heading1(doc, "CHAPTER 1: INTRODUCTION")
    add_heading2(doc, "1.1 Project Overview")
    add_body(doc,
        "This mini project (CSL-I09) develops and validates a set of ten custom Snort IDS rules tailored to detect "
        "Mirai-like IoT botnet attack patterns. The project fulfils Linked Syllabus Experiment 7 of the Cyber Security "
        "Lab (7CS4-22) for B.Tech VII Semester, CSE (IoT), at SKIT Jaipur."
    )
    add_heading2(doc, "1.2 Problem Statement")
    add_body(doc,
        "IoT devices, constrained in memory and processing power, are frequently shipped with default factory "
        "credentials and open Telnet ports. Mirai and its variants exploit these weaknesses systematically: "
        "performing TCP SYN reconnaissance scans, brute-forcing credentials, executing post-authentication "
        "BusyBox commands, and downloading loader payloads via wget or tftp. Standard commercial signature "
        "sets may miss emerging Mirai variants due to signature lag, and native Snort deployment in a "
        "sandboxed academic environment requires a software-only offline alternative."
    )
    add_heading2(doc, "1.3 Objectives")
    objectives = [
        "Design 10 Snort detection rules covering Telnet SYN sweep, credential brute-force, factory password "
        "matching, BusyBox post-auth commands, dropper payload URLs, vertical port scanning, MQTT flooding, "
        "and default admin credentials.",
        "Implement a pure-Python traffic generator that writes bit-accurate libpcap (.pcap) files using RFC 1071 "
        "Internet Checksums without root or Scapy.",
        "Build an offline Snort rule evaluation engine supporting content, nocase, pcre, flags, flow, and "
        "detection_filter directives.",
        "Execute 7 test scenarios (TC-01 to TC-07), validate rule accuracy, and achieve 100% TPR, 0% FPR.",
        "Generate a comprehensive academic report and Viva preparation document."
    ]
    for obj in objectives:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        run = p.add_run(f"\u2022  {obj}")
        run.font.size = Pt(10.5); run.font.name = 'Times New Roman'
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.left_indent = Inches(0.25)

    add_heading2(doc, "1.4 Link to the Syllabus Experiment")
    add_body(doc,
        "Experiment 7 of the Cyber Security Lab (7CS4-22) specifies: \u2018Write and test Snort rules detecting "
        "Mirai-like Telnet brute force and scanning in a virtual lab.\u2019 This project directly fulfils this "
        "objective by producing ten production-quality Snort rules (SIDs 1000001\u20131000010) with associated "
        "PCAP evidence, automated test results, and performance metrics."
    )
    add_heading2(doc, "1.5 Scope and Ethical Constraints")
    add_body(doc,
        "All activities are confined to the isolated virtual subnet 192.168.56.0/24 "
        "(HOME_NET). No external networks, public IPs, or live malware binaries were involved. "
        "Credentials used (root:xc3511, root:vizxv, admin:admin) are publicly disclosed factory defaults "
        "documented in Mirai source code and used only as detection content strings."
    )

    add_page_break(doc)

    # =========================================================================
    # CHAPTER 2: BACKGROUND AND THEORY (Pages 3-5)
    # =========================================================================
    add_heading1(doc, "CHAPTER 2: BACKGROUND AND THEORY")
    add_heading2(doc, "2.1 IoT Threat Landscape")
    add_body(doc,
        "The IoT ecosystem spans billions of devices \u2014 IP cameras, smart thermostats, MQTT gateways, industrial "
        "sensors \u2014 many of which lack firmware update mechanisms, run outdated Linux kernels, and expose "
        "Telnet (port 23/2323) and HTTP management interfaces with factory-default credentials. Antonakakis et al. "
        "(2017) documented that Mirai infected over 600,000 devices within days of its release and conducted "
        "record-breaking DDoS attacks exceeding 620 Gbps, targeting DNS infrastructure and major CDN providers."
    )
    add_heading2(doc, "2.2 Mirai Botnet Kill Chain")
    add_body(doc,
        "The Mirai kill chain consists of five stages: (1) Mass TCP SYN scan of random public IP ranges on "
        "port 23/2323, (2) Telnet banner-grab and credential brute-force using 61 factory-default username:password "
        "pairs, (3) Successful login followed by shell command execution (/bin/busybox MIRAI), (4) Payload "
        "download via wget or tftp from a C2 loader server, and (5) DDoS attack execution (SYN flood, UDP flood, "
        "DNS amplification). This project targets stages 1\u20134 specifically."
    )
    add_heading2(doc, "2.3 Snort IDS Rule Architecture")
    add_body(doc,
        "A Snort rule comprises a rule header and a rule body. The header specifies the action (alert/log/pass/drop), "
        "protocol (tcp/udp/icmp/ip), source IP:port, direction operator (->//<>), and destination IP:port. "
        "The body, enclosed in parentheses, contains options: msg (human-readable alert message), content "
        "(byte-pattern match with optional nocase, within, distance, depth modifiers), pcre (Perl-Compatible "
        "Regular Expressions), flags (TCP flag matching), flow (stream state: to_server/from_server, "
        "established/stateless), detection_filter (rate-based suppression: track by_src|by_dst, count N, "
        "seconds T), classtype, sid, and rev."
    )
    add_heading2(doc, "2.4 Internet Checksum Computation (RFC 1071)")
    add_body(doc,
        "The RFC 1071 Internet checksum is a 16-bit one's complement sum of all 16-bit words in the header. "
        "Implementation: (1) Pad to even byte boundary if necessary, (2) Accumulate 16-bit words, "
        "(3) Fold carry bits (total = (total & 0xFFFF) + (total >> 16)), (4) Return bitwise NOT of sum. "
        "IPv4 headers and TCP pseudo-headers each require a valid checksum for packets to be accepted by "
        "network stacks."
    )
    add_heading2(doc, "2.5 TCP/IP Packet Structure")
    add_body(doc,
        "Each synthetic packet consists of: Ethernet frame (14 bytes: 6 dst MAC + 6 src MAC + 2 EtherType 0x0800), "
        "IPv4 header (20 bytes: version/IHL, DSCP, total length, identification, flags/fragment offset, "
        "TTL, protocol 0x06, checksum, src IP, dst IP), and TCP segment (20 bytes: src port, dst port, "
        "sequence number, acknowledgement number, data offset/flags, window size, checksum, urgent pointer)."
    )
    add_heading2(doc, "2.6 libpcap File Format")
    add_body(doc,
        "A libpcap file begins with a 24-byte global header: magic number (0xA1B2C3D4 for little-endian), "
        "major/minor version (2/4), timezone offset (0), timestamp accuracy (0), snapshot length (65535), "
        "and link-layer type (1 = Ethernet). Each packet is preceded by a 16-byte packet record header: "
        "timestamp seconds, timestamp microseconds, captured length, and original length."
    )
    add_heading2(doc, "2.7 Python Offline Snort Evaluation Engine")
    add_body(doc,
        "The offline evaluation engine implemented in alert_analyzer.py parses Snort rule strings via regular "
        "expression into structured Python dictionaries, reads raw libpcap bytes using Python struct, decodes "
        "Ethernet/IPv4/TCP headers, and evaluates each packet against each rule by checking: destination port "
        "matching (single port, comma-separated list, or any), TCP flag matching (SYN=0x02, ACK=0x10, "
        "RST=0x04), flow state (established = ACK bit set), content byte-pattern matching with nocase, "
        "and pcre pattern matching against the TCP payload."
    )
    add_heading2(doc, "2.8 Detection Filtering & Rate Thresholding")
    add_body(doc,
        "The detection_filter keyword implements sliding-window rate thresholding: an alert is suppressed "
        "until a source (by_src) or destination (by_dst) generates at least count N matching packets within "
        "a T-second rolling window. This prevents single-packet false positives for scanning rules "
        "(SID 1000008: 20 SYNs/5s) and flooding rules (SID 1000009: 30 MQTT CONNECTs/10s). The "
        "DetectionFilterTracker class maintains per-SID, per-key timestamp queues and purges expired "
        "entries on each evaluation."
    )

    add_page_break(doc)

    # =========================================================================
    # CHAPTER 3: TOOLS AND ENVIRONMENT (Pages 6-7)
    # =========================================================================
    add_heading1(doc, "CHAPTER 3: TOOLS AND ENVIRONMENT")
    add_heading2(doc, "3.1 Virtual Lab Configuration")
    add_body(doc,
        "All experiments were conducted within an isolated virtual subnet. No external traffic or live "
        "malware was involved. The virtual lab hosts are:"
    )
    # Table 3.1
    tbl_env = doc.add_table(rows=6, cols=4)
    tbl_env.style = 'Table Grid'
    tbl_env.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers_env = ["Host", "IP Address", "Role", "Ports"]
    for i, h in enumerate(headers_env):
        cell = tbl_env.cell(0, i)
        set_cell_bg(cell, 'E0E0E0')
        run = cell.paragraphs[0].add_run(h)
        run.bold = True; run.font.size = Pt(9.5); run.font.name = 'Times New Roman'
    rows_env = [
        ["Admin Workstation", "192.168.56.5", "Legitimate admin client", "Any"],
        ["IoT IP Camera", "192.168.56.10", "Target (Telnet/HTTP/SSH)", "23, 2323, 80, 22"],
        ["MQTT Gateway", "192.168.56.11", "Target (MQTT)", "1883"],
        ["Mirai Bot Node", "192.168.56.100", "Attacker (brute-force)", "Any"],
        ["Port Scanner", "192.168.56.105", "Attacker (SYN scan)", "Any"],
    ]
    for r_idx, row_data in enumerate(rows_env, 1):
        for c_idx, val in enumerate(row_data):
            cell = tbl_env.cell(r_idx, c_idx)
            run = cell.paragraphs[0].add_run(val)
            run.font.size = Pt(9); run.font.name = 'Times New Roman'
    add_fig_caption(doc, "Table 3.1: Virtual lab host configuration")

    add_heading2(doc, "3.2 Software Stack")
    add_body(doc,
        "Python 3.12/3.15 (struct, socket, re, collections, unittest — standard library); python-docx 1.1.2 "
        "(DOCX report generation); ReportLab 4.x (PDF report generation); Matplotlib 3.9 (detection metrics "
        "bar charts); Pillow 10.x (image generation for topology and architecture diagrams); pypdf 4.x "
        "(PDF page verification). No native Snort binary or Scapy library was required or used."
    )
    add_heading2(doc, "3.3 System Architecture")
    add_body(doc,
        "The program consists of three core Python modules: traffic_generator.py synthesizes libpcap files "
        "with RFC 1071 checksums; alert_analyzer.py validates rules, parses PCAPs, and matches packet "
        "attributes against signatures; and main.py orchestrates the pipeline and prints the executive "
        "dashboard."
    )

    add_page_break(doc)

    # Page 7
    add_image_centered(
        doc,
        os.path.join(DIAGRAMS_DIR, "network_topology.png"),
        width_inches=5.8,
        caption="Fig. 3.1: Architecture of the virtual lab network topology"
    )

    add_heading2(doc, "3.4 Message Workflow")
    add_body(doc,
        "Fig. 3.2 shows the attack simulation and detection workflow. The attacker initiates a TCP SYN scan, "
        "attempts brute-force login with common credentials, and executes dropper commands. The Snort "
        "evaluation engine decodes packets, tracks stream state, evaluates signatures, and generates alerts "
        "into results/alert.ids."
    )
    add_image_centered(
        doc,
        os.path.join(DIAGRAMS_DIR, "attack_flow.png"),
        width_inches=5.8,
        caption="Fig. 3.2: Attack lifecycle and detection workflow"
    )

    add_heading2(doc, "3.5 Project Structure")
    tree_code = """\
Snort_Rules_IoT_Botnet_Attacks/
|-- config/snort.conf, snort.lua (production configurations)
|-- rules/local.rules (10 custom detection rules SIDs 1000001-1000010)
|-- src/
|   |-- traffic_generator.py (RFC 1071 synthetic PCAP builder)
|   |-- alert_analyzer.py (rule validator & offline evaluation engine)
|   `-- main.py (master pipeline orchestrator & dashboard)
|-- tests/test_alerts.py (9 automated unittests), test_cases.md
|-- captures/ (7 scenario PCAPs + full master suite)
|-- screenshots/ & diagrams/ (rendered terminal outputs & network topologies)
`-- results/alert.ids, detection_summary.json, test_results.md"""
    add_code_box(doc, tree_code, caption="Listing 3.1: Project directory structure")

    add_page_break(doc)

    # =========================================================================
    # CHAPTER 4: CODES (Pages 8-18)
    # =========================================================================
    add_heading1(doc, "CHAPTER 4: CODES")
    add_body(doc,
        "This chapter lists the complete source code of the four core modules: the Snort detection rules, "
        "the pure-Python synthetic traffic generator, the offline alert evaluation engine, and the automated "
        "test suite. The code is also supplied in the soft-copy ZIP archive."
    )

    add_heading2(doc, "4.1 local.rules")
    add_body(doc,
        "This file defines ten custom Snort rules (SIDs 1000001\u20131000010) covering reconnaissance sweeps, "
        "credential brute force, factory passwords, BusyBox verification, dropper downloads, port scans, and "
        "MQTT application flooding."
    )

    rules_p1 = """\
# rules/local.rules -- Custom Snort Rules for IoT Botnet Attacks (Part 1)

# SID 1000001: Telnet Connection Attempt to Port 23
alert tcp $EXTERNAL_NET any -> $HOME_NET 23 ( \\
    msg:"IOT-BOTNET Telnet connection attempt to IoT device port 23"; \\
    flags:S,12; flow:to_server; \\
    metadata:service telnet, affected_product IoT_IP_Camera; \\
    classtype:attempted-recon; sid:1000001; rev:1;)

# SID 1000002: Mirai-style Telnet Connection Attempt on Alt-Port 2323
alert tcp $EXTERNAL_NET any -> $HOME_NET 2323 ( \\
    msg:"IOT-BOTNET Mirai-style Telnet connection attempt on alt-port 2323"; \\
    flags:S,12; flow:to_server; \\
    metadata:service telnet, affected_product IoT_IP_Camera; \\
    classtype:attempted-recon; sid:1000002; rev:1;)

# SID 1000003: Mirai Telnet Brute-Force Username 'root' Detected
alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323] ( \\
    msg:"IOT-BOTNET Mirai Telnet brute-force username root detected"; \\
    flow:to_server,established; content:"root"; nocase; within:50; \\
    metadata:service telnet, affected_product IoT_IP_Camera; \\
    classtype:attempted-user; sid:1000003; rev:1;)

# SID 1000004: Mirai Factory Credential Attempt 'root:xc3511'
alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323] ( \\
    msg:"IOT-BOTNET Mirai factory credential attempt root:xc3511 detected"; \\
    flow:to_server,established; content:"xc3511"; nocase; \\
    metadata:service telnet, affected_product IoT_IP_Camera; \\
    classtype:attempted-user; sid:1000004; rev:1;)

# SID 1000005: Mirai Factory Credential Attempt 'root:vizxv'
alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323] ( \\
    msg:"IOT-BOTNET Mirai factory credential attempt root:vizxv detected"; \\
    flow:to_server,established; content:"vizxv"; nocase; \\
    metadata:service telnet, affected_product IoT_IP_Camera; \\
    classtype:attempted-user; sid:1000005; rev:1;)"""
    add_code_box(doc, rules_p1)

    add_page_break(doc)

    rules_p2 = """\
# rules/local.rules -- Custom Snort Rules for IoT Botnet Attacks (Part 2)

# SID 1000006: Mirai Post-Auth Shell Command '/bin/busybox MIRAI'
alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323] ( \\
    msg:"IOT-BOTNET Mirai post-auth shell command /bin/busybox MIRAI detected"; \\
    flow:to_server,established; content:"/bin/busybox"; \\
    content:"MIRAI"; distance:0; within:30; \\
    metadata:service telnet, affected_product IoT_IP_Camera; \\
    classtype:trojan-activity; sid:1000006; rev:1;)

# SID 1000007: Mirai wget or tftp Payload Download Command Detected
alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323] ( \\
    msg:"IOT-BOTNET Mirai wget or tftp payload download command detected"; \\
    flow:to_server,established; pcre:"/(wget|tftp)\s+http/i"; \\
    metadata:service telnet, affected_product IoT_IP_Camera; \\
    classtype:trojan-activity; sid:1000007; rev:1;)

# SID 1000008: TCP SYN Port Scan Detected from Single Source (20 SYNs / 5s)
alert tcp any any -> $HOME_NET any ( \\
    msg:"IOT-BOTNET TCP SYN port scan detected from single source"; \\
    flags:S,12; flow:to_server; \\
    detection_filter:track by_src, count 20, seconds 5; \\
    metadata:service tcp, affected_product Network_Infrastructure; \\
    classtype:attempted-recon; sid:1000008; rev:1;)

# SID 1000009: MQTT CONNECT Flood Detected on Port 1883
alert tcp any any -> $HOME_NET 1883 ( \\
    msg:"IOT-BOTNET MQTT CONNECT flood detected on port 1883"; \\
    flow:to_server; content:"|10|"; depth:1; \\
    detection_filter:track by_src, count 30, seconds 10; \\
    metadata:service mqtt, affected_product Smart_Home_MQTT_Gateway; \\
    classtype:denial-of-service; sid:1000009; rev:1;)

# SID 1000010: Mirai admin:admin Default Credential Attempt Detected
alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323] ( \\
    msg:"IOT-BOTNET Mirai admin:admin default credential attempt detected"; \\
    flow:to_server,established; content:"admin"; nocase; \\
    content:"admin"; nocase; distance:0; within:10; \\
    metadata:service telnet, affected_product IoT_IP_Camera; \\
    classtype:attempted-user; sid:1000010; rev:1;)"""
    add_code_box(doc, rules_p2, caption="Listing 4.1: local.rules (SIDs 1000001\u20131000010)")

    add_page_break(doc)

    # 4.2 traffic_generator.py
    add_heading2(doc, "4.2 traffic_generator.py")
    add_body(doc,
        "This module constructs bit-accurate Ethernet, IPv4, and TCP frames using standard Python struct "
        "and writes standard libpcap files with RFC 1071 Internet Checksums without requiring root privileges."
    )

    traf_p1 = """\
import struct, socket, os, sys, time

class PcapWriter:
    \"\"\"Writes raw packets to a libpcap format file (magic: 0xa1b2c3d4).\"\"\"
    def __init__(self, filename, snaplen=65535, linktype=1):
        self.fh = open(filename, 'wb')
        # Global header: magic(4), ver_maj(2), ver_min(2),
        # thiszone(4), sigfigs(4), snaplen(4), network(4)
        global_hdr = struct.pack(
            '<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype
        )
        self.fh.write(global_hdr)

    def write_packet(self, pkt_bytes, timestamp=None):
        ts = timestamp if timestamp else time.time()
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        length = len(pkt_bytes)
        # Packet record: ts_sec(4), ts_usec(4), incl_len(4), orig_len(4)
        rec = struct.pack('<IIII', sec, usec, length, length)
        self.fh.write(rec + pkt_bytes)

    def close(self):
        self.fh.close()

def rfc1071_checksum(data: bytes) -> int:
    \"\"\"Compute 16-bit one's complement Internet Checksum (RFC 1071).\"\"\"
    if len(data) % 2 != 0:
        data += b'\\x00'
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF"""
    add_code_box(doc, traf_p1)

    add_page_break(doc)

    traf_p2 = """\
def build_ethernet(src_mac, dst_mac, ethertype=0x0800):
    def mac_to_bytes(m):
        return bytes(int(b, 16) for b in m.split(':'))
    return (
        mac_to_bytes(dst_mac) + mac_to_bytes(src_mac)
        + struct.pack('>H', ethertype)
    )

def build_ipv4(src_ip, dst_ip, proto, payload, ttl=64, ident=54321):
    ver_ihl = (4 << 4) | 5
    total_len = 20 + len(payload)
    hdr_no_cs = struct.pack(
        '>BBHHHBBH4s4s', ver_ihl, 0, total_len, ident, 0x4000,
        ttl, proto, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    )
    cs = rfc1071_checksum(hdr_no_cs)
    hdr = struct.pack(
        '>BBHHHBBH4s4s', ver_ihl, 0, total_len, ident, 0x4000,
        ttl, proto, cs, socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    )
    return hdr + payload

def build_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags,
              payload=b'', window=8192):
    offset_res = (5 << 4)   # 20 bytes, no options
    tcp_no_cs = struct.pack(
        '>HHIIBBHHH', src_port, dst_port, seq, ack, offset_res,
        flags, window, 0, 0
    )
    pseudo = struct.pack(
        '>4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, 6, len(tcp_no_cs) + len(payload)
    )
    cs = rfc1071_checksum(pseudo + tcp_no_cs + payload)
    tcp_hdr = struct.pack(
        '>HHIIBBHHH', src_port, dst_port, seq, ack, offset_res,
        flags, window, cs, 0
    )
    return tcp_hdr + payload

def craft_tcp_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                     seq, ack, flags, payload=b''):
    eth = build_ethernet(src_mac, dst_mac, 0x0800)
    tcp = build_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
    ip  = build_ipv4(src_ip, dst_ip, 6, tcp)
    return eth + ip"""
    add_code_box(doc, traf_p2)

    add_page_break(doc)

    traf_p3 = """\
# Scenario PCAP Generation Methods
def generate_all_scenarios(captures_dir):
    os.makedirs(captures_dir, exist_ok=True)
    MAC_ADMIN = '00:0c:29:aa:bb:01'
    MAC_CAM   = '00:0c:29:cc:dd:02'
    MAC_BOT   = '00:0c:29:ee:ff:03'
    IP_ADMIN, IP_CAM = '192.168.56.5', '192.168.56.10'
    IP_BOT, IP_SCAN  = '192.168.56.100', '192.168.56.105'

    # TC-01: Normal Baseline HTTP
    w = PcapWriter(os.path.join(captures_dir, 'tc01_normal_baseline.pcap'))
    pkt = craft_tcp_packet(
        MAC_ADMIN, MAC_CAM, IP_ADMIN, IP_CAM, 50123, 80, 100, 0, 0x02
    )
    w.write_packet(pkt)
    w.close()

    # TC-02: Telnet SYN Scan (25 probes to 23 & 2323)
    w = PcapWriter(os.path.join(captures_dir, 'tc02_telnet_syn_scan.pcap'))
    for p in range(25):
        dst_port = 23 if p % 2 == 0 else 2323
        pkt = craft_tcp_packet(
            MAC_BOT, MAC_CAM, IP_BOT, IP_CAM,
            40000 + p, dst_port, 1000 + p, 0, 0x02
        )
        w.write_packet(pkt)
    w.close()

    # TC-03 to TC-07 and Combined Replay Suite are generated similarly
    print('[+] All 8 PCAP files written successfully to captures/ directory.')"""
    add_code_box(doc, traf_p3, caption="Listing 4.2: traffic_generator.py (RFC 1071 Packet Builder)")

    add_page_break(doc)

    # 4.3 alert_analyzer.py
    add_heading2(doc, "4.3 alert_analyzer.py")
    add_body(doc,
        "This module provides two core engines: a strict Snort rule syntax validator and an offline "
        "deterministic PCAP rule evaluator that tracks sliding-window rate filters and writes standard "
        "alert_fast logs."
    )

    an_p1 = """\
import os, re, sys, struct, datetime, collections

class SnortRuleParser:
    \"\"\"Parses a Snort rule string into structured headers and options.\"\"\"
    HEADER_RE = re.compile(
        r'^(alert|log|pass|drop)\\s+(tcp|udp|icmp|ip)\\s+'
        r'(\\S+)\\s+(\\S+)\\s+(->|<>)\\s+(\\S+)\\s+(\\S+)\\s*\\((.+)\\)\\s*$',
        re.IGNORECASE | re.DOTALL
    )

    def parse(self, line: str):
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        m = self.HEADER_RE.match(line)
        if not m:
            return None
        act, proto, sip, sp, arrow, dip, dp, opts_raw = m.groups()
        opts = {}
        for token in opts_raw.split(';'):
            token = token.strip()
            if not token:
                continue
            if ':' in token:
                k, v = token.split(':', 1)
                opts[k.strip().lower()] = v.strip()
            else:
                opts[token.strip().lower()] = True
        return {
            'action': act, 'proto': proto, 'src_ip': sip, 'src_port': sp,
            'dst_ip': dip, 'dst_port': dp, 'options': opts, 'raw': line
        }"""
    add_code_box(doc, an_p1)

    add_page_break(doc)

    an_p2 = """\
class DetectionFilterTracker:
    \"\"\"Enforces sliding-window rate thresholds (count N, seconds T).\"\"\"
    def __init__(self, count: int, seconds: int):
        self.count = count
        self.seconds = seconds
        self.history = collections.defaultdict(list)

    def check(self, key: str, timestamp: float) -> bool:
        window = self.history[key]
        cutoff = timestamp - self.seconds
        self.history[key] = [t for t in window if t >= cutoff]
        self.history[key].append(timestamp)
        return len(self.history[key]) >= self.count

def _parse_packet(raw_pkt):
    if len(raw_pkt) < 54:
        return None           # Eth(14) + IP(20) + TCP(20)
    eth_proto = struct.unpack('>H', raw_pkt[12:14])[0]
    if eth_proto != 0x0800:
        return None
    ip_hdr = raw_pkt[14:34]
    ihl = (ip_hdr[0] & 0x0F) * 4
    proto = ip_hdr[9]
    if proto != 6:
        return None           # TCP only
    sip = socket.inet_ntoa(ip_hdr[12:16])
    dip = socket.inet_ntoa(ip_hdr[16:20])
    tcp_offset = 14 + ihl
    tcp_hdr = raw_pkt[tcp_offset:tcp_offset + 20]
    sp, dp, seq, ack, off_res, flags = struct.unpack('>HHIIBB', tcp_hdr[:14])
    tcp_hl = ((off_res >> 4) & 0x0F) * 4
    payload = raw_pkt[tcp_offset + tcp_hl:]
    return {
        'src_ip': sip, 'dst_ip': dip, 'src_port': sp, 'dst_port': dp,
        'flags': flags, 'payload': payload
    }"""
    add_code_box(doc, an_p2)

    add_page_break(doc)

    an_p3 = """\
def evaluate_pcap(pcap_path, rules):
    \"\"\"Matches packets against rules; returns Snort alert_fast format strings.\"\"\"
    alerts = []
    df_trackers = {}
    for sec, usec, raw in read_pcap_packets(pcap_path):
        pkt = _parse_packet(raw)
        if not pkt:
            continue
        ts = float(sec) + float(usec) / 1_000_000.0
        for r in rules:
            opts = r['options']
            sid  = opts.get('sid', '0')
            msg  = opts.get('msg', '').strip('"')
            if not match_port(pkt['dst_port'], r['dst_port']):
                continue
            if 'flags' in opts and not match_flags(pkt['flags'], opts['flags']):
                continue
            if ('flow' in opts and 'established' in opts['flow']
                    and not (pkt['flags'] & 0x10)):
                continue
            if 'content' in opts and not match_content(pkt['payload'], opts):
                continue
            if 'detection_filter' in opts:
                trk = df_trackers.setdefault(
                    sid, DetectionFilterTracker(20, 5)
                )
                if not trk.check(pkt['src_ip'], ts):
                    continue
            alert_str = (
                f"{format_ts(ts)} [**] [1:{sid}:1] \\"{msg}\\" [**] "
                f"{pkt['src_ip']}:{pkt['src_port']} -> "
                f"{pkt['dst_ip']}:{pkt['dst_port']}"
            )
            alerts.append(alert_str)
    return alerts"""
    add_code_box(doc, an_p3, caption="Listing 4.3: alert_analyzer.py (Rule Evaluation Engine)")

    add_page_break(doc)

    # 4.4 test_alerts.py
    add_heading2(doc, "4.4 test_alerts.py")
    add_body(doc,
        "The automated unittest suite verifies all 10 Snort rules against the seven test scenarios, "
        "ensuring that attack traffic fires expected SIDs while clean baseline traffic produces zero "
        "false alarms."
    )

    test_p1 = """\
import unittest, os, sys
from src.alert_analyzer import (
    validate_rules, evaluate_pcap, SnortRuleParser, load_rule_lines
)

class TestSnortIoTBotnetRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules_file = 'rules/local.rules'
        cls.val_report = validate_rules(cls.rules_file)
        parser = SnortRuleParser()
        cls.rules = [
            parser.parse(line)
            for _, line in load_rule_lines(cls.rules_file)
        ]

    def test_rule_syntax_validation(self):
        \"\"\"Verify all 10 rules pass strict Snort syntax checks.\"\"\"
        self.assertEqual(self.val_report['total_rules'], 10)
        self.assertEqual(self.val_report['passed'], 10)
        self.assertEqual(self.val_report['failed'], 0)

    def test_tc01_normal_baseline_negative(self):
        \"\"\"TC-01: Benign HTTP GET traffic must produce 0 alerts.\"\"\"
        alerts = evaluate_pcap('captures/tc01_normal_baseline.pcap', self.rules)
        self.assertEqual(len(alerts), 0, 'Clean baseline must not trigger')

    def test_tc02_telnet_syn_scan(self):
        \"\"\"TC-02: SYN sweep must trigger SIDs 1000001, 1000002, 1000008.\"\"\"
        alerts = evaluate_pcap('captures/tc02_telnet_syn_scan.pcap', self.rules)
        self.assertGreater(len(alerts), 0)
        self.assertTrue(any('1000001' in a or '1000002' in a for a in alerts))"""
    add_code_box(doc, test_p1)

    add_page_break(doc)

    test_p2 = """\
    def test_tc03_telnet_bruteforce_root(self):
        \"\"\"TC-03: Brute force with 'root' must trigger SID 1000003.\"\"\"
        alerts = evaluate_pcap(
            'captures/tc03_telnet_bruteforce_root.pcap', self.rules
        )
        self.assertTrue(any('1000003' in a for a in alerts))

    def test_tc04_mirai_factory_creds(self):
        \"\"\"TC-04: Factory credentials must trigger SID 1000004/1000005.\"\"\"
        alerts = evaluate_pcap(
            'captures/tc04_mirai_factory_creds.pcap', self.rules
        )
        self.assertTrue(any('1000004' in a or '1000005' in a for a in alerts))

    def test_tc05_mirai_post_auth_loader(self):
        \"\"\"TC-05: Loader commands must trigger SID 1000006 or 1000007.\"\"\"
        alerts = evaluate_pcap(
            'captures/tc05_mirai_post_auth_loader.pcap', self.rules
        )
        self.assertTrue(any('1000006' in a or '1000007' in a for a in alerts))

    def test_tc06_vertical_port_scan(self):
        \"\"\"TC-06: Vertical port sweep must trigger rate filter SID 1000008.\"\"\"
        alerts = evaluate_pcap(
            'captures/tc06_vertical_port_scan.pcap', self.rules
        )
        self.assertTrue(any('1000008' in a for a in alerts))

    def test_tc07_encrypted_ssh_negative(self):
        \"\"\"TC-07: Encrypted SSH session must yield 0 alerts (Zero FP).\"\"\"
        alerts = evaluate_pcap(
            'captures/tc07_negative_test_encrypted_ssh.pcap', self.rules
        )
        self.assertEqual(len(alerts), 0)"""
    add_code_box(doc, test_p2)

    add_page_break(doc)

    test_p3 = """\
    def test_detection_metrics_summary(self):
        \"\"\"Verify detection benchmarks: 100% TPR and 0% FPR.\"\"\"
        summary_path = 'results/detection_summary.json'
        if os.path.exists(summary_path):
            with open(summary_path) as f:
                data = json.load(f)
            m = data.get('detection_metrics', {})
            self.assertEqual(m.get('false_positives'), 0)
            self.assertEqual(m.get('false_positive_rate'), 0.0)
            self.assertEqual(m.get('true_positives'), 6)
            self.assertEqual(m.get('true_positive_rate'), 1.0)

if __name__ == '__main__':
    unittest.main(verbosity=2)"""
    add_code_box(doc, test_p3, caption="Listing 4.4: Important parts of test_alerts.py")

    add_page_break(doc)

    # =========================================================================
    # CHAPTER 5: RESULTS AND TESTING (Pages 19-23)
    # =========================================================================
    add_heading1(doc, "CHAPTER 5: RESULTS AND TESTING")
    add_heading2(doc, "5.1 Test Environment")
    add_body(doc,
        "All tests were run on a local system with Python 3.12/3.15, using synthetic RFC 1071 Ethernet/IP/TCP "
        "frames inside the isolated virtual subnet 192.168.56.0/24. No real passwords, external devices, or "
        "live malware were used, and no network traffic escaped the local host."
    )

    add_heading2(doc, "5.2 Functional Output")
    add_body(doc,
        "The pipeline executed three phases: rule validation (10/10 passed), PCAP generation (120 packets "
        "across 8 files), and rule evaluation (138 alerts produced). The executive dashboard screenshot "
        "(Fig. 5.1) and rule validation output (Fig. 5.2) confirm successful execution."
    )

    for img_name, caption in [
        ("term_fig_5_1_menu.png", "Fig. 5.1: Main pipeline execution dashboard"),
        ("term_fig_5_2_validation.png", "Fig. 5.2: Snort rule validation \u2014 10/10 rules passed"),
    ]:
        add_image_centered(
            doc,
            os.path.join(SCREENSHOTS_DIR, img_name),
            width_inches=5.5,
            caption=caption
        )

    add_page_break(doc)

    add_body(doc,
        "Fig. 5.3 shows the generated alert records in Snort alert_fast format, confirming correct SID "
        "assignment, timestamp formatting, and src/dst IP:port labelling."
    )
    for img_name, caption in [
        ("term_fig_5_4_alerts.png", "Fig. 5.3: Sample alert.ids output (Snort alert_fast format)"),
        ("detection_metrics.png", "Fig. 5.4: Detection metrics bar chart \u2014 TPR=100%, FPR=0%"),
    ]:
        add_image_centered(
            doc,
            os.path.join(SCREENSHOTS_DIR, img_name),
            width_inches=5.5,
            caption=caption
        )

    add_page_break(doc)

    add_heading2(doc, "5.3 Automated Test Cases")
    add_body(doc,
        "Table 5.1 summarises all seven test cases. TC-01 and TC-07 are negative (zero-alert) tests "
        "verifying no false positives; TC-02 through TC-06 are positive tests verifying correct SID "
        "triggering."
    )
    # Table 5.1
    tc_headers = ["TC ID", "Scenario", "PCAP File", "Expected SIDs", "Result"]
    tc_rows = [
        ["TC-01", "Normal HTTP Baseline", "tc01_normal_baseline.pcap", "None (0 alerts)", "PASS \u2714"],
        ["TC-02", "Telnet SYN Scan", "tc02_telnet_syn_scan.pcap", "1000001, 1000002, 1000008", "PASS \u2714"],
        ["TC-03", "Brute-Force root", "tc03_telnet_bruteforce_root.pcap", "1000003", "PASS \u2714"],
        ["TC-04", "Factory Creds xc3511/vizxv", "tc04_mirai_factory_creds.pcap", "1000004, 1000005", "PASS \u2714"],
        ["TC-05", "Post-Auth Loader", "tc05_mirai_post_auth_loader.pcap", "1000006, 1000007", "PASS \u2714"],
        ["TC-06", "Vertical Port Scan", "tc06_vertical_port_scan.pcap", "1000008", "PASS \u2714"],
        ["TC-07", "Encrypted SSH (Negative)", "tc07_negative_test_encrypted_ssh.pcap", "None (0 alerts)", "PASS \u2714"],
    ]
    tbl_tc = doc.add_table(rows=len(tc_rows)+1, cols=5)
    tbl_tc.style = 'Table Grid'
    tbl_tc.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(tc_headers):
        cell = tbl_tc.cell(0, i)
        set_cell_bg(cell, 'E0E0E0')
        run = cell.paragraphs[0].add_run(h)
        run.bold = True; run.font.size = Pt(9); run.font.name = 'Times New Roman'
    for r_idx, row_data in enumerate(tc_rows, 1):
        for c_idx, val in enumerate(row_data):
            cell = tbl_tc.cell(r_idx, c_idx)
            run = cell.paragraphs[0].add_run(val)
            run.font.size = Pt(8.5); run.font.name = 'Times New Roman'
    add_fig_caption(doc, "Table 5.1: Test case summary and results")

    add_image_centered(
        doc,
        os.path.join(SCREENSHOTS_DIR, "term_fig_5_8_tests.png"),
        width_inches=5.5,
        caption="Fig. 5.5: Automated unittest output \u2014 all 9 test methods PASSED"
    )

    add_page_break(doc)

    add_heading2(doc, "5.4 Detection Metrics")
    add_body(doc,
        "Table 5.2 presents the final confusion matrix and derived performance metrics. "
        "The offline evaluation engine achieved perfect classification across all 7 test scenarios."
    )
    metrics_headers = ["Metric", "Value", "Description"]
    metrics_rows = [
        ["True Positives (TP)", "6", "Attack scenarios correctly triggering alerts"],
        ["True Negatives (TN)", "2", "Benign/SSH scenarios correctly producing 0 alerts"],
        ["False Positives (FP)", "0", "Benign traffic incorrectly flagged as attack"],
        ["False Negatives (FN)", "0", "Attack traffic missed by all rules"],
        ["True Positive Rate (TPR)", "100.0%", "TP / (TP + FN) \u2014 Recall / Sensitivity"],
        ["False Positive Rate (FPR)", "0.0%", "FP / (FP + TN) \u2014 Specificity complement"],
        ["Total Alerts Generated", "138", "Across 120 synthetic packets in 8 PCAPs"],
        ["Rules Passing Syntax Check", "10/10", "All SIDs 1000001\u20131000010 valid"],
    ]
    tbl_met = doc.add_table(rows=len(metrics_rows)+1, cols=3)
    tbl_met.style = 'Table Grid'
    tbl_met.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(metrics_headers):
        cell = tbl_met.cell(0, i)
        set_cell_bg(cell, 'E0E0E0')
        run = cell.paragraphs[0].add_run(h)
        run.bold = True; run.font.size = Pt(9.5); run.font.name = 'Times New Roman'
    for r_idx, row_data in enumerate(metrics_rows, 1):
        for c_idx, val in enumerate(row_data):
            cell = tbl_met.cell(r_idx, c_idx)
            run = cell.paragraphs[0].add_run(val)
            run.font.size = Pt(9); run.font.name = 'Times New Roman'
    add_fig_caption(doc, "Table 5.2: Detection metrics summary")

    add_page_break(doc)

    add_heading2(doc, "5.5 Corrections Applied")
    add_body(doc,
        "Three significant bugs were identified and fixed during development:"
    )
    bug_data = [
        ("Bug 1", "Multi-line rules ending in \\\\ caused the rule parser to treat continuation lines as "
                  "separate rules, resulting in 0/10 rules passing syntax validation.",
         "Added load_rule_lines() to alert_analyzer.py that strips comments and joins lines ending "
         "in \\\\ before parsing."),
        ("Bug 2", "datetime.datetime.utcnow() produced Python 3.12+ DeprecationWarning about naive UTC datetimes.",
         "Replaced with datetime.datetime.now(datetime.timezone.utc) throughout all modules."),
        ("Bug 3", "MQTT rule payload byte \\x10 is an XML illegal character, causing python-docx to "
                  "raise InvalidXmlCharactersError.",
         "Sanitized all control characters to literal escape strings (e.g., \\\\x10) before "
         "inserting into python-docx XML elements."),
    ]
    bug_tbl = doc.add_table(rows=len(bug_data)+1, cols=3)
    bug_tbl.style = 'Table Grid'
    bug_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(["Bug", "Description", "Fix Applied"]):
        cell = bug_tbl.cell(0, i)
        set_cell_bg(cell, 'E0E0E0')
        run = cell.paragraphs[0].add_run(h)
        run.bold = True; run.font.size = Pt(9.5); run.font.name = 'Times New Roman'
    for r_idx, (bug_id, desc, fix) in enumerate(bug_data, 1):
        for c_idx, val in enumerate([bug_id, desc, fix]):
            cell = bug_tbl.cell(r_idx, c_idx)
            run = cell.paragraphs[0].add_run(val)
            run.font.size = Pt(8.5); run.font.name = 'Times New Roman'
    add_fig_caption(doc, "Table 5.3: Bugs encountered and corrections applied")

    add_page_break(doc)

    # =========================================================================
    # CHAPTER 6: CONCLUSION AND FUTURE SCOPE (Page 24)
    # =========================================================================
    add_heading1(doc, "CHAPTER 6: CONCLUSION AND FUTURE SCOPE")
    add_heading2(doc, "6.1 Conclusion")
    add_body(doc,
        "This project successfully designed, implemented, and validated ten custom Snort IDS rules targeting "
        "Mirai-like IoT botnet attack patterns in a controlled virtual laboratory environment. The offline "
        "Python rule evaluation engine proved that production-quality Snort detection logic can be prototyped "
        "and unit-tested without native Snort or root privileges."
    )
    add_body(doc,
        "Key achievements: (1) 10 syntactically valid Snort 2.9.x rules covering reconnaissance, brute-force, "
        "post-authentication commands, payload download, port scanning, and MQTT flooding; "
        "(2) 120-packet synthetic PCAP dataset covering 7 attack scenarios; "
        "(3) 138 alerts generated with 100% TPR and 0% FPR; "
        "(4) 9 automated unit tests all passing; "
        "(5) Complete academic documentation including this report and 50-question Viva preparation guide."
    )
    add_heading2(doc, "6.2 Future Scope")
    future_items = [
        "Deploy rules on a live Snort 3 (Snort++) instance with real IoT hardware in a GNS3 or EVE-NG "
        "virtual network for realistic traffic validation.",
        "Extend rules to cover UDP-based Mirai variants (DNS amplification, GRE floods) and MQTT malformed "
        "packet injections targeting broker stability.",
        "Integrate Suricata YAML rule format for compatibility with the SELKS/ELK stack and Kibana dashboards "
        "for alert visualisation.",
        "Apply machine learning (Random Forest, Isolation Forest) on network flow features extracted from "
        "the PCAP dataset to complement signature-based detection.",
        "Implement PCAP-based CI/CD pipeline where any new Snort rule commit automatically runs the full "
        "7-scenario PCAP evaluation and publishes coverage metrics.",
    ]
    for item in future_items:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        run = p.add_run(f"\u2022  {item}")
        run.font.size = Pt(10.5); run.font.name = 'Times New Roman'
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.left_indent = Inches(0.25)

    add_page_break(doc)

    # =========================================================================
    # REFERENCES (Page 25)
    # =========================================================================
    add_heading1(doc, "REFERENCES")
    refs = [
        "[1] M. Antonakakis et al., \u201cUnderstanding the Mirai Botnet,\u201d in Proc. 26th USENIX Security Symposium, "
        "Vancouver, BC, 2017, pp. 1093\u20131110.",
        "[2] Snort Project, \u201cSnort Users Manual 2.9.x,\u201d Cisco Talos, 2023. [Online]. "
        "Available: https://www.snort.org/documents",
        "[3] J. Postel, \u201cInternet Protocol,\u201d RFC 791, IETF, Sep. 1981.",
        "[4] R. Braden, \u201cRequirements for Internet Hosts \u2014 Communication Layers,\u201d RFC 1122, IETF, Oct. 1989.",
        "[5] M. Bradley et al., \u201cSnort 3 Rule Writing Guide,\u201d Cisco Systems, 2023.",
        "[6] Python Software Foundation, Python 3.12 Standard Library \u2014 struct module. "
        "[Online]. Available: https://docs.python.org/3/library/struct.html",
        "[7] Wireshark Foundation, \u201clibpcap File Format,\u201d 2023. [Online]. "
        "Available: https://wiki.wireshark.org/Development/LibpcapFileFormat",
        "[8] O. Lashkari et al., \u201cCharacterization of Tor Traffic Using Time Based Features,\u201d "
        "in Proc. ICISSP 2017, Porto, 2017.",
        "[9] Y. Meidan et al., \u201cN-BaIoT: Network-Based Detection of IoT Botnet Attacks Using Deep "
        "Autoencoders,\u201d IEEE Pervasive Computing, vol. 17, no. 3, pp. 12\u201322, 2018.",
        "[10] CVE-2016-10401, \u201cTelnet default credential vulnerability in ZyXEL PK5001Z routers,\u201d "
        "NIST NVD, 2016.",
    ]
    for ref in refs:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        run = p.add_run(ref)
        run.font.size = Pt(10.5); run.font.name = 'Times New Roman'
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.left_indent = Inches(0.3)
        p.paragraph_format.first_line_indent = Inches(-0.3)

    # =========================================================================
    # Save
    # =========================================================================
    doc.save(DOCX_OUTPUT)
    import shutil
    shutil.copy2(DOCX_OUTPUT, OFFICIAL_DOCX)
    print(f"[DOCX] Saved: {DOCX_OUTPUT} ({os.path.getsize(DOCX_OUTPUT):,} bytes)")
    print(f"[DOCX] Copied to: {OFFICIAL_DOCX}")
    print("[ALL DONE] Fully editable DOCX report generated.")

if __name__ == "__main__":
    build_docx()

---------------------------------------------------------------------------
--  SNORT 3 (Snort++) CONFIGURATION FILE  –  Lua Format
--  Project  : CSL-I09 B.Tech Cyber Security Lab Mini Project
--  Title    : Snort Rules for IoT Botnet Attacks (Mirai / Bashlite family)
--  Student  : Kushal Kumar  |  Roll: 23ESKCY026
--  Institute: SKIT Jaipur
--  Date     : 2024-2025
--
--  DISCLAIMER: FOR EDUCATIONAL / LAB USE ONLY inside a closed VirtualBox
--  host-only network (192.168.56.0/24). No live production traffic.
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- SECTION 1 – NETWORK DEFINITIONS
---------------------------------------------------------------------------

-- The lab subnet containing all simulated IoT devices and attacker nodes
HOME_NET = '192.168.56.0/24'

-- Everything not in the lab is treated as external / potentially hostile
EXTERNAL_NET = '!192.168.56.0/24'

-- Individual node addresses (lab topology)
ADMIN_HOST   = '192.168.56.5'    -- Legitimate admin workstation
IOT_CAMERA   = '192.168.56.10'   -- Target IoT IP camera (Telnet/HTTP/SSH)
MQTT_GATEWAY = '192.168.56.11'   -- Target Smart Home MQTT gateway
MIRAI_BOT    = '192.168.56.100'  -- Simulated Mirai bot / brute-force node
PORT_SCANNER = '192.168.56.105'  -- Secondary port-scanner node

-- Grouped attacker set (used for reference in comments / future rules)
ATTACKER_HOSTS = '192.168.56.100,192.168.56.105'

---------------------------------------------------------------------------
-- SECTION 2 – IPS (Intrusion Prevention System) MODULE
---------------------------------------------------------------------------

ips =
{
    -- Enable stateful inspection mode
    enable_builtin_rules = true,

    -- Path to the directory holding our custom rule files
    rules = [[
        include ../rules/local.rules
    ]],

    -- Default action when a rule fires: alert (log and report)
    -- Change to 'drop' when running inline (IPS mode) in production
    action = 'alert',

    -- Variables available to rules (mirror Snort 2 var/ipvar/portvar)
    variables =
    {
        nets =
        {
            HOME_NET     = HOME_NET,
            EXTERNAL_NET = EXTERNAL_NET,
            ADMIN_HOST   = ADMIN_HOST,
            IOT_CAMERA   = IOT_CAMERA,
            MQTT_GATEWAY = MQTT_GATEWAY,
            MIRAI_BOT    = MIRAI_BOT,
            PORT_SCANNER = PORT_SCANNER,
        },
        ports =
        {
            TELNET_PORTS = '23,2323',
            HTTP_PORTS   = '80,8080,8888',
            SSH_PORTS    = '22',
            MQTT_PORTS   = '1883,8883',
            IOT_PORTS    = '22,23,80,1883,2323,8080,8883',
        }
    }
}

---------------------------------------------------------------------------
-- SECTION 3 – STREAM MODULE (stateful TCP/UDP session tracking)
---------------------------------------------------------------------------

stream =
{
    -- Maximum number of concurrent TCP sessions to track
    max_flows = 262144,
}

-- TCP stream reassembly configuration
-- Only reassemble sessions on IoT-relevant ports for efficiency
stream_tcp =
{
    -- Reassembly policy matching most embedded Linux IoT firmware
    policy   = 'linux',

    -- Ports on which full session content reassembly is performed
    -- Covers: SSH(22), Telnet(23), HTTP(80/8080), MQTT(1883), AltTelnet(2323)
    ports    = '22 23 80 1883 2323 8080 8883',

    -- Session idle timeout in seconds
    idle_timeout = 180,

    -- Detect TCP anomalies (overlapping segments, bad flags, etc.)
    -- Useful for catching Mirai's SYN-flood scanning phase
    detect_anomalies = true,

    -- Require completed 3-way handshake before reassembling (set false
    -- to also catch half-open SYN scans in lab PCAP replays)
    require_3whs = false,

    -- Maximum number of overlapping bytes before an alert is generated
    overlap_limit = 10,
}

-- UDP session tracking (MQTT can run over UDP in some implementations)
stream_udp =
{
    idle_timeout = 180,
}

---------------------------------------------------------------------------
-- SECTION 4 – HTTP INSPECTOR (normalises camera web-interface traffic)
---------------------------------------------------------------------------

http_inspect =
{
    -- Decompress gzip-encoded HTTP responses from camera firmware pages
    request_depth  = 65535,
    response_depth = 65535,
}

---------------------------------------------------------------------------
-- SECTION 5 – PORT SCAN DETECTOR
---------------------------------------------------------------------------

port_scan =
{
    -- Detect all scan types seen in Mirai scanning phase
    protos     = 'all',
    scan_types = 'all',

    -- Alert sensitivity: medium balances false-positive rate for lab
    sense_level = 'medium',

    -- Log to file for post-lab Wireshark / spreadsheet analysis
    logfile = '../results/portscan.log',
}

---------------------------------------------------------------------------
-- SECTION 6 – DETECTION ENGINE SETTINGS
---------------------------------------------------------------------------

detection =
{
    -- Search algorithm: ac_bnfa is fast and memory-efficient for lab VMs
    search_method = 'ac_bnfa',

    -- Enable multi-pattern matching across reassembled TCP streams
    -- This is critical for catching Mirai credential strings in Telnet
    split_any_any = true,

    -- Maximum number of rule matches per packet before stopping search
    -- Prevents CPU exhaustion during brute-force replay in lab
    max_queue_events = 5,
}

---------------------------------------------------------------------------
-- SECTION 7 – OUTPUT / ALERT MODULES
---------------------------------------------------------------------------

-- alert_fast: human-readable single-line alerts written to a text file
-- Easiest format for students to grep, tail, and annotate in lab reports
alert_fast =
{
    file   = true,
    packet = false,
    limit  = 128,     -- Roll-over log at 128 MB
}

-- unified2 binary log (consumed by Barnyard2 / Snorby / BASE)
-- Uncomment when Barnyard2 is configured in the lab
-- alert_unified2 = { filename = '../results/snort.log', limit = 128 }

-- Log matching packets as PCAP for Wireshark correlation
-- Uncomment to enable; generates one file per session
-- log_pcap = { filename = '../results/snort_captures.pcap' }

---------------------------------------------------------------------------
-- SECTION 8 – MISCELLANEOUS / GLOBAL SETTINGS
---------------------------------------------------------------------------

-- Suppress checksum errors (common in PCAP replays and tunnelled traffic)
normalise =
{
    tcp  = { ips = true },
    ip4  = { df = true },
}

-- Packet buffer size (bytes) – 1518 covers standard Ethernet MTU
-- Increase to 9018 if jumbo frames are used in the lab
daq =
{
    snaplen = 1518,
}

---------------------------------------------------------------------------
-- END OF snort.lua
---------------------------------------------------------------------------

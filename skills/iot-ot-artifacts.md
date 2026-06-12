---
name: iot-ot-artifacts
description: IoT and OT/ICS forensic triage — firmware analysis, industrial protocol capture, and when to invoke Daedalus for unknown devices
---

# IoT and OT/ICS Forensic Artifacts

IoT and OT investigations differ from Windows/Linux IR in one fundamental way:
**the device may have no logs, no standard filesystem, and no forensic tool with
native support.** This skill covers what to try with known tools and when the
evidence warrants invoking Daedalus for tool discovery.

---

## Classify the evidence type first

Before doing anything, identify what you actually have. IoT/OT evidence falls into
four categories:

| Evidence type | What it is | Primary tools |
|---|---|---|
| **Firmware blob** | Binary image extracted from flash storage | `binwalk`, `strings`, `file`, `entropy` analysis |
| **Industrial protocol capture** | PCAP/PCAPNG of Modbus, DNP3, EtherNet/IP, PROFINET, BACnet | `tshark` with industrial dissectors |
| **Device log export** | Syslog/text logs exported from a PLC, historian, or gateway | `grep`, `awk`, text parsing |
| **Database export** | SCADA historian, HMI database (OSIsoft PI, Wonderware, InfluxDB) | `sqlite3`, vendor-specific tools |

Classify before starting any analysis. The approach is completely different for each.

---

## Firmware blob analysis

### Step 1 — Identify the firmware format

```bash
file firmware.bin
binwalk firmware.bin           # signature scan — identifies embedded filesystems
strings -n 10 firmware.bin | head -50   # quick recon
hexdump -C firmware.bin | head -20     # check magic bytes / header
```

**binwalk output interpretation:**

| Signature found | Meaning |
|---|---|
| `squashfs` | Compressed filesystem — extract with binwalk `-e` |
| `JFFS2` | Flash filesystem — common in routers/embedded Linux |
| `UBI` | NAND flash filesystem — use `ubireader` |
| `gzip/lzma/xz` | Compressed section — decompress and re-analyze |
| `ELF` | Executable — analyze with `strings`, `readelf`, `ghidra` |
| `uImage` header | U-Boot image — strip 64-byte header then analyze payload |
| Nothing | Encrypted firmware, custom format — invoke Daedalus |

### Step 2 — Extract filesystem

```bash
# Automatic extraction (tries all known formats)
binwalk -e --run-as=root firmware.bin
ls _firmware.bin.extracted/

# Manual squashfs extraction
unsquashfs -d /output/squashfs/ firmware.squashfs

# JFFS2
modprobe jffs2 mtdram mtdblock
dd if=firmware.jffs2 of=/dev/mtdblock0
mount -t jffs2 /dev/mtdblock0 /mnt/jffs2/
```

### Step 3 — Analyze extracted filesystem

Once extracted, treat as a minimal Linux filesystem. The commands below pull
relevant material together; the analysis is reading each file and reasoning
about what role it plays in the device.

```bash
# Startup paths — read each, follow what they exec, and map the boot sequence
cat /etc/init.d/*
cat /etc/rc.local
cat /etc/inittab

# Configuration files likely to carry secrets — read the candidates
grep -r "password\|passwd\|admin\|root\|default" /output/ --include="*.conf" --include="*.xml" --include="*.json" -i

# Executables — review with strings, then disassemble the interesting ones
find /output/ -type f -executable | xargs strings -n 8 2>/dev/null | head -200

# Web interface source — open each entry point and evaluate authentication,
# input handling, and any command-execution sinks
find /output/ -name "*.html" -o -name "*.php" -o -name "*.cgi" | head -20
```

Reading hardcoded credentials, embedded URLs, or hardcoded IP ranges is
common in IoT firmware; the value of each finding depends on whether the
credential is reachable on a production device, whether the URL points to
a still-live C2 or vendor service, and how the device uses each value.

### Entropy analysis (detecting encryption/packing)

```bash
binwalk -E firmware.bin   # plots entropy — high uniform entropy = encrypted/compressed
```

Sections with entropy > 7.8 are likely encrypted. If the entire firmware is
high-entropy, document this and invoke Daedalus to research the vendor's encryption
scheme before attempting deeper analysis.

---

## Industrial protocol PCAP analysis

### Identify protocols present

```bash
tshark -r capture.pcap -q -z io,phs 2>/dev/null | head -40
```

### Protocol-specific extraction

**Modbus TCP (port 502)**
```bash
# List all Modbus transactions
tshark -r capture.pcap -Y "modbus" -T fields \
    -e frame.time -e ip.src -e ip.dst \
    -e modbus.func_code -e modbus.reference_num -e modbus.word_cnt 2>/dev/null
```

**DNP3 (port 20000)**
```bash
tshark -r capture.pcap -Y "dnp3" -T fields \
    -e frame.time -e ip.src -e dnp3.ctl.dir -e dnp3.al.func \
    -e dnp3.al.obj.class 2>/dev/null
```

**EtherNet/IP / CIP (port 44818)**
```bash
tshark -r capture.pcap -Y "enip or cip" -T fields \
    -e frame.time -e ip.src -e ip.dst -e cip.service 2>/dev/null
```

**BACnet (port 47808 UDP)**
```bash
tshark -r capture.pcap -Y "bacnet" -T fields \
    -e frame.time -e ip.src -e bacnet.apdu.type \
    -e bacnet.prop.object_identifier 2>/dev/null
```

### Reading OT traffic

After extracting flows and per-protocol records with tshark, evaluate each
pattern against the plant's documented control philosophy and the
engineering team's baseline of expected traffic. There is no universal
"bad function code" — a write to a coil is the entire point of the protocol
when it comes from the right HMI. The questions to ask of each observation:

- Which device originated the write? Is its IP in the engineering inventory?
  Was it authorised to program this PLC at this time, under change control?
- What did the write change? Does the new value lie inside the safe operating
  range the process owner defined?
- How does the timing compare to normal operator pacing? Burst writes at
  millisecond cadence are consistent with automation, not a human at an HMI.
- Are discovery or enumeration packets present that have no business in a
  production segment (broadcast `ListIdentity`, ARP sweeps, port scans)?
- Does the traffic correlate in time with IT-side incident artifacts
  (Windows EVTX, VPN logs, jump-server access)?

Bring each candidate finding to a control engineer for validation before
calling it malicious — OT environments routinely include test traffic,
diagnostics, and vendor maintenance that look anomalous without context.

### OT network topology reconstruction

```bash
# All unique src→dst pairs with protocol
tshark -r capture.pcap -q -z conv,ip 2>/dev/null | head -30

# Devices by IP (helps identify PLCs vs HMIs vs historians)
tshark -r capture.pcap -T fields -e ip.src 2>/dev/null | sort -u
```

---

## SCADA / Historian database artifacts

If you receive a database export from a historian or HMI:

**SQLite databases** (many smaller SCADA systems, HMI logs):
```bash
sqlite3 historian.db ".tables"
sqlite3 historian.db ".schema"
sqlite3 historian.db "SELECT * FROM events ORDER BY timestamp DESC LIMIT 100;"
```

**CSV/text exports from OSIsoft PI, Wonderware, GE iFIX:**
These are typically time-series exports. Key questions:
- Were any setpoints changed? (compare current values to baseline)
- Were alarms acknowledged without operator action?
- Were any values written outside normal operating range?

---

## When to invoke Daedalus

Invoke `/daedalus` when:

- `binwalk` finds no signatures and entropy analysis shows the firmware is not
  encrypted (i.e., it's a genuinely unknown format)
- `tshark` shows a protocol that displays as "data" or "TCP/UDP" with no dissector
- The device is a specific industrial vendor product (Siemens S7, Allen-Bradley,
  Schneider Modicon) and you need vendor-specific tools
- The evidence is a `.pcap` with a protocol on an unusual port that tshark doesn't
  automatically identify

**For Siemens S7 (port 102 / ISO-TSAP):**
```bash
# tshark has S7comm dissector built-in but needs the plugin
tshark -r capture.pcap -Y "s7comm" -T fields \
    -e s7comm.param.func -e s7comm.data.mem.area 2>/dev/null
# If this returns nothing, invoke Daedalus to find S7 analysis tools
```

**For unknown serial protocols converted to PCAP:**
The payload will be raw bytes with no tshark dissector. Invoke Daedalus with
the device make/model and protocol name if known.

---

## OT incident triage checklist

- [ ] Classify evidence type (firmware / PCAP / log export / database)
- [ ] For firmware: `binwalk` scan + entropy — encrypted or extractable?
- [ ] For PCAP: `tshark -z io,phs` — what protocols are present?
- [ ] Identify all devices by IP and protocol role (PLC, HMI, historian, EWS)
- [ ] Flag any IP not in the expected network topology
- [ ] For Modbus/DNP3: extract write commands — what values were set, when, from where?
- [ ] For firmware: extract filesystem and check for hardcoded credentials + startup scripts
- [ ] For logs: parse timestamps to UTC, build timeline, identify anomalous events
- [ ] Flag any engineering workstation connection to a PLC outside normal change windows
- [ ] Document what tools were available and what couldn't be parsed — invoke Daedalus for gaps

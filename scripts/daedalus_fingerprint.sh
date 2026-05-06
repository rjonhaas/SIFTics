#!/usr/bin/env bash
# DAEDALUS:HANDLES *(meta — this script performs artifact discovery, not analysis)*
# daedalus_fingerprint.sh — Daedalus Phase D1: Artifact Fingerprinting
#
# Probes mounted evidence for every known artifact class and writes a manifest
# to stdout (one line per class).  Read-only — never modifies evidence.
#
# Usage:
#   bash daedalus_fingerprint.sh <CASE_ROOT> [MNT_POINT] [IMAGE_PATH]
#
#   CASE_ROOT   : /cases/<case_name>
#   MNT_POINT   : root of mounted disk image (e.g. /mnt/evidence).
#                 Auto-detected from /mnt/evidence or /mnt/ewf_mount/ewf1 if omitted.
#   IMAGE_PATH  : raw/EWF image path for partition table probing (optional).
#                 Used only for linux_ext_partition and linux_lvm detection.
#
# Output format (tab-separated):
#   PRESENT  <class>  <count> file(s)  <sample_path>
#   ABSENT   <class>  —
#   SKIP     <class>  <reason>
#
# The ISC / Daedalus SKILL.md reads this output and builds the run plan.

set -uo pipefail

# ─── args ───────────────────────────────────────────────────────────────────

CASE_ROOT="${1:-${CASE_ROOT:-}}"
MNT="${2:-}"
IMAGE_PATH="${3:-}"

[[ -n "$CASE_ROOT" && -d "$CASE_ROOT" ]] || {
    echo "Usage: $0 <CASE_ROOT> [MNT_POINT] [IMAGE_PATH]" >&2
    exit 1
}

# Auto-detect mount point
if [[ -z "$MNT" ]]; then
    for candidate in /mnt/evidence /mnt/ewf_mount/ewf1 /mnt/kape /mnt/disk; do
        if [[ -d "$candidate" && "$(ls -A "$candidate" 2>/dev/null)" ]]; then
            MNT="$candidate"
            break
        fi
    done
fi

# Auto-detect image path
if [[ -z "$IMAGE_PATH" ]]; then
    IMAGE_PATH=$(find "$CASE_ROOT" -maxdepth 3 \
        \( -name "*.E01" -o -name "*.e01" -o -name "*.raw" -o -name "*.img" \) \
        ! -path "*/analysis/*" ! -path "*/exports/*" | head -1)
fi

# ─── output helpers ─────────────────────────────────────────────────────────

present() {
    local class="$1" count="$2" sample="$3"
    printf "PRESENT\t%-35s\t%s file(s)\t%s\n" "$class" "$count" "$sample"
}

absent() {
    local class="$1"
    printf "ABSENT\t%-35s\t—\n" "$class"
}

skip() {
    local class="$1" reason="$2"
    printf "SKIP\t%-35s\t%s\n" "$class" "$reason"
}

probe() {
    # probe <class> <find_command_with_args...>
    # Runs the find, counts results, emits PRESENT or ABSENT
    local class="$1"; shift
    if [[ -z "$MNT" ]]; then
        skip "$class" "no mount point"
        return
    fi
    local result
    result=$(eval "$@" 2>/dev/null | head -5)
    if [[ -n "$result" ]]; then
        local count
        count=$(eval "$@" 2>/dev/null | wc -l)
        local sample
        sample=$(echo "$result" | head -1)
        present "$class" "$count" "$sample"
    else
        absent "$class"
    fi
}

# ─── header ─────────────────────────────────────────────────────────────────

echo "# Daedalus Artifact Manifest"
echo "# Generated : $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "# Case root : $CASE_ROOT"
echo "# Mount pt  : ${MNT:-<not mounted>}"
echo "# Image     : ${IMAGE_PATH:-<not found>}"
echo "#"
echo "# STATUS  ARTIFACT_CLASS                      COUNT         SAMPLE_PATH"
echo "# ─────────────────────────────────────────────────────────────────────────"

# ─── Windows Filesystem & System ────────────────────────────────────────────

echo ""
echo "# ── Windows Filesystem & System ──"

probe win_evtx \
    "find '$MNT' -path '*/winevt/Logs/*.evtx' 2>/dev/null"

probe win_registry \
    "find '$MNT' -path '*/System32/config/SYSTEM' 2>/dev/null"

probe win_mft \
    "find '$MNT' -name '\$MFT' 2>/dev/null"

probe win_prefetch \
    "find '$MNT' -path '*/Windows/Prefetch/*.pf' 2>/dev/null"

probe win_lnk \
    "find '$MNT' -name '*.lnk' -path '*/Recent/*' 2>/dev/null"

probe win_jumplist \
    "find '$MNT' -name '*.automaticDestinations-ms' 2>/dev/null"

probe win_shellbags \
    "find '$MNT' -name 'UsrClass.dat' 2>/dev/null"

probe win_recyclebin \
    "find '$MNT' -path '*RECYCLE.BIN*' -name '\$I*' 2>/dev/null"

probe win_sched_tasks \
    "find '$MNT' -path '*/System32/Tasks/*' ! -type d 2>/dev/null"

probe win_ps_history \
    "find '$MNT' -name 'ConsoleHost_history.txt' 2>/dev/null"

probe win_amcache \
    "find '$MNT' -name 'Amcache.hve' 2>/dev/null"

probe win_wmi_repo \
    "find '$MNT' -name 'OBJECTS.DATA' -path '*/wbem/Repository/*' 2>/dev/null"

probe win_srum \
    "find '$MNT' -name 'SRUDB.dat' 2>/dev/null"

probe win_ntds \
    "find '$MNT' -name 'ntds.dit' 2>/dev/null"

probe win_thumbcache \
    "find '$MNT' -name 'thumbcache_*.db' 2>/dev/null"

probe win_hiberfil \
    "find '$MNT' -maxdepth 2 -name 'hiberfil.sys' 2>/dev/null"

probe win_pagefile \
    "find '$MNT' -maxdepth 2 -name 'pagefile.sys' 2>/dev/null"

# ─── Browser & User Activity ────────────────────────────────────────────────

echo ""
echo "# ── Browser & User Activity ──"

probe browser_chrome \
    "find '$MNT' -path '*/Google/Chrome/User Data/*/History' 2>/dev/null"

probe browser_edge \
    "find '$MNT' -path '*/Microsoft/Edge/User Data/*/History' 2>/dev/null"

probe browser_firefox \
    "find '$MNT' -path '*/Firefox/Profiles/*/places.sqlite' 2>/dev/null"

probe browser_ie_legacy \
    "find '$MNT' -name 'WebCacheV01.dat' 2>/dev/null"

# ─── Email & Messaging ──────────────────────────────────────────────────────

echo ""
echo "# ── Email & Messaging ──"

probe email_ost \
    "find '$MNT' -name '*.ost' 2>/dev/null"

probe email_pst \
    "find '$MNT' -name '*.pst' 2>/dev/null"

probe email_mbox \
    "find '$MNT' \( -name '*.mbox' -o -name '*.mbx' \) 2>/dev/null"

probe email_eml \
    "find '$MNT' -name '*.eml' 2>/dev/null"

probe email_thunderbird \
    "find '$MNT' -path '*/Thunderbird/Profiles/*' -name '*.msf' 2>/dev/null"

probe slack_workspace \
    "find '$MNT' -path '*/Slack/storage/*.db' 2>/dev/null"

probe teams_db \
    "find '$MNT' -path '*/Microsoft/Teams/databases/*.db' 2>/dev/null"

# ─── Web & Application Server Logs ──────────────────────────────────────────

echo ""
echo "# ── Web & Application Server Logs ──"

probe log_iis \
    "find '$MNT' -path '*/LogFiles/W3SVC*/*.log' 2>/dev/null"

probe log_iis_httperr \
    "find '$MNT' -path '*/HTTPERR/*.log' 2>/dev/null"

probe log_apache \
    "find '$MNT' \( -name 'access.log' -o -name 'access_log' \) -path '*/apache*' 2>/dev/null"

probe log_nginx \
    "find '$MNT' \( -name 'access.log' -o -name 'access_log' \) -path '*/nginx*' 2>/dev/null"

probe log_tomcat \
    "find '$MNT' -name 'localhost_access_log*.txt' 2>/dev/null"

# HFS does not generate W3C logs — detect by binary presence only
probe log_hfs \
    "find '$MNT' -iname 'hfs.exe' -o -iname 'hfs.ini' 2>/dev/null"

# ─── Linux Partitions ───────────────────────────────────────────────────────

echo ""
echo "# ── Linux Partitions ──"

if [[ -n "$IMAGE_PATH" ]] && command -v mmls &>/dev/null; then
    linux_part=$(mmls "$IMAGE_PATH" 2>/dev/null \
        | awk '$4=="83" || $4=="8E" || tolower($0)~/linux/' | head -3)
    if [[ -n "$linux_part" ]]; then
        count=$(echo "$linux_part" | wc -l)
        sample=$(echo "$linux_part" | head -1 | awk '{print "offset sector="$3}')
        present "linux_ext_partition" "$count" "$sample"
    else
        absent "linux_ext_partition"
    fi

    lvm_part=$(mmls "$IMAGE_PATH" 2>/dev/null \
        | awk '$4=="8E" || tolower($0)~/lvm/' | head -3)
    if [[ -n "$lvm_part" ]]; then
        present "linux_lvm" "$(echo "$lvm_part" | wc -l)" "$(echo "$lvm_part" | head -1)"
    else
        absent "linux_lvm"
    fi
else
    skip "linux_ext_partition" "no IMAGE_PATH or mmls not available"
    skip "linux_lvm"           "no IMAGE_PATH or mmls not available"
fi

# If a Linux partition is already mounted, probe it for sub-artifacts
LINUX_MNT="${LINUX_MNT:-/mnt/linux_mount}"
if [[ -d "$LINUX_MNT" && "$(ls -A "$LINUX_MNT" 2>/dev/null)" ]]; then
    probe linux_bash_history \
        "find '$LINUX_MNT' -name '.bash_history' 2>/dev/null"
    probe linux_auth_log \
        "find '$LINUX_MNT' \( -name 'auth.log' -o -name 'secure' \) -path '*/log/*' 2>/dev/null"
    probe linux_cron \
        "find '$LINUX_MNT' -path '*/cron*' -type f 2>/dev/null"
    probe linux_systemd_journal \
        "find '$LINUX_MNT' -name '*.journal' -path '*/systemd/journal/*' 2>/dev/null"
    probe linux_docker_layers \
        "find '$LINUX_MNT' -path '*/docker/overlay2/*/diff' -type d 2>/dev/null"
    probe linux_ssh_keys \
        "find '$LINUX_MNT' \( -name 'authorized_keys' -o -name 'id_rsa' \) 2>/dev/null"
else
    skip "linux_bash_history"       "Linux partition not mounted (run run_linux.sh first)"
    skip "linux_auth_log"           "Linux partition not mounted"
    skip "linux_cron"               "Linux partition not mounted"
    skip "linux_systemd_journal"    "Linux partition not mounted"
    skip "linux_docker_layers"      "Linux partition not mounted"
    skip "linux_ssh_keys"           "Linux partition not mounted"
fi

# ─── Memory ─────────────────────────────────────────────────────────────────

echo ""
echo "# ── Memory Artifacts ──"

probe memory_raw \
    "find '$CASE_ROOT' \( -name '*.mem' -o -name '*.raw' -o -name '*.vmem' \) ! -path '*/analysis/*' 2>/dev/null"

probe memory_dump \
    "find '$CASE_ROOT' -name '*.dmp' ! -path '*/analysis/*' ! -path '*/exports/*' 2>/dev/null"

probe memory_hiberfil \
    "find '${MNT:-/nonexistent}' -maxdepth 2 -name 'hiberfil.sys' 2>/dev/null"

probe memory_pagefile \
    "find '${MNT:-/nonexistent}' -maxdepth 2 -name 'pagefile.sys' 2>/dev/null"

# ─── Network ────────────────────────────────────────────────────────────────

echo ""
echo "# ── Network Captures ──"

probe pcap \
    "find '$CASE_ROOT' \( -name '*.pcap' -o -name '*.pcapng' \) ! -path '*/analysis/*' 2>/dev/null"

probe zeek_logs \
    "find '$CASE_ROOT' -name 'conn.log' 2>/dev/null"

probe netflow_nfcapd \
    "find '$CASE_ROOT' -name 'nfcapd.*' 2>/dev/null"

# ─── Database & Specialized Windows ─────────────────────────────────────────

echo ""
echo "# ── Database & Specialized ──"

probe sqlite_generic \
    "find '${MNT:-/nonexistent}' \( -name '*.sqlite' -o -name '*.sqlite3' \) 2>/dev/null"

probe ese_database \
    "find '${MNT:-/nonexistent}' \( -name '*.edb' \) ! -name 'ntds.dit' 2>/dev/null"

# ─── Cloud & EDR Collections ────────────────────────────────────────────────

echo ""
echo "# ── Cloud & EDR Collections ──"

probe aws_cloudtrail \
    "find '$CASE_ROOT' \( -name '*.json.gz' -o -name '*.json' \) -path '*cloudtrail*' 2>/dev/null"

probe aws_guardduty \
    "find '$CASE_ROOT' -name '*.json' -path '*guardduty*' 2>/dev/null"

# Velociraptor ZIP: check for Windows.KapeFiles evidence inside ZIP
velo_zip=$(find "$CASE_ROOT" -name "*.zip" ! -path "*/analysis/*" 2>/dev/null | head -1)
if [[ -n "$velo_zip" ]]; then
    if unzip -l "$velo_zip" 2>/dev/null | grep -q "Windows.KapeFiles\|Generic.Collectors\|velociraptor"; then
        present "velociraptor_zip" "1" "$velo_zip"
    else
        absent "velociraptor_zip"
    fi
else
    absent "velociraptor_zip"
fi

# ─── Disk Images (for ISC scope awareness) ───────────────────────────────────

echo ""
echo "# ── Disk Images ──"

probe disk_e01 \
    "find '$CASE_ROOT' \( -name '*.E01' -o -name '*.e01' \) ! -path '*/analysis/*' 2>/dev/null"

probe disk_vmdk \
    "find '$CASE_ROOT' -name '*.vmdk' ! -path '*/analysis/*' 2>/dev/null"

probe disk_raw_img \
    "find '$CASE_ROOT' \( -name '*.img' -o -name '*.dd' \) ! -path '*/analysis/*' ! -name '*.raw' 2>/dev/null"

# ─── Summary ────────────────────────────────────────────────────────────────

echo ""
echo "# ── Summary ──"

# Count present vs absent (read back our own output is not possible mid-pipe,
# so we re-run a quick tally instead)
echo "# Run: grep '^PRESENT' <manifest> | wc -l   to count present classes"
echo "# Run: grep '^ABSENT'  <manifest> | wc -l   to count absent classes"
echo "# Run: grep '^PRESENT' <manifest> | awk '{print \$2}' to list classes for handler matching"

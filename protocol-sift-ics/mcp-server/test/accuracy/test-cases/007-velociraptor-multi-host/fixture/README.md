# Fixture Generation — Case 007: Velociraptor Multi-Host

This case requires three evidence sources:

1. `Collection-MAC-DESIGNER-2026-04-22.zip` — Velociraptor Offline Collector output from a macOS host
2. `Collection-WIN-MARKETING-2026-04-22.zip` — Velociraptor Offline Collector output from a Windows host
3. `WIN-MARKETING.raw` — WinPMEM memory capture from the Windows host (acquired BEFORE the Velociraptor collection so process state is preserved)

## Mac Collection (`MAC-DESIGNER`)

### VM setup

- macOS 14.x in UTM (or any virtualization that runs macOS — Apple Silicon native preferred for realism, Intel macOS in UTM acceptable)
- Single user `dmartin` with home `/Users/dmartin`
- Safari + Chrome installed
- No EDR / endpoint protection

### Plant the artifacts

```bash
# 1. Plant the impostor binary in a hidden Application Support subdirectory
mkdir -p "/Users/dmartin/Library/Application Support/.afh"
cat > "/Users/dmartin/Library/Application Support/.afh/helper" <<'EOF'
#!/bin/bash
# Stub — would be a Mach-O in a real attack. For fixture purposes a script
# is fine because only the path/persistence chain is being tested.
while true; do
  curl -s "https://update.adobefonts-cdn.example.invalid/beacon" >/dev/null 2>&1 || true
  sleep 60
done
EOF
chmod +x "/Users/dmartin/Library/Application Support/.afh/helper"

# 2. Create the LaunchAgent plist
mkdir -p /Users/dmartin/Library/LaunchAgents
cat > /Users/dmartin/Library/LaunchAgents/com.adobe.fonts.helper.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.adobe.fonts.helper</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/dmartin/Library/Application Support/.afh/helper</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
EOF

# 3. Load it (this generates the launchd Unified Log entries)
launchctl load /Users/dmartin/Library/LaunchAgents/com.adobe.fonts.helper.plist

# 4. Generate browser history — visit the C2 domain in Safari + Chrome
open -a Safari "https://update.adobefonts-cdn.example.invalid/"
sleep 5
open -a "Google Chrome" "https://update.adobefonts-cdn.example.invalid/"
sleep 5

# 5. Open Terminal a few minutes after the LaunchAgent fires (KnowledgeC focus event)
sleep 360
open -a Terminal

# 6. Wait at least 15 minutes so KnowledgeC accumulates focus data and
#    Unified Log captures the launchd spawn events.
```

### Run the Velociraptor Offline Collector

Build a custom collector with:

```yaml
artifacts:
  - MacOS.System.Persistence
  - MacOS.UnifiedLogs.Search
  - MacOS.System.KnowledgeC
  - MacOS.System.Users
  - MacOS.Applications.Safari.History
  - MacOS.Applications.Chrome.History
  - Generic.System.FileFinder
parameters:
  - artifact: MacOS.UnifiedLogs.Search
    parameters:
      - name: predicate
        value: 'subsystem == "com.apple.xpc.launchd" OR process == "helper"'
      - name: hours
        value: 24
  - artifact: Generic.System.FileFinder
    parameters:
      - name: SearchFilesGlob
        value: |
          /Users/dmartin/Library/LaunchAgents/*.plist
          /Users/dmartin/Library/Application Support/.afh/**
      - name: Calculate_Hash
        value: Y
```

Run as `dmartin` (or with sudo for system-scoped artifacts), then move the output zip into `fixture/` as `Collection-MAC-DESIGNER-2026-04-22.zip`.

## Windows Collection (`WIN-MARKETING`)

### VM setup

- Windows 10 22H2 (build 19045) in any hypervisor
- Single user account, Edge + Chrome installed
- Defender Off (or exclude `C:\ProgramData\AdobeFonts\`)
- Snapshot before planting so you can re-run the fixture build

### Plant the artifacts

```powershell
# 1. Plant the impostor binary
New-Item -Path "C:\ProgramData\AdobeFonts" -ItemType Directory -Force | Out-Null
@'
$ErrorActionPreference = "SilentlyContinue"
while ($true) {
  Invoke-WebRequest -Uri "https://update.adobefonts-cdn.example.invalid/beacon" -UseBasicParsing | Out-Null
  Start-Sleep -Seconds 60
}
'@ | Out-File -Encoding ASCII "C:\ProgramData\AdobeFonts\helper.ps1"

# Wrap as an exe (use ps2exe or sign as a self-contained .NET app for realism).
# For fixture purposes a small C# stub or a renamed powershell.exe + .ps1 launcher is acceptable.

# 2. Create the scheduled task
$action = New-ScheduledTaskAction -Execute "C:\ProgramData\AdobeFonts\helper.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal
Register-ScheduledTask -TaskName "AdobeFontsHelper" -InputObject $task

# 3. Run the helper now so it shows up in memory
Start-Process "C:\ProgramData\AdobeFonts\helper.exe"

# 4. Generate browser history
Start-Process "msedge.exe" "https://update.adobefonts-cdn.example.invalid/"
Start-Sleep -Seconds 5
Start-Process "chrome.exe" "https://update.adobefonts-cdn.example.invalid/"

# 5. Wait long enough for the task to log a fire and the helper to make
#    network connections (15+ minutes recommended)
```

### Acquire memory FIRST

```powershell
# Memory must be captured BEFORE Velociraptor runs, otherwise the
# helper's process state may have changed.
.\winpmem.exe -o C:\evidence\WIN-MARKETING.raw
```

Move `WIN-MARKETING.raw` into `fixture/`.

### Run the Velociraptor Offline Collector

```yaml
artifacts:
  - Windows.Forensics.Persistence
  - Windows.System.Services
  - Windows.System.TaskScheduler
  - Windows.Sys.AllUsers
  - Windows.Applications.Chrome.History
  - Windows.Applications.Edge.History
  - Generic.System.FileFinder
parameters:
  - artifact: Generic.System.FileFinder
    parameters:
      - name: SearchFilesGlob
        value: |
          C:\ProgramData\AdobeFonts\**
          C:\Windows\System32\Tasks\AdobeFontsHelper
      - name: Calculate_Hash
        value: Y
```

Run as Administrator, then move the output zip into `fixture/` as `Collection-WIN-MARKETING-2026-04-22.zip`.

## Sanity Checks Before Committing the Fixture

```bash
# Mac collection should contain at minimum these artifact files
unzip -l fixture/Collection-MAC-DESIGNER-2026-04-22.zip | grep -E 'results/(MacOS\.System\.Persistence|MacOS\.UnifiedLogs\.Search|MacOS\.System\.KnowledgeC|MacOS\.Applications\.Safari\.History)\.json'

# Windows collection should contain
unzip -l fixture/Collection-WIN-MARKETING-2026-04-22.zip | grep -E 'results/(Windows\.System\.TaskScheduler|Windows\.Forensics\.Persistence|Windows\.Applications\.Edge\.History)\.json'

# Memory image should be non-empty and readable by Volatility
vol -f fixture/WIN-MARKETING.raw windows.info
```

Once these pass, run the case end-to-end:

```bash
cd ../../../..
npm run test:accuracy -- --case 007-velociraptor-multi-host
```

## IP and Domain Discipline

Per project conventions:

- Domains are `*.example.invalid` (RFC 6761) — `update.adobefonts-cdn.example.invalid`
- C2 IP range is `198.51.100.0/24` (RFC 5737 documentation prefix)
- User `dmartin` is fictional. Do not use real PII.

## What If Mac Memory Fixture Is Demanded Later?

It cannot be produced reliably on Apple Silicon. The case's negative findings (GT-007-011, GT-007-012) explicitly verify the Memory Branch's correct platform-conditional behavior. Adding a Mac memory image to this case would defeat the test.

If a future case wants Mac memory analysis, target Intel Mac hardware with osxpmem or a kernel extension capable of memory imaging — and document the platform constraint clearly. Do not retrofit this case.

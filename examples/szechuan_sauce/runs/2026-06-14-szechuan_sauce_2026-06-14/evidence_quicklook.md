# Evidence Quicklook

Generated: 2026-06-14T23:35:46Z
Case directory: `/cases/szechuan_sauce_2026-06-14`
Evidence directory: `/cases/szechuan_sauce_2026-06-14/evidence`
Evidence files: 5

## Files

- `DC01-E01.zip` - zip_container, 4836649413 bytes, sha256 `efe06d12388dbc00...`
  - ZIP members: 4; uncompressed bytes: 4872432596; types: {'disk_image': 2, 'unknown': 1}
  - Extracted high-value members:
    - `/cases/szechuan_sauce_2026-06-14/work/ingest/extracted/DC01-E01/E01-DC01/20200918_0347_CDrive.E01.txt` (unknown, 1399 bytes)
  - First members:
    - `E01-DC01/20200918_0347_CDrive.E01` (disk_image, 2524848357 bytes)
    - `E01-DC01/20200918_0347_CDrive.E01.txt` (unknown, 1399 bytes)
    - `E01-DC01/20200918_0347_CDrive.E02` (disk_image, 2347582840 bytes)
- `DC01-memory.zip` - zip_container, 561424278 bytes, sha256 `86658d85d8254e8d...`
  - ZIP members: 1; uncompressed bytes: 2147483648; types: {'memory_image': 1}
  - First members:
    - `citadeldc01.mem` (memory_image, 2147483648 bytes)
- `DESKTOP-E01.zip` - zip_container, 6843484923 bytes, sha256 `ade4c11a695bdcbe...`
  - ZIP members: 5; uncompressed bytes: 6864968629; types: {'disk_image': 4, 'unknown': 1}
  - Extracted high-value members:
    - `/cases/szechuan_sauce_2026-06-14/work/ingest/extracted/DESKTOP-E01/20200918_0417_DESKTOP-SDN1RPT.E01.txt` (unknown, 1608 bytes)
  - First members:
    - `20200918_0417_DESKTOP-SDN1RPT.E01` (disk_image, 2147291154 bytes)
    - `20200918_0417_DESKTOP-SDN1RPT.E01.txt` (unknown, 1608 bytes)
    - `20200918_0417_DESKTOP-SDN1RPT.E02` (disk_image, 2147330394 bytes)
    - `20200918_0417_DESKTOP-SDN1RPT.E03` (disk_image, 2147392052 bytes)
    - `20200918_0417_DESKTOP-SDN1RPT.E04` (disk_image, 422953421 bytes)
- `DESKTOP-SDN1RPT-memory.zip` - zip_container, 802767348 bytes, sha256 `fce1bdd584cd52d7...`
  - ZIP members: 1; uncompressed bytes: 2147483648; types: {'memory_image': 1}
  - First members:
    - `DESKTOP-SDN1RPT.mem` (memory_image, 2147483648 bytes)
- `case001-pcap.zip` - zip_container, 151610116 bytes, sha256 `ea8eee228cdf82b1...`
  - ZIP members: 1; uncompressed bytes: 197583252; types: {'network_capture': 1}
  - Extracted high-value members:
    - `/cases/szechuan_sauce_2026-06-14/work/ingest/extracted/case001-pcap/case001.pcap` (network_capture, 197583252 bytes)
  - First members:
    - `case001.pcap` (network_capture, 197583252 bytes)

## PCAP Quicklooks

### `/cases/szechuan_sauce_2026-06-14/work/ingest/extracted/case001-pcap/case001.pcap`

```text
File name:           /cases/szechuan_sauce_2026-06-14/work/ingest/extracted/case001-pcap/case001.pcap
File type:           Wireshark/... - pcapng
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: (not set)
Number of packets:   411 k
File size:           197 MB
Data size:           183 MB
Capture duration:    27650.358197 seconds
First packet time:   2020-09-18 21:58:07.470323
Last packet time:    2020-09-19 05:38:57.828520
Data byte rate:      6649 bytes/s
Data bit rate:       53 kbps
Average packet size: 446.47 bytes
Average packet rate: 14 packets/s
SHA256:              09abf49efea1852e047987d92907704d47f36d75f6c8056e2cafa6cc027791cb
SHA1:                ab2deca8c7881187806856c6baeb215abc990d2b
Strict time order:   True
Capture oper-sys:    Linux 5.8.0-kali1-amd64
Capture application: Mergecap (Wireshark) 3.2.6 (Git v3.2.6 packaged as 3.2.6-1)
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 262144
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 411797
```

HTTP request sample:
```text
1600491991.167680000	10.42.85.115	23.61.187.27	sf.symcd.com	/MFEwTzBNMEswSTAJBgUrDgMCGgUABBTSqZMG5M8TA9rdzkbCnNwuMAd5VgQUz5mp6nsm9EvJjo%2FX8AUm7%2BPSp50CEFkECVfyCEMwK6Uqofarzu8%3D
1600492369.580590000	10.42.85.115	104.92.247.90	tile-service.weather.microsoft.com	/en-US/livetile/preinstall?region=US&appid=C98EA5B0842DBB9405BBF071E1DA76512D21FE36&FORM=Threshold
1600493020.635439000	10.42.85.115	205.185.216.10	dl.delivery.mp.microsoft.com	/filestreamingservice/files/f0aaf762-c7ce-4613-a7b8-b4157cba425d/pieceshash
1600493020.704825000	10.42.85.115	205.185.216.42	9.tlu.dl.delivery.mp.microsoft.com	/filestreamingservice/files/f0aaf762-c7ce-4613-a7b8-b4157cba425d?P1=1600476086&P2=402&P3=2&P4=f5amSNTnuKWhvlCiFoYvK8VL6hdc7gjkF4XzTpFwdWXaeK2jOfBV6F9AxQ33%2fHdnGKTVa7s%2fFughRgk64PcarQ%3d%3d
1600493020.710054000	10.42.85.115	205.185.216.10	9.tlu.dl.delivery.mp.microsoft.com	/filestreamingservice/files/f0aaf762-c7ce-4613-a7b8-b4157cba425d?P1=1600476086&P2=402&P3=2&P4=f5amSNTnuKWhvlCiFoYvK8VL6hdc7gjkF4XzTpFwdWXaeK2jOfBV6F9AxQ33%2fHdnGKTVa7s%2fFughRgk64PcarQ%3d%3d
1600493022.885434000	10.42.85.115	8.240.65.254	tlu.dl.delivery.mp.microsoft.com	/filestreamingservice/files/f0aaf762-c7ce-4613-a7b8-b4157cba425d?P1=1600493662&P2=402&P3=2&P4=A3cW0RsCilJtpHQ8DaqOcwVaxrewRfHu%2fuE6x%2bam9nQanH271tyc11bczgFZ6fN4ZUGioS47%2bw1Djcu5AlNFGg%3d%3d
1600493022.890458000	10.42.85.115	8.253.200.120	tlu.dl.delivery.mp.microsoft.com	/filestreamingservice/files/f0aaf762-c7ce-4613-a7b8-b4157cba425d?P1=1600493662&P2=402&P3=2&P4=A3cW0RsCilJtpHQ8DaqOcwVaxrewRfHu%2fuE6x%2bam9nQanH271tyc11bczgFZ6fN4ZUGioS47%2bw1Djcu5AlNFGg%3d%3d
1600493023.327125000	10.42.85.115	8.240.65.254	tlu.dl.delivery.mp.microsoft.com	/filestreamingservice/files/f0aaf762-c7ce-4613-a7b8-b4157cba425d?P1=1600493662&P2=402&P3=2&P4=A3cW0RsCilJtpHQ8DaqOcwVaxrewRfHu%2fuE6x%2bam9nQanH271tyc11bczgFZ6fN4ZUGioS47%2bw1Djcu5AlNFGg%3d%3d
1600493029.776640000	10.42.85.115	23.37.117.182	www.microsoft.com	/pkiops/certs/Microsoft%20ECC%20Update%20Secure%20Server%20CA%202.1.crt
1600493030.560051000	10.42.85.115	205.185.216.10	dl.delivery.mp.microsoft.com	/filestreamingservice/fi ** (tshark:21795) 23:36:20.008181 [Epan WARNING] -- Dissector bug, protocol CLDAP, in packet 411695: ./epan/dissectors/packet-ldap.c:2180: failed assertion "recursion_depth <= 100"
les/3b79c97b-09ea-41fb-92f1-4589f4e2f3c3/pieceshash
1600493030.612772000	10.42.85.115	8.252.174.254	tlu.dl.delivery.mp.microsoft.com	/filestreamingservice/files/3b79c97b-09ea-41fb-92f1-4589f4e2f3c3?P1=1600493649&P2=402&P3=2&P4=dybMOALUBpuQjbzcgON2xBkv8Er4yik3rRfLgrJ3sfa4yBctkWahmOL%2bP4Nca6IVJUoCc4Yl3aPiu20SaNbAAQ%3d%3d
1600493030.614565000	10.42.85.115	8.253.200.120	tlu.dl.delivery.mp.microsoft.com	/filestreamingservice/files/3b79c97b-09ea-41fb-92f1-4589f4e2f3c3?P1=1600493649&P2=402&P3=2&P4=dybMOALUBpuQjbzcgON2xBkv8Er4yik3rRfLgrJ3sfa4yBctkWahmOL%2bP4Nca6IVJUoCc4Yl3aPiu20SaNbAAQ%3d%3d
1600493031.218732000	10.42.85.115	205.185.216.10	dl.delivery.mp.microsoft.com	/filestreamingservice/
```


## Recommended Next Actions

- Read this manifest before broad artifact exploration.
- Open ASR rows for confirmed hosts only after artifact-backed identification.
- Record every factual claim with `finding_record()` before briefing it.
- Use extracted PCAP/text quicklook outputs as pivots, not as ground truth replacements for source evidence.

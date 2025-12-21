# PEscan
a WIP vol3 plugin that looks for potentially suspicious/malicious PEs

## Usage
Add `pescan.py` to `volatility3/framework/plugins/windows`.

Then run:
```
vol3 -f mem.dump windows.pescan.PEscan
```

**Example:**
```
python3 vol.py -f Damian.mem windows.pescan.PEscan

--snip--

====================    0       0x0     0x0     ====================    0.0     HIGH/CRITICAL   THREAT DETAILS (1 findings)
[1] scvhost.exe 1924    0x13f130000     0xfafff Unknown 6.17    HIGH    Score:10
  Indicators    0       0x0     0x0     PACKED:UPX, HIGH_ENT:6.2, Packer_detected:_UPX  0.0
  File  0       0x0     0x0     \Users\EdwardNygma7\Downloads\windows-patch-update\scvhost.exe  0.0     PPID:1532
  PE_Header     0       0x0     0x0     Arch:0x8664 Sections:3  0.0     Entry:0xf91c0   Packer:UPX
    Section:UPX1        0       0x0     0x0     R:1W:0X:1       6.18    VSize:286720    RSize:284160
    Section:.rsrc       0       0x0     0x0     R:1W:1X:0       5.97    VSize:4096      RSize:2048
  Anomalies     0       0x0     0x0     Packer detected: UPX    0.0
--------------------    0       0x0     0x0     --------------------    0.0
```

## Features (tentative)
* Scans VADs, paged/non-paged pools, and mapped files to detect PE signatures.
* Performs PE header integrity validation to identify malformed or tampered structures.
* Verifies section tables for overlaps, inconsistencies, and suspicious section attributes.
* Detects RWX memory regions associated with PE images.
* Identifies parent process and mapping anomalies.
* Analyzes import and export tables.
* Calculates entropy levels to detect packed, encrypted, or obfuscated PE sections.
* Recognizes compiler metadata and packer signatures.
* Extracts and scans strings for C2 indicators, PowerShell scripting traces, and related artifacts.
* Correlates threads to determine execution originating from suspicious PE regions.
* Outputs structured findings in JSON format.


## References
- [Investigating Memory Forensics](https://alpbatursahin.medium.com/investigating-memory-forensic-processes-dlls-consoles-process-memory-and-networking-7277689a09b7)
- [Key Windows Kernel Data Structures](https://codemachine.com/articles/kernel_structures.html)
- [Windows Process Internals](https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-823d72d4d7b8)

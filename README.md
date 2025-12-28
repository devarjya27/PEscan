# PEscan
a WIP vol3 plugin that looks for potentially suspicious/malicious PEs

## Usage
Add `pescan.py` to `volatility3/framework/plugins/windows`.

Then run:
```
vol3 -f mem.dump windows.pescan.PEscan
```
Plugin Arguments:
```
--json-output
```
Output detailed analysis results in JSON format instead of table format. JSON includes complete PE structure analysis, all extracted strings, thread information, and full anomaly details.

**Example:**

```bash
python3 vol.py -f Damian.mem windows.pescan.PEscan --json-output

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

Json output:
```json
--snip--

  "high_threat_details": [
    {
      "process": "scvhost.exe",
      "pid": 1924,
      "ppid": 1532,
      "virtual_address": "0x13f130000",
      "size": "0xfafff",
      "protection": "Unknown",
      "filename": "\\Users\\EdwardNygma7\\Downloads\\windows-patch-update\\scvhost.exe",
      "threat_level": "HIGH",
      "threat_score": 10,
      "indicators": [
        "PACKED:UPX",
        "HIGH_ENT:6.2",
        "Packer_detected:_UPX"
      ],
      "entropy": 6.17,
      "pe_analysis": {
        "valid": true,
        "dos_header": {
          "e_lfanew": 128
        },
        "pe_header": {
          "machine": "0x8664",
          "sections": 3,
          "timestamp": 1683391173,
          "characteristics": "0x22e",
          "is_64bit": true,
          "entry_point": "0xf91c0",
          "image_base": "0x13f130000"
        },
        "sections": [
          {
            "name": "UPX0",
            "virtual_size": 733184,
            "virtual_addr": "0x1000",
            "raw_size": 0,
            "characteristics": "0x60000080",
            "entropy": 0.0,
            "is_executable": true,
            "is_writable": false,
            "is_readable": true
          },
          {
            "name": "UPX1",
            "virtual_size": 286720,
            "virtual_addr": "0xb4000",
            "raw_size": 284160,
            "characteristics": "0x60000040",
            "entropy": 6.18,
            "is_executable": true,
            "is_writable": false,
            "is_readable": true
          },
          {
            "name": ".rsrc",
            "virtual_size": 4096,
            "virtual_addr": "0xfa000",
            "raw_size": 2048,
            "characteristics": "0xc0000040",
            "entropy": 5.97,
            "is_executable": false,
            "is_writable": true,
            "is_readable": true
          }
        ],
        "anomalies": [
          "Packer detected: UPX"
        ],
        "packer": "UPX"
      },
      "strings": {
        "urls": [],
        "ips": [],
        "commands": [],
        "powershell": [],
        "registry": [],
        "suspicious": []
      },
      "threads": []
    }
  ]

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

# PEscan
a WIP vol3 plugin that looks for potentially suspicious/malicious PEs

## Usage
Add `pescan.py` to `volatility3/framework/plugins/windows`.

Then run:
```
vol3 -f mem.dump windows.pescan
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
* Extracts and scans strings for C2 indicators, PowerShell/WMI scripting traces, and related artifacts.
* Correlates threads to determine execution originating from suspicious PE regions.
* Outputs structured findings in JSON format for automation, analysis, and integration.
  
## References
- [Investigating Memory Forensics](https://alpbatursahin.medium.com/investigating-memory-forensic-processes-dlls-consoles-process-memory-and-networking-7277689a09b7)
- [Key Windows Kernel Data Structures](https://codemachine.com/articles/kernel_structures.html)
- [Windows Process Internals](https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-823d72d4d7b8)

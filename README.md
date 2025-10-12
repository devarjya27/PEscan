# PEscan
a WIP vol3 plugin that looks for suspicious PEs

## Usage
Add `pescan.py` to `volatility3/framework/plugins/windows`.

Then run:
```
vol3 -f mem.dump windows.pescan
```

## References
- [Investigating Memory Forensics](https://alpbatursahin.medium.com/investigating-memory-forensic-processes-dlls-consoles-process-memory-and-networking-7277689a09b7)
- [Key Windows kernel data structures](https://codemachine.com/articles/kernel_structures.html)
- [Windows Process Internals](https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-823d72d4d7b8)

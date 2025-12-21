# PEscan
# Features implemented as of now:
# - Scans VADs regions to detect PE signatures. (Plans to implement scanning of paged/non-paged pools aswell)
# - Performs PE header integrity validation to identify malformed or tampered structures.
# - Calculates entropy levels to detect packed, encrypted, or obfuscated PE sections.
# - Detects compiler and packer signatures
# - Threat criteria thresholds are mainly trial and error, and can be modified by user for their use cases.

import logging
import struct
import math
import re
import json
from typing import List, Tuple, Iterator, Dict, Any, Set
from collections import defaultdict

from volatility3.framework import renderers, interfaces, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class PEscan(interfaces.plugins.PluginInterface):

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.BooleanRequirement(
                name="json-output",
                description="Output detailed results in JSON format",
                optional=True,
                default=False,
            ),
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.statistics = {
            "processes": 0, "vads": 0, "pe_found": 0,
            "high": 0, "medium": 0, "low": 0, "critical": 0
        }
        self.all_findings = []
        self.high_threat_findings = []

        # Known packers with threat levels
        self.packer_signatures = {
            b'UPX': 'UPX',
            b'FSG': 'FSG',
            b'.UPX': 'UPX',
            b'MEW': 'MEW',
            b'PECompact': 'PECompact',
            b'ASPack': 'ASPack',
            b'Themida': 'Themida',
            b'VMProtect': 'VMProtect',
            b'Armadillo': 'Armadillo',
            b'Obsidium': 'Obsidium',
            b'Enigma': 'Enigma',
        }

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data or len(data) < 16:
            return 0.0
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        entropy = 0.0
        size = len(data)
        for count in byte_counts:
            if count == 0:
                continue
            p = float(count) / size
            entropy -= p * math.log2(p)
        return entropy

    def validate_pe_structure(self, data: bytes) -> Dict[str, Any]:
        result = {
            "valid": False,
            "dos_header": {},
            "pe_header": {},
            "sections": [],
            "anomalies": [],
            "packer": None,
        }

        if len(data) < 64:
            result["anomalies"].append("Insufficient data")
            return result

        # DOS header
        dos_magic = struct.unpack("<H", data[0:2])[0]
        if dos_magic != 0x5A4D:
            result["anomalies"].append("Invalid MZ signature")
            return result

        pe_offset = struct.unpack("<I", data[60:64])[0]
        result["dos_header"]["e_lfanew"] = pe_offset

        if pe_offset > len(data) - 24 or pe_offset > 0x1000:
            result["anomalies"].append(f"Suspicious PE offset: 0x{pe_offset:x}")
            return result

        # PE signature
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            result["anomalies"].append("Invalid PE signature")
            return result

        # COFF header
        coff = pe_offset + 4
        try:
            machine = struct.unpack("<H", data[coff:coff + 2])[0]
            num_sections = struct.unpack("<H", data[coff + 2:coff + 4])[0]
            timestamp = struct.unpack("<I", data[coff + 4:coff + 8])[0]
            opt_header_size = struct.unpack("<H", data[coff + 16:coff + 18])[0]
            characteristics = struct.unpack("<H", data[coff + 18:coff + 20])[0]

            result["pe_header"]["machine"] = hex(machine)
            result["pe_header"]["sections"] = num_sections
            result["pe_header"]["timestamp"] = timestamp
            result["pe_header"]["characteristics"] = hex(characteristics)

            # Validate machine
            if machine not in [0x14c, 0x8664, 0x1c0, 0x1c4, 0xaa64]:
                result["anomalies"].append(f"Unusual machine: {hex(machine)}")

            # Validate sections
            if num_sections == 0 or num_sections > 96:
                result["anomalies"].append(f"Invalid section count: {num_sections}")
                return result

            # Timestamp validation
            if timestamp == 0:
                result["anomalies"].append("Zeroed timestamp")
            elif timestamp < 631152000:
                result["anomalies"].append(f"Suspicious timestamp")

            opt_header_start = coff + 20
            if opt_header_size < 2:
                result["anomalies"].append("No optional header")
                return result

            magic = struct.unpack("<H", data[opt_header_start:opt_header_start + 2])[0]
            is_64bit = (magic == 0x20b)
            result["pe_header"]["is_64bit"] = is_64bit

            if is_64bit:
                entry_point = struct.unpack("<I", data[opt_header_start + 16:opt_header_start + 20])[0]
                image_base = struct.unpack("<Q", data[opt_header_start + 24:opt_header_start + 32])[0]
            else:
                entry_point = struct.unpack("<I", data[opt_header_start + 16:opt_header_start + 20])[0]
                image_base = struct.unpack("<I", data[opt_header_start + 28:opt_header_start + 32])[0]

            result["pe_header"]["entry_point"] = hex(entry_point)
            result["pe_header"]["image_base"] = hex(image_base)

            # Section table
            section_table_offset = opt_header_start + opt_header_size
            sections = []

            for i in range(num_sections):
                sec_offset = section_table_offset + (i * 40)
                if sec_offset + 40 > len(data):
                    break

                sec_name = data[sec_offset:sec_offset + 8].rstrip(b'\x00').decode('ascii', errors='ignore')
                virtual_size = struct.unpack("<I", data[sec_offset + 8:sec_offset + 12])[0]
                virtual_addr = struct.unpack("<I", data[sec_offset + 12:sec_offset + 16])[0]
                raw_size = struct.unpack("<I", data[sec_offset + 16:sec_offset + 20])[0]
                raw_ptr = struct.unpack("<I", data[sec_offset + 20:sec_offset + 24])[0]
                sec_char = struct.unpack("<I", data[sec_offset + 36:sec_offset + 40])[0]

                if raw_ptr + raw_size <= len(data):
                    sec_data = data[raw_ptr:raw_ptr + min(raw_size, 0x10000)]
                    sec_entropy = self.calculate_entropy(sec_data)
                else:
                    sec_entropy = 0.0

                section = {
                    "name": sec_name,
                    "virtual_size": virtual_size,
                    "virtual_addr": hex(virtual_addr),
                    "raw_size": raw_size,
                    "characteristics": hex(sec_char),
                    "entropy": round(sec_entropy, 2),
                    "is_executable": bool(sec_char & 0x20000000),
                    "is_writable": bool(sec_char & 0x80000000),
                    "is_readable": bool(sec_char & 0x40000000),
                }

                sections.append(section)

                # Check for RWX sections
                if section["is_executable"] and section["is_writable"]:
                    result["anomalies"].append(f"RWX section: {sec_name}")

                if sec_entropy > 6.5:
                    result["anomalies"].append(f"High entropy section {sec_name}: {sec_entropy:.2f}")

                if raw_size > 0 and virtual_size > 0:
                    if abs(raw_size - virtual_size) > virtual_size * 2:
                        result["anomalies"].append(f"Size mismatch in {sec_name}")

            result["sections"] = sections

            for i in range(len(sections) - 1):
                curr_end = sections[i]["virtual_size"] + int(sections[i]["virtual_addr"], 16)
                next_start = int(sections[i + 1]["virtual_addr"], 16)
                if curr_end > next_start:
                    result["anomalies"].append(f"Section overlap: {sections[i]['name']} and {sections[i+1]['name']}")

            for sig, name in self.packer_signatures.items():
                if sig in data[:1024]:
                    result["packer"] = name
                    result["anomalies"].append(f"Packer detected: {name}")
                    break

            result["valid"] = True

        except Exception as e:
            result["anomalies"].append(f"Parse error: {str(e)}")

        return result

    def extract_strings(self, data: bytes, min_len: int = 5) -> Dict[str, List[str]]:
        result = {
            "urls": [],
            "ips": [],
            "commands": [],
            "powershell": [],
            "registry": [],
            "suspicious": [],
        }

        # ASCII strings
        ascii_pattern = b'[\x20-\x7E]{' + str(min_len).encode() + b',}'
        strings = re.findall(ascii_pattern, data)

        unicode_pattern = b'(?:[\x20-\x7E]\x00){' + str(min_len).encode() + b',}'
        unicode_strings = re.findall(unicode_pattern, data)
        unicode_decoded = [s.decode('utf-16le', errors='ignore') for s in unicode_strings]

        all_strings = [s.decode('ascii', errors='ignore') for s in strings] + unicode_decoded

        for s in all_strings[:500]:
            s_lower = s.lower()

            if 'http://' in s_lower or 'https://' in s_lower or 'ftp://' in s_lower:
                result["urls"].append(s)

            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
                result["ips"].append(s)

            if any(cmd in s_lower for cmd in ['cmd.exe', 'powershell', 'wscript', 'cscript', 'rundll32']):
                result["commands"].append(s)

            if any(ps in s_lower for ps in ['invoke-', 'downloadstring', 'iex', 'encodedcommand', '-exec bypass']):
                result["powershell"].append(s)

            if 'hkey' in s_lower or 'hklm' in s_lower or 'hkcu' in s_lower:
                result["registry"].append(s)

            if any(sus in s_lower for sus in ['malware', 'trojan', 'backdoor', 'keylog', 'rootkit', 'exploit']):
                result["suspicious"].append(s)

        return result

    def analyze_threads(self, task) -> List[Dict[str, Any]]:
        threads = []
        try:
            for thread in task.ThreadListHead.to_list(
                f"{constants.BANG}_{self.context.symbol_space[task.vol.type_name].name}_ETHREAD",
                "ThreadListEntry"
            ):
                try:
                    tid = thread.Cid.UniqueThread
                    start_addr = thread.StartAddress

                    threads.append({
                        "tid": int(tid),
                        "start_address": hex(start_addr),
                    })
                except:
                    continue
        except:
            pass

        return threads

    def scan_process(self, task, proc_layer) -> Iterator[Dict[str, Any]]:
        proc_name = task.ImageFileName.cast("string", max_length=task.ImageFileName.vol.count, errors="replace")
        pid = task.UniqueProcessId

        try:
            ppid = task.InheritedFromUniqueProcessId
        except:
            ppid = 0

        threads = self.analyze_threads(task)

        try:
            for vad in task.get_vad_root().traverse():
                self.statistics["vads"] += 1

                vad_start = vad.get_start()
                vad_end = vad.get_end()
                vad_size = vad_end - vad_start

                if vad_size > 100 * 1024 * 1024:
                    continue

                read_size = min(vad_size, 0x100000)
                try:
                    data = proc_layer.read(vad_start, read_size, pad=True)
                except:
                    continue

                if data[:2] != b"MZ":
                    continue

                pe_analysis = self.validate_pe_structure(data)
                if not pe_analysis["valid"]:
                    continue

                self.statistics["pe_found"] += 1

                try:
                    protection = vad.get_protection(
                        self.context.layers[task.vol.layer_name].config.get("kernel_virtual_offset", task.vol.layer_name),
                        task.vol.layer_name,
                        self.context.symbol_space
                    )
                except:
                    protection = "Unknown"

                try:
                    filename = vad.get_file_name() or "None"
                except:
                    filename = "None"

                strings = self.extract_strings(data[:min(len(data), 0x50000)])
                overall_entropy = self.calculate_entropy(data[:min(len(data), 0x10000)])

                threat_score = 0
                indicators = []

                if pe_analysis.get("packer"):
                    threat_score += 6
                    indicators.append(f"PACKED:{pe_analysis['packer']}")

                if filename == "None" or "Pagefile" in filename:
                    threat_score += 4
                    indicators.append("UNBACKED")

                if "EXECUTE" in protection and "WRITE" in protection:
                    threat_score += 5
                    indicators.append("RWX_MEMORY")

                if overall_entropy > 7.0:
                    threat_score += 5
                    indicators.append(f"VERY_HIGH_ENT:{overall_entropy:.1f}")
                elif overall_entropy > 6.0:
                    threat_score += 3
                    indicators.append(f"HIGH_ENT:{overall_entropy:.1f}")
                elif overall_entropy > 5.5:
                    threat_score += 2
                    indicators.append(f"ELEVATED_ENT:{overall_entropy:.1f}")

                threat_score += len(pe_analysis["anomalies"])
                for anom in pe_analysis["anomalies"][:3]:
                    indicators.append(anom.replace(" ", "_"))

                if strings["urls"]:
                    threat_score += 3
                    indicators.append(f"URLS:{len(strings['urls'])}")

                if strings["powershell"]:
                    threat_score += 4
                    indicators.append(f"POWERSHELL:{len(strings['powershell'])}")

                if strings["suspicious"]:
                    threat_score += 3
                    indicators.append("SUSPICIOUS_STRINGS")

                if strings["commands"]:
                    threat_score += 2
                    indicators.append(f"COMMANDS:{len(strings['commands'])}")

                # Classify threat
                if threat_score >= 15:
                    threat_level = "CRITICAL"
                    self.statistics["critical"] += 1
                elif threat_score >= 8:
                    threat_level = "HIGH"
                    self.statistics["high"] += 1
                elif threat_score >= 4:
                    threat_level = "MEDIUM"
                    self.statistics["medium"] += 1
                else:
                    threat_level = "LOW"
                    self.statistics["low"] += 1

                finding = {
                    "process": proc_name,
                    "pid": int(pid),
                    "ppid": int(ppid),
                    "virtual_address": hex(vad_start),
                    "size": hex(vad_size),
                    "protection": protection,
                    "filename": filename,
                    "threat_level": threat_level,
                    "threat_score": threat_score,
                    "indicators": indicators,
                    "entropy": round(overall_entropy, 2),
                    "pe_analysis": pe_analysis,
                    "strings": strings,
                    "threads": threads,
                }

                self.all_findings.append(finding)

                # Store high-threat findings
                if threat_level in ["HIGH", "CRITICAL"]:
                    self.high_threat_findings.append(finding)

                yield finding

        except Exception as e:
            vollog.debug(f"Error scanning {proc_name}: {e}")

    def scan_all_processes(self):


        procs = pslist.PsList.list_processes(self.context, self.config["kernel"])

        for task in procs:
            self.statistics["processes"] += 1
            proc_name = task.ImageFileName.cast("string", max_length=task.ImageFileName.vol.count, errors="replace")

            vollog.info(f"Analyzing: {proc_name} (PID: {task.UniqueProcessId})")

            try:
                proc_layer_name = task.add_process_layer()
                proc_layer = self.context.layers[proc_layer_name]
            except:
                continue

            for finding in self.scan_process(task, proc_layer):
                yield finding

    def run(self):
        if self.config.get("json-output", False):
            return self.output_json()
        else:
            return self.output_table()

    def output_json(self):
        list(self.scan_all_processes())

        output = {
            "statistics": self.statistics,
            "all_findings": self.all_findings,
            "high_threat_details": self.high_threat_findings,
        }

        json_str = json.dumps(output, indent=2)

        return renderers.TreeGrid(
            [("JSON Output", str)],
            [(0, (json_str,))]
        )

    def output_table(self):
        return renderers.TreeGrid(
            [
                ("Process", str),
                ("PID", int),
                ("Virtual_Address", format_hints.Hex),
                ("Size", format_hints.Hex),
                ("Protection", str),
                ("Entropy", float),
                ("Threat", str),
                ("Indicators", str),
            ],
            self._generate_table(),
        )

    def _generate_table(self):
        for finding in self.scan_all_processes():
            yield (
                0,
                (
                    finding["process"],
                    finding["pid"],
                    format_hints.Hex(int(finding["virtual_address"], 16)),
                    format_hints.Hex(int(finding["size"], 16)),
                    finding["protection"],
                    finding["entropy"],
                    finding["threat_level"],
                    ", ".join(finding["indicators"][:4]),
                ),
            )

        yield (
            0,
            (
                "=" * 20,
                0,
                format_hints.Hex(0),
                format_hints.Hex(0),
                "=" * 20,
                0.0,
                "SUMMARY",
                f"Total:{self.statistics['pe_found']} CRIT:{self.statistics['critical']} HIGH:{self.statistics['high']} MED:{self.statistics['medium']} LOW:{self.statistics['low']}",
            ),
        )

        if self.high_threat_findings:
            yield (
                0,
                (
                    "",
                    0,
                    format_hints.Hex(0),
                    format_hints.Hex(0),
                    "",
                    0.0,
                    "",
                    "",
                ),
            )
            yield (
                0,
                (
                    "=" * 20,
                    0,
                    format_hints.Hex(0),
                    format_hints.Hex(0),
                    "=" * 20,
                    0.0,
                    "HIGH/CRITICAL",
                    f"THREAT DETAILS ({len(self.high_threat_findings)} findings)",
                ),
            )

            for idx, finding in enumerate(self.high_threat_findings, 1):
                yield (
                    0,
                    (
                        f"[{idx}] {finding['process']}",
                        finding['pid'],
                        format_hints.Hex(int(finding['virtual_address'], 16)),
                        format_hints.Hex(int(finding['size'], 16)),
                        finding['protection'],
                        finding['entropy'],
                        finding['threat_level'],
                        f"Score:{finding['threat_score']}",
                    ),
                )

                yield (
                    0,
                    (
                        "  Indicators",
                        0,
                        format_hints.Hex(0),
                        format_hints.Hex(0),
                        ", ".join(finding['indicators']),
                        0.0,
                        "",
                        "",
                    ),
                )

                yield (
                    0,
                    (
                        "  File",
                        0,
                        format_hints.Hex(0),
                        format_hints.Hex(0),
                        finding['filename'],
                        0.0,
                        f"PPID:{finding['ppid']}",
                        "",
                    ),
                )

                pe = finding['pe_analysis']
                yield (
                    0,
                    (
                        "  PE_Header",
                        0,
                        format_hints.Hex(0),
                        format_hints.Hex(0),
                        f"Arch:{pe['pe_header'].get('machine','?')} Sections:{pe['pe_header'].get('sections',0)}",
                        0.0,
                        f"Entry:{pe['pe_header'].get('entry_point','?')}",
                        f"Packer:{pe.get('packer','None')}",
                    ),
                )

                high_ent_sections = [s for s in pe.get('sections', []) if s['entropy'] > 5.5]
                if high_ent_sections:
                    for sec in high_ent_sections[:3]:
                        yield (
                            0,
                            (
                                f"    Section:{sec['name']}",
                                0,
                                format_hints.Hex(0),
                                format_hints.Hex(0),
                                f"R:{int(sec['is_readable'])}W:{int(sec['is_writable'])}X:{int(sec['is_executable'])}",
                                sec['entropy'],
                                f"VSize:{sec['virtual_size']}",
                                f"RSize:{sec['raw_size']}",
                            ),
                        )

                strings = finding['strings']
                if strings['urls']:
                    yield (
                        0,
                        (
                            "  URLs",
                            0,
                            format_hints.Hex(0),
                            format_hints.Hex(0),
                            ", ".join(strings['urls'][:3]),
                            0.0,
                            "",
                            "",
                        ),
                    )

                if strings['powershell']:
                    yield (
                        0,
                        (
                            "  PowerShell",
                            0,
                            format_hints.Hex(0),
                            format_hints.Hex(0),
                            ", ".join(strings['powershell'][:2]),
                            0.0,
                            "",
                            "",
                        ),
                    )

                if strings['suspicious']:
                    yield (
                        0,
                        (
                            "  Suspicious",
                            0,
                            format_hints.Hex(0),
                            format_hints.Hex(0),
                            ", ".join(strings['suspicious'][:3]),
                            0.0,
                            "",
                            "",
                        ),
                    )

                if strings['commands']:
                    yield (
                        0,
                        (
                            "  Commands",
                            0,
                            format_hints.Hex(0),
                            format_hints.Hex(0),
                            ", ".join(strings['commands'][:2]),
                            0.0,
                            "",
                            "",
                        ),
                    )

                if pe.get('anomalies'):
                    yield (
                        0,
                        (
                            "  Anomalies",
                            0,
                            format_hints.Hex(0),
                            format_hints.Hex(0),
                            ", ".join(pe['anomalies'][:5]),
                            0.0,
                            "",
                            "",
                        ),
                    )

                yield (
                    0,
                    (
                        "-" * 20,
                        0,
                        format_hints.Hex(0),
                        format_hints.Hex(0),
                        "-" * 20,
                        0.0,
                        "",
                        "",
                    ),
                )

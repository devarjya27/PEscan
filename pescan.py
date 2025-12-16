# PEscan
# Features implemented as of now:
# - Scans VADs, paged/non-paged pools, and mapped files to detect PE signatures.
# - Performs PE header integrity validation to identify malformed or tampered structures.
# - Calculates entropy levels to detect packed, encrypted, or obfuscated PE sections.
# - Outputs structured findings in JSON format.

import logging
import struct
import math
import json
from typing import List, Tuple, Iterator, Dict, Any
from collections import defaultdict

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, poolscanner

vollog = logging.getLogger(__name__)


class PEscan(interfaces.plugins.PluginInterface):

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Define plugin requirements and configuration options"""
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"]
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="poolscanner", component=poolscanner.PoolScanner, version=(1, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="json-output",
                description="Output detailed results in JSON format",
                optional=True,
                default=False
            ),
            requirements.BooleanRequirement(
                name="quick-scan",
                description="Skip pool scanning for faster results (VADs only)",
                optional=True,
                default=False
            ),
        ]

    def __init__(self, *args, **kwargs):
        """Initialize plugin with statistics tracking"""
        super().__init__(*args, **kwargs)
        self.statistics = {
            "processes_scanned": 0,
            "vads_scanned": 0,
            "pools_scanned": 0,
            "pe_found_vad": 0,
            "pe_found_pool": 0,
            "high_threat": 0,
            "medium_threat": 0,
            "low_threat": 0,
            "total_suspicious": 0
        }

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        
        # Calculate Shannon entropy. Threshold for now: >5.

        if not data:
            return 0.0
        
        entropy = 0.0
        size = len(data)
        byte_counts = [0] * 256
        
        for byte in data:
            byte_counts[byte] += 1
        
        for count in byte_counts:
            if count == 0:
                continue
            probability = float(count) / size
            entropy -= probability * math.log2(probability)
        
        return entropy

    @staticmethod
    def validate_pe_header(data: bytes) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Perform comprehensive PE header validation.
        
        Validates:
        - DOS header (MZ signature)
        - PE signature  
        - COFF header structure
        - Machine type validity
        - Section count sanity
        - Compilation timestamp
        
        Args:
            data: Memory buffer containing potential PE image
            
        Returns:
            Tuple of (is_valid, status_message, details_dict)
        """
        details = {
            "dos_signature": None,
            "pe_signature": None,
            "machine": None,
            "sections": 0,
            "timestamp": None,
            "characteristics": None,
            "anomalies": []
        }
        
        if len(data) < 64:
            return False, "Insufficient data for DOS header", details
        
        dos_magic = struct.unpack("<H", data[0:2])[0]
        details["dos_signature"] = hex(dos_magic)
        
        if dos_magic != 0x5A4D:
            details["anomalies"].append("Invalid DOS signature")
            return False, "Invalid DOS signature", details
        
        try:
            pe_offset = struct.unpack("<I", data[60:64])[0]
        except:
            return False, "Cannot read PE offset", details
        
        if pe_offset > len(data) - 4 or pe_offset > 0x800:
            details["anomalies"].append(f"Suspicious PE offset: {hex(pe_offset)}")
            return False, f"Invalid PE offset: {hex(pe_offset)}", details
        
        if len(data) < pe_offset + 24:
            return False, "Insufficient data for PE header", details
        
        pe_signature = data[pe_offset:pe_offset + 4]
        details["pe_signature"] = pe_signature.hex()
        
        if pe_signature != b'PE\x00\x00':
            details["anomalies"].append("Invalid PE signature")
            return False, "Invalid PE signature", details
        
        try:
            coff_start = pe_offset + 4
            machine = struct.unpack("<H", data[coff_start:coff_start + 2])[0]
            num_sections = struct.unpack("<H", data[coff_start + 2:coff_start + 4])[0]
            timestamp = struct.unpack("<I", data[coff_start + 4:coff_start + 8])[0]
            characteristics = struct.unpack("<H", data[coff_start + 18:coff_start + 20])[0]
            
            details["machine"] = hex(machine)
            details["sections"] = num_sections
            details["timestamp"] = timestamp
            details["characteristics"] = hex(characteristics)
            
            valid_machines = [0x14c, 0x8664, 0x1c0, 0x1c4, 0xaa64]
            
            if machine not in valid_machines:
                details["anomalies"].append(f"Unusual machine type: {hex(machine)}")
            
            if num_sections == 0 or num_sections > 96:
                details["anomalies"].append(f"Suspicious section count: {num_sections}")
                return False, f"Invalid section count: {num_sections}", details
            
            if timestamp > 0 and (timestamp > 2147483647 or timestamp < 631152000):
                details["anomalies"].append(f"Suspicious timestamp: {timestamp}")
            
        except Exception as e:
            return False, f"Error parsing COFF header: {str(e)}", details
        
        return True, "Valid PE structure", details

    def classify_threat_level(self, threat_score: int) -> str:
        """
        Classify finding based on threat score.
        
        Args:
            threat_score: Calculated threat score
            
        Returns:
            Threat level string (HIGH/MEDIUM/LOW)
        """
        if threat_score >= 6:
            return "HIGH"
        elif threat_score >= 3:
            return "MEDIUM"
        else:
            return "LOW"

    def scan_vad_for_pe(self, task, process_layer) -> Iterator[Dict[str, Any]]:
        """
        Scan process Virtual Address Descriptors for PE images.
        
        Traverses all VADs in a process looking for:
        - MZ signatures
        - Executable memory regions
        - Unbacked memory (no file mapping)
        - High entropy content
        
        Args:
            task: EPROCESS object to scan
            process_layer: Memory layer for reading process memory
            
        Yields:
            Dictionary containing finding details for each detected PE
        """
        for vad in task.get_vad_root().traverse():
            self.statistics["vads_scanned"] += 1
            
            try:
                protection = vad.get_protection(
                    self.context.layers[task.vol.layer_name].config.get("kernel_virtual_offset", task.vol.layer_name),
                    self.context.symbol_space
                )
                
                is_executable = protection in [
                    "PAGE_EXECUTE_READWRITE", 
                    "PAGE_EXECUTE_WRITECOPY", 
                    "PAGE_EXECUTE_READ", 
                    "PAGE_EXECUTE"
                ]
                
                vad_start = vad.get_start()
                vad_end = vad.get_end()
                vad_size = vad_end - vad_start
                
                read_size = min(vad_size, 0x10000)
                
                try:
                    data = process_layer.read(vad_start, read_size, pad=True)
                except exceptions.InvalidAddressException:
                    continue
                
                if data[:2] != b'MZ':
                    continue
                
                self.statistics["pe_found_vad"] += 1
                
                is_valid, status, pe_details = self.validate_pe_header(data)
                entropy = self.calculate_entropy(data[:min(len(data), 8192)])
                
                threat_score = 0
                indicators = []
                
                if is_executable:
                    threat_score += 3
                    indicators.append("Executable memory")
                
                if not vad.get_file_name():
                    threat_score += 2
                    indicators.append("No backing file")
                
                if entropy > 5.0:
                    threat_score += 2
                    indicators.append(f"High entropy ({entropy:.2f})")
                
                if pe_details.get("anomalies"):
                    threat_score += len(pe_details["anomalies"])
                    indicators.extend(pe_details["anomalies"])
                
                threat_level = self.classify_threat_level(threat_score)
                
                if threat_level == "HIGH":
                    self.statistics["high_threat"] += 1
                elif threat_level == "MEDIUM":
                    self.statistics["medium_threat"] += 1
                else:
                    self.statistics["low_threat"] += 1
                
                self.statistics["total_suspicious"] += 1
                
                yield {
                    "type": "VAD",
                    "process_name": task.ImageFileName.cast("string", max_length=task.ImageFileName.vol.count, errors="replace"),
                    "pid": task.UniqueProcessId,
                    "address": format_hints.Hex(vad_start),
                    "size": format_hints.Hex(vad_size),
                    "protection": protection,
                    "file_name": vad.get_file_name() or "N/A",
                    "pe_valid": is_valid,
                    "pe_status": status,
                    "pe_details": pe_details,
                    "entropy": round(entropy, 3),
                    "threat_score": threat_score,
                    "threat_level": threat_level,
                    "indicators": indicators
                }
                
            except Exception as e:
                vollog.debug(f"Error scanning VAD at {vad.get_start():#x}: {str(e)}")
                continue

    def scan_pools_for_pe(self) -> Iterator[Dict[str, Any]]:

        # Scan kernel memory pools (paged and non-paged) for PE images.

        kernel = self.context.modules[self.config["kernel"]]
        layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name
        
        pool_tags_to_scan = [
            b'MmSt', b'AlPc', b'File', b'Even',
            b'Proc', b'Thre', b'VadS', b'VadF', b'Vadl'
        ]
        
        constraints = []
        for tag in pool_tags_to_scan:
            for pool_type in [poolscanner.PoolType.PAGED, poolscanner.PoolType.NONPAGED]:
                try:
                    constraint = poolscanner.PoolConstraint(
                        tag=tag,
                        type_name=None,
                        page_type=pool_type,
                        size=(0x100, None),
                        skip_type_test=True
                    )
                    constraints.append((constraint, pool_type, tag))
                except Exception as e:
                    vollog.debug(f"Error creating constraint for tag {tag}: {e}")
                    continue
        
        try:
            for constraint, pool_type, tag in constraints:
                pool_type_str = "PAGED" if pool_type == poolscanner.PoolType.PAGED else "NONPAGED"
                
                try:
                    for result in poolscanner.PoolScanner.pool_scan(
                        self.context,
                        self.config["kernel"],
                        layer_name,
                        symbol_table,
                        [constraint],
                        alignment=8,
                        progress_callback=None
                    ):
                        self.statistics["pools_scanned"] += 1
                        
                        try:
                            constraint_match, pool_header = result
                            pool_address = pool_header.vol.offset
                            header_size = pool_header.vol.size
                            data_offset = pool_address + header_size
                            
                            layer = self.context.layers[layer_name]
                            data = layer.read(data_offset, 0x10000, pad=True)
                            
                            if data[:2] != b'MZ':
                                continue
                            
                            self.statistics["pe_found_pool"] += 1
                            
                            is_valid, status, pe_details = self.validate_pe_header(data)
                            entropy = self.calculate_entropy(data[:min(len(data), 8192)])
                            
                            threat_score = 4
                            indicators = [f"PE in {pool_type_str} pool"]
                            
                            if entropy > 7.0:
                                threat_score += 2
                                indicators.append(f"High entropy ({entropy:.2f})")
                            
                            if pe_details.get("anomalies"):
                                threat_score += len(pe_details["anomalies"])
                                indicators.extend(pe_details["anomalies"])
                            
                            threat_level = self.classify_threat_level(threat_score)
                            
                            if threat_level == "HIGH":
                                self.statistics["high_threat"] += 1
                            elif threat_level == "MEDIUM":
                                self.statistics["medium_threat"] += 1
                            else:
                                self.statistics["low_threat"] += 1
                            
                            self.statistics["total_suspicious"] += 1
                            
                            try:
                                pool_size = pool_header.BlockSize * 16
                            except:
                                pool_size = 0
                            
                            yield {
                                "type": f"POOL_{pool_type_str}",
                                "process_name": "N/A (Kernel)",
                                "pid": 0,
                                "address": format_hints.Hex(data_offset),
                                "size": format_hints.Hex(pool_size) if pool_size else "Unknown",
                                "protection": pool_type_str,
                                "file_name": f"Pool Tag: {tag.decode('ascii', errors='ignore')}",
                                "pe_valid": is_valid,
                                "pe_status": status,
                                "pe_details": pe_details,
                                "entropy": round(entropy, 3),
                                "threat_score": threat_score,
                                "threat_level": threat_level,
                                "indicators": indicators
                            }
                            
                        except Exception as e:
                            vollog.debug(f"Error processing pool allocation: {e}")
                            continue
                            
                except Exception as e:
                    vollog.debug(f"Error scanning pool tag {tag} ({pool_type_str}): {e}")
                    continue
                    
        except Exception as e:
            vollog.error(f"Pool scanning error: {e}")

    def _generator(self, tasks):

        # Main generator coordinating all scanning operations.
        
        for task in tasks:
            self.statistics["processes_scanned"] += 1
            
            try:
                process_layer_name = task.add_process_layer()
                process_layer = self.context.layers[process_layer_name]
            except exceptions.InvalidAddressException:
                continue
            
            for finding in self.scan_vad_for_pe(task, process_layer):
                yield (0, finding)
        
        if not self.config.get("quick-scan", False):
            for finding in self.scan_pools_for_pe():
                yield (0, finding)

    def run(self):

        # Main plugin execution entry point.

        # Scan ALL processes (no filter)
        tasks = pslist.PsList.list_processes(
            context=self.context,
            layer_name=self.config["kernel"],
            symbol_table=self.config["kernel"],
            filter_func=None
        )
        
        if self.config.get("json-output", False):
            return self._output_json(tasks)
        else:
            return self._output_treegrid(tasks)

    def _output_json(self, tasks):

        results = {
            "scan_statistics": {},
            "findings": []
        }
        
        for _, finding in self._generator(tasks):
            json_finding = finding.copy()
            
            if isinstance(json_finding.get("address"), format_hints.Hex):
                json_finding["address"] = hex(json_finding["address"])
            if isinstance(json_finding.get("size"), format_hints.Hex):
                json_finding["size"] = hex(json_finding["size"])
            
            results["findings"].append(json_finding)
        
        results["scan_statistics"] = self.statistics
        
        json_output = json.dumps(results, indent=2)
        
        return renderers.TreeGrid(
            [("JSON Output", str)],
            self._json_generator(json_output)
        )

    def _json_generator(self, json_output):
        """Helper to yield JSON output"""
        yield (0, [json_output])

    def _output_treegrid(self, tasks):

        # Format and return results as TreeGrid table with summary.

        return renderers.TreeGrid(
            [
                ("Type", str),
                ("Process", str),
                ("PID", int),
                ("Address", format_hints.Hex),
                ("Size", format_hints.Hex),
                ("Protection", str),
                ("File/Tag", str),
                ("PE Valid", bool),
                ("Entropy", float),
                ("Threat", str),
                ("Indicators", str),
            ],
            self._format_generator(tasks)
        )

    def _format_generator(self, tasks):

        # Format findings for TreeGrid display with summary report.

        findings_list = list(self._generator(tasks))
        
        for _, finding in findings_list:
            yield (0, [
                finding["type"],
                finding["process_name"],
                finding["pid"],
                finding["address"],
                finding["size"],
                finding["protection"],
                finding["file_name"],
                finding["pe_valid"],
                finding["entropy"],
                finding["threat_level"],
                ", ".join(finding["indicators"]) if finding["indicators"] else "None"
            ])
        
        # Add summary report
        if findings_list:
            yield (0, [
                "=" * 20,
                "SCAN SUMMARY",
                "=" * 20,
                format_hints.Hex(0),
                format_hints.Hex(0),
                "=" * 20,
                "=" * 20,
                False,
                0.0,
                "INFO",
                ""
            ])
            
            yield (0, [
                "STATISTICS",
                f"Processes: {self.statistics['processes_scanned']}",
                0,
                format_hints.Hex(0),
                format_hints.Hex(0),
                f"VADs: {self.statistics['vads_scanned']}",
                f"Pools: {self.statistics['pools_scanned']}",
                False,
                0.0,
                "INFO",
                f"Total Suspicious: {self.statistics['total_suspicious']}"
            ])
            
            yield (0, [
                "THREATS",
                f"HIGH: {self.statistics['high_threat']}",
                0,
                format_hints.Hex(0),
                format_hints.Hex(0),
                f"MEDIUM: {self.statistics['medium_threat']}",
                f"LOW: {self.statistics['low_threat']}",
                False,
                0.0,
                "INFO",
                f"PE in VADs: {self.statistics['pe_found_vad']}, Pools: {self.statistics['pe_found_pool']}"
            ])


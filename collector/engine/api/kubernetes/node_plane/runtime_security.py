"""k8s_runtime_security — eBPF runtime-sensor alerts (Falco / Tetragon).

If Falco, Tetragon, or another eBPF runtime sensor is deployed, its syscall-level detections
of reverse shells, privilege escalation, and sensitive file reads are often the best evidence
available — things nothing else captures. We detect it and collect its alerts + ruleset; we do
not require it.
"""

from __future__ import annotations

from collector.lib.models import GapReason, SourceResult, SourceStatus, WrittenFile

from ..common.journal import collect_unit
from ..common.nodebase import NodePlaneCollector

_SENSORS: dict[str, dict[str, tuple[str, ...]]] = {
    "falco": {
        "detect": ("/etc/falco", "/var/log/falco"),
        "logs": ("/var/log/falco/*.log", "/var/log/falco/events.txt"),
        "rules": ("/etc/falco/falco_rules.yaml", "/etc/falco/falco_rules.local.yaml"),
        "unit": ("falco",),
    },
    "tetragon": {
        "detect": ("/etc/tetragon", "/var/run/cilium/tetragon"),
        "logs": ("/var/run/cilium/tetragon/tetragon.log", "/var/log/tetragon/*.log"),
        "rules": ("/etc/tetragon/tetragon.yaml",),
        "unit": ("tetragon",),
    },
}


class RuntimeSecurityCollector(NodePlaneCollector):
    name = "k8s_runtime_security"
    priority = 2
    description = "eBPF runtime-sensor alerts + rules (Falco/Tetragon); detected, not required."
    required_actions = ()

    def collect(self) -> SourceResult:
        node = self.node
        nc = self.node_context()
        files: list[WrittenFile] = []
        detected: list[str] = []
        alerts = 0

        for sensor, cfg in _SENSORS.items():
            if not any(node.exists(p) or node.iter_glob(p) for p in cfg["detect"]):
                continue
            detected.append(sensor)
            for glob in cfg["logs"]:
                for path in node.iter_glob(glob):
                    if not path.is_file():
                        continue
                    wf = self.capture_path(path, f"{sensor}/{path.name}")
                    if wf is not None:
                        files.append(wf)
                        alerts += 1
            for rule in cfg["rules"]:
                if node.exists(rule):
                    wf = self.copy_node_file(rule, f"{sensor}/rules/{rule.split('/')[-1]}")
                    if wf is not None:
                        files.append(wf)
            journal = collect_unit(node, cfg["unit"][0])
            if journal["available"] and journal["records"]:
                for rec in journal["records"]:
                    nc.stamp(rec)
                files.append(self.write_jsonl(journal["records"], f"{sensor}/journal.jsonl.gz"))
                alerts += len(journal["records"])

        files.append(
            self.write_json({"detected_sensors": detected, "alerts": alerts}, "config.json")
        )
        self.write_meta({"source": self.name, "sensors": detected, "alerts": alerts})

        if not detected:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                files=files,
                gaps=[
                    (
                        self.name,
                        GapReason.NOT_PRESENT,
                        "No eBPF runtime sensor (Falco/Tetragon) detected. Consider deploying one "
                        "before/after the incident for syscall-level detection.",
                    )
                ],
                notes="No runtime-security sensor present.",
            )
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=files,
            record_count=alerts,
            notes=f"Sensors: {', '.join(detected)}; {alerts} alert record(s).",
        )

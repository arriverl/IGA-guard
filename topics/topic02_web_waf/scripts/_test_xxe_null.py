import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.obfuscation_signals import xxe_rescue_label, xxe_structure_score
from iga_guard.pipeline import IgaGuardEngine, load_config

PLAIN = (
    '<?xml version="1.0" encoding="UTF-16BE"?> <!DOCTYPE r [ '
    '<!ENTITY % a "SYS"> <!ENTITY % b "TEM"> '
    '<!ENTITY % test %a;%b; "file:///etc/passwd"> ]> <r>&test;</r>'
)


def encode_null_spaced(text: str) -> str:
    out = []
    for ch in text:
        out.append("%00")
        out.append(f"%{ord(ch):02x}")
    return "".join(out)


encoded = encode_null_spaced(PLAIN)
url = f"http://demo/api/data?xml={encoded}"

engine = IgaGuardEngine(load_config(ROOT / "configs" / "default.yaml"))
report = engine.analyze_url("GET", url)
for n in report.normalized:
    print("raw has null:", "\x00" in n.raw_payload)
    print("norm has null:", "\x00" in (n.normalized_payload or ""))
    print("xxe score:", xxe_structure_score(n.raw_payload, n.normalized_payload))
    print("xxe hit:", xxe_rescue_label(n.raw_payload, n.normalized_payload))
print("label:", report.detection.label, report.detection.confidence)
print("span:", report.explanation.malicious_span if report.explanation else None)

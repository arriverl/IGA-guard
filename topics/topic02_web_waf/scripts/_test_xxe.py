import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.pipeline import IgaGuardEngine, load_config

payload = (
    '<?xml version="1.0" encoding="UTF-16BE"?> <!DOCTYPE r [ '
    '<!ENTITY % a "SYS"> <!ENTITY % b "TEM"> '
    '<!ENTITY % test %a;%b; "file:///etc/passwd"> ]> <r>&test;</r>'
)
engine = IgaGuardEngine(load_config(ROOT / "configs" / "default.yaml"))
report = engine.analyze_url("GET", "http://x/?xml=" + quote(payload))
d = report.to_dict()
print("label:", d["detection"]["label"])
print("confidence:", d["detection"]["confidence"])
probs = {k: round(v, 4) for k, v in d["detection"]["probs"].items() if v > 0.001}
print("probs:", probs)
if d.get("explanation"):
    print("span:", d["explanation"]["malicious_span"])
    print("nl:", d["explanation"]["natural_language"])

from pathlib import Path
import runpy


runpy.run_path(str(Path(__file__).resolve().parents[2] / "reality_v2_tls12_wire_probe.py"), run_name="__main__")

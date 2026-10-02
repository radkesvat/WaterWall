"""Small child for startup/timeout/group cleanup checks, no runtime dependency."""
import subprocess
import sys
import time

sys.dont_write_bytecode = True

if sys.argv[1] == "fail":
    print("startup failure fixture", flush=True)
    sys.exit(17)
if sys.argv[1] == "descendant":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    print(f"descendant {child.pid}", flush=True)
print("ready", flush=True)
time.sleep(30)

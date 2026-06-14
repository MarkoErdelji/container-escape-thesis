import os
import sys
import time

secret = os.environ.get("THESIS_SECRET")
if not secret:
    sys.stderr.write("THESIS_SECRET not set\n")
    sys.exit(1)

key = "THESISKEY{" + secret + "}"
print(f"app-worker started pid={os.getpid()}", flush=True)

while True:
    _ = key
    time.sleep(60)

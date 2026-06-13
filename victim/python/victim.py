"""Naive Python victim: holds the secret as an immutable str, never on disk.

Memory profile: CPython pymalloc arenas; an ASCII str is stored ~1 byte/char so it is
grep-findable, but being immutable + reference-counted it cannot be wiped while alive
(a finding in itself). The raw secret also lives in os.environ.
"""
import os
import sys
import time

secret = os.environ.get("THESIS_SECRET")
if not secret:
    sys.stderr.write("THESIS_SECRET not set\n")
    sys.exit(1)

key = "THESISKEY{" + secret + "}"  # immutable str held in RAM
print(f"app-worker started pid={os.getpid()}", flush=True)

while True:
    _ = key  # keep a live reference
    time.sleep(60)

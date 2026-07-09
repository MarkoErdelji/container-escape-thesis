import hashlib
import os
import time

raw = os.urandom(32)
key = "THESISKEY{" + raw.hex() + "}"
token_hash = hashlib.sha256(key.encode()).hexdigest()

print(f"app-worker started pid={os.getpid()}", flush=True)
print(f"TOKEN_HASH:{token_hash}", flush=True)

while True:
    _ = key
    time.sleep(60)

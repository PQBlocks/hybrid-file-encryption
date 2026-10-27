"""Library-level timing of encrypt() and decrypt() for one recipient (median of N runs).

    python benchmarks/bench_roundtrip.py [runs]
"""
import os
import statistics
import sys
import time

from pqblocks_files.encrypt import decrypt, encrypt
from pqblocks_files.keys import keygen

runs = int(sys.argv[1]) if len(sys.argv) > 1 else 5
kp = keygen()
for label, size in (("1KB", 1024), ("1MB", 1 << 20), ("10MB", 10 << 20)):
    data = os.urandom(size)
    enc, dec = [], []
    for _ in range(runs):
        t = time.perf_counter(); blob = encrypt(data, [kp.public]); enc.append(time.perf_counter() - t)
        t = time.perf_counter(); out = decrypt(blob, kp); dec.append(time.perf_counter() - t)
        assert out == data
    print("%-5s encrypt median %.4f s   decrypt median %.4f s   (n=%d)" % (
        label, statistics.median(enc), statistics.median(dec), runs))

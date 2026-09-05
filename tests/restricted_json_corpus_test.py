#!/usr/bin/env python3
"""Small deterministic differential corpus for the restricted cJSON entry point."""
import json
import random
import subprocess
import sys


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def main():
    rng = random.Random(73003)
    scalars = [None, True, False, 0, -17, 0.125, "", 'quote"slash\\', "// comment", "$value$", "é😀", "\n"]

    def value(depth=0):
        if depth == 4 or rng.randrange(3) == 0:
            return rng.choice(scalars)
        if rng.randrange(2):
            return [value(depth + 1) for _ in range(rng.randrange(5))]
        return {f"key{i}": value(depth + 1) for i in range(rng.randrange(5))}

    corpus = []
    for _ in range(100):
        encoded = json.dumps(value(), ensure_ascii=bool(rng.randrange(2)), separators=(",", ":"))
        corpus.extend([encoded, encoded + " trailing", encoded[:-1]])
    corpus.extend(['{"a":0,"\\u0061":1}', '[01]', '1.', '1e+', '"\\uZZZZ"'])
    for encoded in corpus:
        try:
            json.loads(encoded, object_pairs_hook=unique_object)
            expected = True
        except (ValueError, json.JSONDecodeError):
            expected = False
        result = subprocess.run([sys.argv[1], "--parse-json"], input=encoded.encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5, check=False)
        if result.returncode not in (0, 1) or (result.returncode == 0) != expected:
            raise AssertionError(f"differential mismatch for {encoded!r}: {result.returncode}, {result.stdout!r}")
    print(f"restricted JSON differential corpus: {len(corpus)} cases passed")


if __name__ == "__main__":
    main()

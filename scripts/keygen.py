#!/usr/bin/python3

import sys
import os

def keygen(filename, keylen):
    rng_data = os.urandom(keylen)

    with open(filename, "wb") as key_file:
        key_file.write(rng_data)

if len(sys.argv) != 3:
    print("keygen <keyfile> <keylen>")
    exit(1)

if __name__ == "__main__":
    keygen(sys.argv[1], int(sys.argv[2]))

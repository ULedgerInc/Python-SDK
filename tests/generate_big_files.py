#!/usr/bin/env python3

""" This script will generate a random 10, 20, 30, 40, and 50MB file. """

import os

for i in range(1, 6):  # 1 to 5
    with open(f"big{i}.txt", 'wb') as file:
        file.write(os.urandom(i * 2**20))

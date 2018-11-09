#!/usr/bin/env python3

#    Copyright 2018 ULedger Inc
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

""" This script will generate a random 10, 20, 30, 40, and 50MB file. """

import os

for i in range(1, 6):  # 1 to 5
    with open(f"big{i}.txt", 'wb') as file:
        file.write(os.urandom(i * 2**20))

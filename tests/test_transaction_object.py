
""" This module is the test suite for transaction_object.py """

import json
import os
import sys

# Import the uledger package regardless of where this script is run from.
try:
    from .. import uledger
except ValueError:  # Attempted relative import in non-package
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    import uledger

creds = json.load(open("creds.txt"))

url = creds["url"]
token = creds["token"]

# The super-admin for the blockchain.
admin = uledger.BlockchainUser(
    url, token, creds["admin"]["access_key"], creds["admin"]["secret_key"])


to = admin.add_string("hello world", tags=["test", "transaction object"])


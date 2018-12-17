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

""" This is a software development kit for the ULedger API.
It will take care of API-related boilerplate so you don't have to.

Basic Usage:
    1. Create a new BlockchainUser object using the url and token for a
       ULedger blockchain and an access key and secret key belonging to one
       of that blockchain's users.

    2. Use the BlockchainUser object to make requests to the API server.
       In general, you can read data, write data, and manage users.

Once you put data on a ULedger blockchain, you cannot delete or modify it.
Check that your data is clean and proper BEFORE you record it to the blockchain.
"""

from .core import BlockchainUser
from .exceptions import APIError
from .helpers import generate_secret_key, validate_secret_key, ipfs_hash, flatten

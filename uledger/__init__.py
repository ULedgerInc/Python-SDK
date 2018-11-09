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

""" This script adds the entrypoints from the ULedger SDK to the 'uledger'
namespace. Now we can just import the package instead of messing around
with long and confusing package.module.module... chains.

>>> import uledger
>>> user = uledger.BlockchainUser(...)
"""

from .core import BlockchainUser
from .exceptions import APIError
from .helpers import generate_secret_key, validate_secret_key, ipfs_hash, flatten

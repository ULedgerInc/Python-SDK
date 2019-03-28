#    Copyright 2019 ULedger Inc
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
For more information, see the API documentation.

The ULedger API specifies two discrete groups of operations: data manipulation
and user manipulation. Through data manipulation operations, you can read and
write transactions to and from the blockchain, verify transactions, query
transactions, and retrieve transaction content.

For extra management and security, the ULedger API also supports a set of user
manipulation operations using permission-based access control. In order to
make requests to the ULedger API, you must provide a valid set of user
credentials (an access key and a secret key, or username and password).
The user in question must have sufficient permissions for the desired operation.
A user can have any combination of 'can_read', 'can_write', 'can_add_user', and
'can_add_permission' permissions.

'can_read': the user can read content from the blockchain
'can_write': the user can write content to the blockchain
'can_add_user': the user can add new users to the blockchain
'can_add_permission': the user can grant or revoke permissions

A blockchain is always initialized with a single super admin. The super admin
will preside over a blockchain and the rest of its users. The super admin has
permanent access to all four permissions and cannot be deleted. To begin using
your blockchain, you will first need to set the super admin's access key and
secret key.

By design, the ULedger API does NOT support password recovery. If you lose your
secret key, you cannot get it back or reset it. It is imperative that you keep
your secret keys safe and secure, especially for the super admin.

Once you put data on a ULedger blockchain, you cannot modify or delete it.
Make sure to double-check your data BEFORE you record it to the blockchain.

The ULedger protocol uses SHA2-256 multihashes for compatibility with IPFS:
    [1] https://multiformats.io/multihash/
    [2] https://github.com/ipfs/ipfs

Basic Data Manipulation:
    >>> import uledger
    >>> admin = uledger.BlockchainUser(,
    >>>     'blockchain_url', 'api_token', 'access_key', 'secret_key')
    >>> basic_add = admin.add("some content")
    >>> print(basic_add)
    {
        'timestmap': 1549320863,
        'content_hash': 'QmR6vwie4jZiLeUiMZwJjTRMzS55ZMbMrXUCXcwRb3kTt9',
        'block_height': 1241472,
        'transaction_hash': 'QmagmMC4T2zAbVYHX8FzdircTUdtZuYgTQWdqMs6NaHrAp'
        'content_size': 12,
        'merkle_root': 'QmagmMC4T2zAbVYHX8FzdircTUdtZuYgTQWdqMs6NaHrAp',
        'merkle_proof': {
            'hashes': [
                ...,
        ]},
        'author': 'admin'
    }
    >>> admin.verify(basic_add['transaction_hash'])
    True
    >>> admin.get_content(basic_add['content_hash'])
    b"some content"

Basic Querying:
    >>> trx = admin.get_transactions(transaction_hash=basic_add['transaction_hash'])
    >>> print(trx)
    [{
        'timestmap': 1549320863,
        'content_hash': 'QmR6vwie4jZiLeUiMZwJjTRMzS55ZMbMrXUCXcwRb3kTt9',
        'block_height': 1241472,
        'transaction_hash': 'QmagmMC4T2zAbVYHX8FzdircTUdtZuYgTQWdqMs6NaHrAp'
        'content_size': 12,
        'merkle_root': 'QmagmMC4T2zAbVYHX8FzdircTUdtZuYgTQWdqMs6NaHrAp',
        'merkle_proof': {
            'hashes': [
                ...,
        ]},
        'tags': [
            ...
        ],
        'author': 'admin'
    }]
    >>> admin.get_transactions(content_hash=basic_add['content_hash']) == trx
    True
    >>> admin.get_transactions(last_transactions=1) == trx
    True
    >>> import time
    >>> admin.get_transactions(range=(0, time.time())) == trx
    True

Basic User Manipulation:
    >>> jackson = admin.new_confirmed_user('Jackson Parsons')
    >>> print(jackson)
    {
        'url': <your blockchain url>,
        'token': <your blockchain's api token>,
        'access_key': <jackson's access key>,
        'secret_key': <jackson's secret key>
    }
    >>> admin.set_permissions(jackson.access_key, 'rw')
    {
        'error': 'false',
        'access_key': <jackson's access key>,
        'can_read': True,
        'can_write': True
    }
    >>> admin.get_permissions(jackson.access_key)
    {
        'can_add_user': True,
        'can_add_permission': False,
        'can_read': True,
        'can_write': True
    }
    >>> admin.get_users(name='Jackson Parsons')
    [
        {
            'id': 123,
            'access_key': <jackson's access key>,
            'confirmed': True,
            'can_add_user': False,
            'can_add_permission': False,
            'can_read': True,
            'can_write': True,
            'name': 'Jackson Parsons'
        },
        ...
    ]
    >>> admin.deactivate(jackson.access_key)
    {
        'error': 'false',
        'access_key': <jackson's access key>
    }
"""

from .core import BlockchainUser
from .exceptions import APIError
from .helpers import generate_secret_key, validate_secret_key, ipfs_hash, flatten

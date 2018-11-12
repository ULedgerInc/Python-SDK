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

""" This module contains helper functions for the ULedger SDK. """

import collections
import random

import base58
import multihash

charsets = [
    'abcdefghijklmnopqrstuvwxyz',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    '0123456789',
    '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~',
]


def flatten(iterable):
    """ Yields every individual element from an iterable or nested iterable.
    str and bytes literals are treated as single elements.
    Code adapted from: https://stackoverflow.com/a/2158532
    """
    for el in iterable:
        if isinstance(el, collections.Iterable) and not isinstance(el, (str, bytes)):
            yield from flatten(iterable)
        else:
            yield el


def generate_secret_key(length=16):
    """ Generates a random password with at least one lowercase, uppercase,
    digit, and punctuation character.
    """
    password = list(map(random.choice, charsets))
    while len(password) < length:
        password.append(random.choice(random.choice(charsets)))
    random.shuffle(password)
    return "".join(password)


def ipfs_hash(content):
    """ Returns the SHA2-256 multihash of an object. Non-bytes objects are
    converted to strings and then encoded using utf-8 before being hashed.
    """
    if not isinstance(content, bytes):
        content = str(content).encode()
    mh = multihash.digest(content, multihash.Func.sha2_256)
    return base58.b58encode(mh.encode()).decode()


def validate_secret_key(password):
    """ Validates a password / key. The ULedger API requires secret keys that
    are at least 8 characters long with at least one lowercase, uppercase,
    number, and special character.
    """
    if not (len(password) >= 8 and
            any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in charsets[3] for c in password)):
        raise ValueError("Your password is too weak.")

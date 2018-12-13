#!/usr/bin/env python

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

""" This module is a test suite for the ULedger SDK. """

import json
import os
import random
import string
import sys
import time

import requests

# Import the uledger package regardless of where this script is run from.
# This will resolve "attempted relative import with no known parent package.
# All three errors have been encountered on various installs of Python3.5+
try:
    from .. import uledger
except (ImportError, SystemError, ValueError):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    import uledger

APIError = uledger.APIError

creds = json.load(open(os.path.join(os.path.dirname(__file__), "creds.txt")))

url = creds["url"]
token = creds["token"]

# The super-admin for the blockchain.
admin = uledger.BlockchainUser(
    url, token, creds["admin"]["access_key"], creds["admin"]["secret_key"])

# A test user
lumberjack = uledger.BlockchainUser(
    url, token, creds["lumberjack"]["access_key"], creds["lumberjack"]["secret_key"])

sns = [
    '',
    '\n',
    '\0',
    '{"error": "fake error text"}',
    '["more fake text"]',
    '["even", "more", "fake", "text"]',
    '("some", "tuple")',
    '{"key": "value"}',
]


def test_add_file():
    # The blockchain is data-agnostic, so *any* kind of file can be uploaded.

    # Normal File
    tags1 = ["file"]
    filepath1 = "hello_world.txt"
    admin.add_file(filepath1, tags1)
    print(1, 'OK')

    # > 50MB Fails
    filepath2 = "really_big_file.txt"
    with open(filepath2, mode='wb') as rbf:
        rbf.write(os.urandom(51 * 2**20))
    try:
        admin.add_file(filepath2)
    except OSError:
        print(2, 'OK')


def test_flatten(obj):
    pass


def test_add_object(blns=False):
    if blns:
        with open("blns.json", "r") as file:
            blns = json.load(file)
        for ns in blns:
            try:
                response = admin.add_object(ns, "blns")
            except APIError as e:
                print(e, ns)
            else:
                with open("results.txt", "a") as file:
                    file.write(str(response))
                    exit(0)
        return None

    string1 = "a normal string"
    string2 = "with 日本語の文字 to test API encoding"
    string3 = "this string has 50 characters to test the tag lim."
    string4 = "this string has 50 characters with some extra 日本語."
    string5 = "this string has more than 50 characters to break the tag limit"

    tags = ["sampleTag1", "sampleTag2"]

    # Break Tag Typing
    admin.add_object(string1, 'str', None)  # TH: QmdBdyUWgCBuJTiPn3CWwSTQdt5Wqs8QPQTNAYWACMKFWz
    print(-1, 'OK')

    admin.add_object(string1, 'str', [])    # TH: QmaiN7DrKMeXY3vD5qTrwTohdhTYrRVKGQ6UorbMhxnCBa
    print(-2, 'OK')

    admin.add_object(string1, 'str')
    print(-3, 'OK')

    admin.add_object(string1, 'str', True)
    print(-4, 'OK')

    print(admin.add_object(string1, "str"))
    print(-5, 'OK')

    admin.add_object(string1, 'str', [1])
    print(-6, 'OK')

    admin.add_object(string1, 'str', [True])
    print(-7, 'OK')

    admin.add_object(string1, 'str', [["hi", "there"], "hi"])
    print(-8, 'OK')

    # Add simple content with different properties.
    admin.add_object(string1, 'str', tags)
    print(1, 'OK')

    admin.add_object(string2, 'str', tags)
    print(2, 'OK')

    admin.add_object(string3, 'str', tags)
    print(3, 'OK')

    admin.add_object(string4, 'str', tags)
    print(4, 'OK')

    admin.add_object(string5, 'str', tags)
    print(5, 'OK')

    # Coercion
    admin.add_object(string5, 'str', coerce=True)
    print(6, 'OK')

    # Test naughty strings
    i = 7
    for ns in sns:
        admin.add_object(ns, 'str')
        print(i, 'OK')
        i += 1


def test_new_confirmed_user():
    # random.choices is available beginning in Python3.6
    if sys.version_info[1] > 5:
        name1 = ''.join(random.choices(string.ascii_letters, k=random.randint(3, 10)))
        name2 = ''.join(random.choices(string.ascii_letters, k=random.randint(3, 10)))

    else:
        name1 = ''.join([random.choice(string.ascii_letters) for _ in range(random.randint(3, 10))])
        name2 = ''.join([random.choice(string.ascii_letters) for _ in range(random.randint(3, 10))])

    # Test name 1
    print(admin.new_confirmed_user(name1))

    # Test name 2
    password = uledger.generate_secret_key()
    print(admin.new_confirmed_user(name2, password))

    # test a weak password
    try:
        admin.new_confirmed_user(name1, "weak_password")
    except ValueError:
        pass


def test_authorize():
    ak = lumberjack.access_key

    # add one permission PASS
    perms = admin.authorize(ak, "can_add_user")
    assert perms["can_add_user"]
    print(1, 'OK')

    perms = admin.revoke(ak, "can_add_user")
    try:
        perms["can_add_user"]
    except KeyError:
        pass
    print(2, 'OK')

    # add combination of permissions PASS
    perms = admin.authorize(ak, "can_add_user", "can_add_permission")
    assert perms["can_add_user"] and perms["can_add_permission"]
    print(3, 'OK')

    # add no permissions PASS
    perms2 = admin.authorize(ak)
    assert perms2 == perms
    del perms2
    print(4, 'OK')

    perms = admin.revoke(ak, "can_read", "can_write")
    try:
        perms["can_red"]
    except KeyError:
        pass
    try:
        perms["can_write"]
    except KeyError:
        pass
    print(5, 'OK')

    # add all permissions PASS
    perms = admin.authorize(ak, "can_read", "can_write", "can_add_user", "can_add_permission")
    assert perms["can_read"] and perms["can_write"] and perms["can_add_user"] and perms["can_add_permission"]
    print(6, 'OK')

    # add fake permission PASS
    try:
        admin.authorize(ak, "fake_permission")
    except APIError as e:
        assert str(e.args[0]) == 'value fake_permission is not proper'
    print(7, 'OK')

    # add permission they already have PASS
    perms2 = perms.copy()
    perms = admin.authorize(ak, "can_read")
    assert perms2["can_read"] == perms["can_read"]
    del perms2
    print(8, 'OK')

    # authorize self PASS
    perms = lumberjack.revoke(ak, "can_read", "can_write", "can_add_user")
    try:
        perms["can_red"]
    except KeyError:
        pass
    try:
        perms["can_write"]
    except KeyError:
        pass
    try:
        perms["can_add_user"]
    except KeyError:
        pass
    print(9, 'OK')

    perms = lumberjack.revoke(ak, "can_add_permission")
    try:
        perms["can_add_permission"]
    except KeyError:
        pass
    print(10, 'OK')

    perms = admin.authorize(ak, "can_read", "can_write")
    assert perms["can_read"] and perms["can_write"]
    print(11, 'OK')

    # revoke one permission PASS
    perms = admin.revoke(ak, "can_read")
    try:
        perms["can_read"]
    except KeyError:
        pass
    print(12, 'OK')

    perms = admin.authorize(ak, "can_read")
    assert perms["can_read"]
    print(13, 'OK')

    # revoke combination of permissions PASS
    perms = admin.revoke(ak, "can_read", "can_write")
    try:
        perms["can_red"]
    except KeyError:
        pass
    try:
        perms["can_write"]
    except KeyError:
        pass
    print(14, 'OK')

    # revoke no permissions PASS
    perms2 = perms.copy()
    perms = admin.revoke(ak)
    assert perms2 == perms
    del perms2
    print(15, 'OK')

    # revoke all permissions PASS
    perms = admin.authorize(ak, "can_read", "can_write", "can_add_user", "can_add_permission")
    assert perms["can_read"] and perms["can_write"] and perms["can_add_user"] and perms["can_add_permission"]
    print(16, 'OK')

    perms = admin.revoke(ak, "can_read", "can_write", "can_add_user", "can_add_permission")
    try:
        perms["can_red"]
    except KeyError:
        pass
    try:
        perms["can_write"]
    except KeyError:
        pass
    try:
        perms["can_add_user"]
    except KeyError:
        pass
    try:
        perms["can_add_permission"]
    except KeyError:
        pass
    print(17, 'OK')

    # revoke fake permission PASS
    try:
        admin.revoke(ak, "fake permission")
    except APIError as e:
        assert str(e.args[0]) == 'value fake permission is not proper'
    print(18, 'OK')

    # revoke permissions they already lost PASS
    perms2 = perms.copy()
    perms = admin.revoke(ak, "can_read")
    assert perms2 == perms
    del perms2
    print(19, 'OK')

    # revoke self PASS
    perms = admin.authorize(ak, "can_add_permission")
    assert perms["can_add_permission"]
    print(20, 'OK')

    perms = lumberjack.revoke(ak, "can_add_permission")
    try:
        perms["can_add_permission"]
    except KeyError:
        pass
    print(21, 'OK')

    # authorize without permission PASS
    try:
        lumberjack.authorize(ak, "can_read")
    except APIError as e:
        assert str(e.args[0]) == 'you are not authorized to add permission'
    print(22, 'OK')

    # authorize bad key PASS
    try:
        admin.authorize("1", "can_read")
    except APIError as e:
        assert str(e.args[0]) == 'user does not exist'
    print(23, 'OK')

    perms = admin.revoke(ak, "can_read", "can_write")
    try:
        perms["can_red"]
    except KeyError:
        pass
    try:
        perms["can_write"]
    except KeyError:
        pass
    print(24, 'OK')

    # authorize super_user PASS
    try:
        admin.authorize(ak, "is_super_admin")
    except APIError as e:
        assert str(e.args[0]) == 'value is_super_admin is not proper'
    print(25, 'OK')


def test_deactivate():
    # Deactivate user
    print(admin.deactivate('3STYa5OR6J8AWE97ClHhLx1jm2PB04bw'))

    # Deactivate already-deactivated user
    print(admin.deactivate('RVQa03D8ijZpNI9yWY1J267Aw4HqC5rP'))

    # Deactivate without permission
    try:
        lumberjack.deactivate('3STYa5OR6J8AWE97ClHhLx1jm2PB04bw')
    except APIError as e:
        assert str(e.args[0]) == 'you are not authorized to add permission'

    # Deactivate self
    admin.authorize('3STYa5OR6J8AWE97ClHhLx1jm2PB04bw', "can_add_permission")
    print(lumberjack.deactivate('3STYa5OR6J8AWE97ClHhLx1jm2PB04bw'))

    # The super admin CANNOT be authorized
    try:
        admin.deactivate('admin')
    except APIError as e:
        assert str(e.args[0]) == 'you can not authorize this user'


def test_get_content():
    # Normal content strings
    ch1 = "QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ"
    ch2 = "QmNy15eH5efF2ynZjnEoHTipcqJDKuVwVUJqASYo6Soh3K"
    ch3 = "QmUioxUe1qwQhSrPXEtKF9jED2JUhRSinK3CaqDv66gg9d"
    ch4 = "QmPfnrUoqFnk2yrwE3csjK1CpJmEJUqay8YLjypQxzQycB"
    ch5 = "QmZNzm7Waa4GJjGMMEjbzNpXR9hLUm6rEsxN6sAqTKSHD"  # Doesn't exist

    print(admin.get_content(ch1))
    print(admin.get_content(ch2))
    print(admin.get_content(ch3))
    print(admin.get_content(ch4))

    # The hash to a content string that hasn't been recorded to the blockchain
    try:
        print(admin.get_content(ch5))
    except APIError as e:
        assert str(e) == "there is no transaction with given hash"

    # Strings that can be decoded as JSON objects, fake error messages
    # '"Error: there is no transaction with given hash"'
    jt1 = '{"trick": "question”}'
    jt2 = '{"error": "fake error text"}'
    jt3 = '["more fake text"]'
    jt4 = '("some", "tuple")'
    jt5 = '"Error: fake error 2 electric boogaloo"'

    jtch1 = admin.add_object(jt1, 'str')["content_hash"]
    jtch2 = admin.add_object(jt2, 'str')["content_hash"]
    jtch3 = admin.add_object(jt3, 'str')["content_hash"]
    jtch4 = admin.add_object(jt4, 'str')["content_hash"]
    jtch5 = admin.add_object(jt5, 'str')["content_hash"]

    # jtch1 = 'QmTKJFYRcmLdD1MuqLbuwtphHLweS4rwYD23NDfPG19TsA'
    # jtch2 = 'QmSYWkRv6v25XoehXuGwRvURMw2BEsmJK8xtLgm3oU6JLt'
    # jtch3 = 'QmVVDebKYEexKeKtm5raPsqivHKSszFLvbDqeeFuuXmz76'
    # jtch4 = 'QmX1szdZQp68Fn2WKTPWGf32xEDy66XNRhrwKho3yRYCK5'
    # jtch5 = 'QmYSvKcL7kpR3W7Vyx6SoMJxD6Kap8k2GoZBUjXKrFTGt5'

    assert admin.get_content(jtch1) == jt1
    assert admin.get_content(jtch2) == jt2
    assert admin.get_content(jtch3) == jt3
    assert admin.get_content(jtch4) == jt4
    # "fake" error messages trip the same handling as real error messages
    try:
        admin.get_content(jtch5)
    except ValueError:
        pass

    # < 10MB
    # Returns the whole content of the file in escaped utf-8
    with open("hello_world.txt", "r") as file:
        content1 = file.read()
        content_hash = uledger.ipfs_hash(content1)
    content2 = admin.get_content(content_hash)
    assert content1 == content2

    # 10MB, example: 'QmchGu75T7zx8nZ5d6xfxxbkwYYbnH3mumUVMUKrxut1WQ'
    # 10MB is read in
    with open("big1.txt", "rb") as file:
        content1 = file.read()
        content_hash = uledger.ipfs_hash(content1)
    content2 = admin.get_content(content_hash)
    assert content1 == content2

    # 20MB, example: 'QmTdHiAS78KvKtpwfzEeURVFsNoTKfavmjo9aaeshQQRih'
    # 20 MB is read in
    with open("big2.txt", "rb") as file:
        content1 = file.read()
        content_hash = uledger.ipfs_hash(content1)
    content2 = admin.get_content(content_hash)
    assert content1 == content2

    # 30MB, example: 'QmPd4iCWqKujCkPoW9kuagkJKZKhYvd3DpBrnvYjEFoBvg'
    # 30MB read in
    with open("big3.txt", "rb") as file:
        content1 = file.read()
        content_hash = uledger.ipfs_hash(content1)
    content2 = admin.get_content(content_hash)
    assert content1 == content2

    # 40MB, example: 'QmVKNsVWasygDPaQD23nJHT5AJxB4QxpiMvx6Kqsg1vbto'
    # 40MB read in
    with open("big4.txt", "rb") as file:
        content1 = file.read()
        content_hash = uledger.ipfs_hash(content1)
    content2 = admin.get_content(content_hash)
    assert content1 == content2

    # 50MB, example: 'QmWThfhwjC7P7QNQmgJpnMMprUQwd9RpLhEW53ck1Q8PNt'
    # 50MB read in
    with open("big5.txt", "rb") as file:
        content1 = file.read()
        content_hash = uledger.ipfs_hash(content1)
    content2 = admin.get_content(content_hash)
    assert content1 == content2


def test_get_transactions():
    now = int(time.mktime(time.localtime()))

    # content_hash, transaction_hash, range, last_transactions, tags_any, tags_all, page

    # content_hash
    # 256 transactions => pagination correct, "page" added by me
    # TODO BUG: transactions are not sorted by timestamp correctly (pretty inconsistent tbh)
    # TODO BUG: some transactions have "tag_merkle_root", others do not
    # TODO BUG: "block_height" of 2?
    transactions = admin.get_transactions(
        content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ')
    assert len(transactions) == 256
    assert transactions == sorted(transactions, key=lambda x: x["timestamp"])
    # page 0
    transactions_p0 = admin.get_transactions(
        content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
        page=0)
    for trx in transactions_p0:
        print(trx["timestamp"])
    exit(0)
    assert transactions_p0 == transactions[:100]
    # page 1
    transactions_p1 = admin.get_transactions(
        content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
        page=1)
    assert transactions_p0 == transactions[100:200]
    # page 2
    transactions_p2 = admin.get_transactions(
        content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
        page=2)
    assert transactions_p0 == transactions[200:256]

    # transaction
    # this should just return a single value
    # TODO: BUG: {'error': 'false', 'result': [{'merkle_proof': {}}], 'metadata': {'current_page': 0}}, happens regardless of page
    transactions = admin.get_transactions(transaction_hash='QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh')
    print(transactions)
    # page 0 (doesn't make much sense to do this)
    # TODO: {'error': 'false', 'result': [{'merkle_proof': {}}], 'metadata': {'current_page': 0}}, happens regardless of page
    transactions = admin.get_transactions(
        transaction_hash='QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh',
        page=0)
    print(transactions)
    # page 1
    # seemingly ignores page, which is good
    transactions = admin.get_transactions(
        transaction_hash='QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh',
        page=0)
    print(transactions)

    # range
    # FIXED: the transactions returned from "range" are not sorted
    # FIXED: "range" returns transactions outside of the specified interval
    # This appears to only be fixed for "range". Other fields still have this problem.
    then = 1541214477
    transactions = admin.get_transactions(range={"From": then, "To": now})
    assert transactions == sorted(transactions, key=lambda x: x["timestamp"])
    assert transactions == [trx for trx in transactions
                            if then <= trx["timestamp"] <= now]
    # page 0
    transactions = admin.get_transactions(
        range={"From": 1541214477, "To": now},
        page=0)
    assert transactions == sorted(transactions, key=lambda x: x["timestamp"])
    assert transactions == [trx for trx in transactions
                            if then <= trx["timestamp"] <= now]
    # page 1
    transactions = admin.get_transactions(
        range={"From": 1541214477, "To": now},
        page=0)
    assert transactions == sorted(transactions, key=lambda x: x["timestamp"])
    assert transactions == [trx for trx in transactions
                            if then <= trx["timestamp"] <= now]

    # last_transactions
    # last_transactions sorts in descending (reverse) order
    transactions = admin.get_transactions(last_transactions=10)
    assert len(transactions) == 10
    assert transactions == sorted(transactions, key=lambda x: x["timestamp"], reverse=True)
    # page 0
    transactions = admin.get_transactions(
        last_transactions=101,
        page=0)
    assert len(transactions) == 100
    assert transactions == sorted(transactions, key=lambda x: x["timestamp"], reverse=True)
    # page 1
    transactions_p1 = admin.get_transactions(
        last_transactions=101,
        page=1)
    assert len(transactions_p1) == 1
    assert transactions + transactions_p1 == sorted(transactions + transactions_p1, key=lambda x: x["timestamp"], reverse=True)

    # tags_any
    # transactions = admin.get_transactions(tags_any=["hi"])
    assert len(transactions) == 3
    assert transactions == [trx for trx in transactions if "hi" in trx["tags"]]
    # page 0
    transactions_p0 = admin.get_transactions(
        tags_any=["hi"],
        page=0)
    assert transactions[:100] == transactions_p0

    # tags_all
    # transactions that HAVE all of the requested tags, NOT EQUAL to the requested tags
    # normally the transactions are returned in ascending order
    transactions = admin.get_transactions(tags_all=['appname=systemd', 'facility=daemon', 'severity=warning'])
    assert len(transactions) >= 2
    assert transactions == sorted(transactions, key=lambda x: x["timestamp"], reverse=True)
    # page 0
    transactions_p0 = admin.get_transactions(
        tags_all=['appname=systemd', 'facility=daemon', 'severity=warning'],
        page=0)
    assert transactions == transactions_p0

    # page
    # CANNOT BE USED ON ITS OWN.
    # Should return: {'error': 'Unknown parameters. Check spelling.', 'result': None, 'metadata': {'current_page': 0}})
    try:
        admin.get_transactions(page=0)
    except APIError as e:
        assert str(e.args[0]) == 'Unknown parameters. Check spelling.'

    # bad content hash
    # should return {'error': 'false', 'result': None, 'metadata': {'current_page': 0}}
    # get_transactions should output []
    assert admin.get_transactions(content_hash='hi') == []

    # bad transaction hash
    # should return {'error': 'false', 'result': None, 'metadata': {'current_page': 0}}
    # get_transactions should output []
    assert admin.get_transactions(content_hash='hi') == []

    # bad range 1
    # should return {'error': 'No transactions for specified time range.', 'result': None, 'metadata': {'current_page': 0}}
    # get_transactions should raise an API error
    # Note: not illegal to put negative values
    try:
        admin.get_transactions(range={"From": -1, "To": 0})
    except APIError as e:
        assert str(e.args[0]) == 'No transactions for specified time range.'

    # bad range 2
    # should return
    # {'error': "Timesamp error: 'From' timestamp is larger than 'To'.", 'result': None, 'metadata': {'current_page': 0}}
    # Note: an inverted range is made explicitly illegal by the API
    try:
        admin.get_transactions(range={"From": 10, "To": 5})
    except APIError as e:
        assert str(e.args[0]) == "Timesamp error: 'From' timesamp is larger than 'To'."

    # bad range 3
    # Should raise a requests.exceptions.HTTPError: '502 Server Error: Bad Gateway for url: https://elbonetest.uledgerapi.com/store/getTransactions'
    try:
        admin.get_transactions(range={"From": "a", "To": 10})
    except requests.exceptions.HTTPError as e:
        assert str(e) == '502 Server Error: Bad Gateway for url: https://elbonetest.uledgerapi.com/store/getTransactions'

    # bad lt
    # should raise
    # {'error': 'value cannot be a negative integer', 'result': None, 'metadata': {'current_page': 0}}
    try:
        admin.get_transactions(last_transactions=-1)
    except APIError as e:
        assert str(e.args[0]) == 'value cannot be a negative integer'

    # good content, good transaction (matching)
    # should return a single transaction
    transactions = admin.get_transactions(
        content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
        transaction_hash='Qmb4cFnvpxtbLaQxDCj1DXDWxS8Eori7M4AunDNNk5up3m')
    assert len(transactions) == 1
    assert transactions[0]["timestamp"] == 1541098870

    # TODO In general, if content_hash and transaction_hash don't / can't match, the API response gets mucked up

    # good content, good transaction (not matching)
    # TODO BUG: good hashes that don't match muck up the API response
    # Received: {'error': 'false', 'result': [{'merkle_proof': {}}], 'metadata': {'current_page': 0}}
    # Expected: {'error': 'false', 'result': None, 'metadata': {'current_page': 0}}
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     transaction_hash='QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh')

    # good content, bad transaction
    # TODO BUG: a bad transaction hash (one that doesn't / can't exist) paired with a good content hash mucks up the API response
    # Received: {'error': 'false', 'result': [{'merkle_proof': {}}], 'metadata': {'current_page': 0}}
    # Expected: {'error': 'false', 'result': None, 'metadata': {'current_page': 0}}
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     transaction_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ')

    # bad content, good transaction
    # TODO BUG: a bad content hash (one that doesn't / can't exist) matched with a good transaction hash mucks up the API response
    # Received: {'error': 'false', 'result': [{'merkle_proof': {}}], 'metadata': {'current_page': 0}}
    # Expected: {'error': 'false', 'result': None, 'metadata': {'current_page': 0}}
    # transactions = admin.get_transactions(
    #     content_hash='hi',
    #     transaction_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ')

    # bad content, bad transaction
    # TODO BUG: bad c and t hashes muck up the API response
    # Received: {'error': 'false', 'result': [{'merkle_proof': {}}], 'metadata': {'current_page': 0}}
    # Expected: {'error': 'false', 'result': None, 'metadata': {'current_page': 0}}
    # transactions = admin.get_transactions(
    #     content_hash='hi',
    #     transaction_hash='star')

    # content-range
    # TODO BUG: "range" is ignored completely
    # if given content_hash, I can literally put anything I want (illegal range,
    # negative, impossible) for range and the response will be equivalent
    # to returning the FIRST PAGE of content_hash matches.
    # the order of parameters DOES NOT affect this behavior
    # TODO HYPOTHESIS: "content_hash" overwrites / takes precedence over "range"
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     range={"From": 1541095886, "To": 1541098903})
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()

    # page 0
    # TODO BUG: "range" ignored when "content_hash" and "page" are present
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     range={"From": 1541098903, "To": 1541095886},
    #     page=0)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()

    # page 1
    # TODO BUG: "range" ignored when "content_hash" and "page" are present
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     range={"From": 1541098903, "To": 1541095886},
    #     page=1)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()

    # content-lt
    # # TODO BUG: "last_transactions" is completely ignored when "content_hash" is present
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     last_transactions=10)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 0
    # # TODO BUG: "last_transactions" is completely ignored when "content_hash" and "page" are present
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     last_transactions=10,
    #     page=0)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()

    # content-any
    # # TODO BUG: "tags_any" is ignored when "content_hash" is requested
    # # A curl command returns the correct response.
    # # The difference between this is and a curl command is that page 0 is
    # # requested here whereas a curl command doesn't request any pages.
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     tags_any=["simple tag"])
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 0
    # # TODO BUG: "tags_any" is ignored when "content_hash" and "page" are requested
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     tags_any=["simple tag"],
    #     page=0)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()

    # content-all
    # # TODO BUG: "tags_all" is ignored "content_hash" is requested
    # # A curl command returns the correct response.
    # # The difference between this is and a curl command is that page 0 is
    # # requested here whereas a curl command doesn't request any pages.
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     tags_all=['hi', 'there'])
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 0
    # # TODO BUG: "tags_all" is ignored "content_hash" and "page" are requested
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     tags_all=['hi', 'there'],
    #     page=0)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()

    # content-page
    # TODO BUG: 'tag_merkle_root' is returned for some transactions but not for all
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     page=2)
    # assert len(transactions) == 56

    # trans-range (not particularly useful)
    transactions = admin.get_transactions(
        transaction_hash='QmWe3GYj6wLxDRjCfTUnhD2vXASPTjqsqDmscECsbkiP85',
        range={"From": 0, "To": now})
    assert len(transactions) == 1
    assert transactions[0]["timestamp"] == 1541214538
    # page 0 (not useful)
    # CONFIRMED: "range" is ignored when "transaction_hash" is present
    transactions = admin.get_transactions(
        transaction_hash='QmWe3GYj6wLxDRjCfTUnhD2vXASPTjqsqDmscECsbkiP85',
        range={"From": 0, "To": now},
        page=0)
    assert len(transactions) == 1
    assert transactions[0]["timestamp"] == 1541214538
    # page 1 (not useful, in fact doesn't affect the outcome)
    # CONFIRMED: "page" is ignored when "transaction_hash" is present
    transactions = admin.get_transactions(
        transaction_hash='QmWe3GYj6wLxDRjCfTUnhD2vXASPTjqsqDmscECsbkiP85',
        range={"From": 0, "To": now},
        page=1)
    assert len(transactions) == 1
    assert transactions[0]["timestamp"] == 1541214538

    # trans-lt (not very useful)
    # CONFIRMED: "last_transactions" is ignored when "transaction_hash" is present
    transactions = admin.get_transactions(
        transaction_hash='QmWe3GYj6wLxDRjCfTUnhD2vXASPTjqsqDmscECsbkiP85',
        last_transactions=10)
    assert len(transactions) == 1
    assert transactions[0]["timestamp"] == 1541214538
    # page 0
    transactions = admin.get_transactions(
        transaction_hash='QmWe3GYj6wLxDRjCfTUnhD2vXASPTjqsqDmscECsbkiP85',
        last_transactions=10,
        page=0)
    assert len(transactions) == 1
    assert transactions[0]["timestamp"] == 1541214538
    # page 1
    transactions = admin.get_transactions(
        transaction_hash='QmWe3GYj6wLxDRjCfTUnhD2vXASPTjqsqDmscECsbkiP85',
        last_transactions=10,
        page=1)
    assert len(transactions) == 1
    assert transactions[0]["timestamp"] == 1541214538

    # trans-any (not useful)
    # CONFIRMED: "tags_any" ignored when "transaction_hash" is present
    transactions = admin.get_transactions(
        transaction_hash='QmWe3GYj6wLxDRjCfTUnhD2vXASPTjqsqDmscECsbkiP85',
        tags_any=["simple tag"])
    assert len(transactions) == 1
    assert transactions[0]["timestamp"] == 1541214538
    # page 0
    transactions = admin.get_transactions(
        transaction_hash='QmWe3GYj6wLxDRjCfTUnhD2vXASPTjqsqDmscECsbkiP85',
        tags_any=["simple tag"],
        page=0)
    assert len(transactions) == 1
    assert transactions[0]["timestamp"] == 1541214538
    # page 1
    transactions = admin.get_transactions(
        transaction_hash='QmWe3GYj6wLxDRjCfTUnhD2vXASPTjqsqDmscECsbkiP85',
        tags_any=["simple tag"],
        page=1)
    assert len(transactions) == 1
    assert transactions[0]["timestamp"] == 1541214538

    # trans-all (not useful)
    # CONFIRMED: "tags_all" ignored when "transaction_hash" is present
    transactions = admin.get_transactions(
        transaction_hash='QmWe3GYj6wLxDRjCfTUnhD2vXASPTjqsqDmscECsbkiP85',
        tags_all=["simple tag"])
    assert len(transactions) == 1
    assert transactions[0]["timestamp"] == 1541214538
    # page 0
    transactions = admin.get_transactions(
        transaction_hash='QmWe3GYj6wLxDRjCfTUnhD2vXASPTjqsqDmscECsbkiP85',
        tags_all=["simple tag"],
        page=0)
    assert len(transactions) == 1
    assert transactions[0]["timestamp"] == 1541214538
    # page 1
    transactions = admin.get_transactions(
        transaction_hash='QmWe3GYj6wLxDRjCfTUnhD2vXASPTjqsqDmscECsbkiP85',
        tags_all=["simple tag"],
        page=1)
    assert len(transactions) == 1
    assert transactions[0]["timestamp"] == 1541214538

    # range-lt
    # should be in descending order (reverse=True)
    transactions = admin.get_transactions(
        range={"From": 0, "To": now},
        last_transactions=101)
    assert len(transactions) == 101
    assert transactions == sorted(transactions, key=lambda x: x["timestamp"], reverse=True)
    # page 0
    transactions = admin.get_transactions(
        range={"From": 0, "To": now},
        last_transactions=101,
        page=0)
    assert len(transactions) == 100
    assert transactions == sorted(transactions, key=lambda x: x["timestamp"], reverse=True)
    # page 1
    transactions = admin.get_transactions(
        range={"From": 0, "To": now},
        last_transactions=101,
        page=1)
    assert len(transactions) == 1

    # range-any
    # tags_any appears to take priority over range because these results aren't sorted
    transactions = admin.get_transactions(
        range={"From": 1541098870, "To": 1541098879},
        tags_any=["there"])
    assert len(transactions) == 2
    # page 0
    transactions_p0 = admin.get_transactions(
        range={"From": 1541098870, "To": 1541098879},
        tags_any=["hi"],
        page=0)
    assert transactions_p0 == transactions
    # page 1
    # TODO :{'error': 'false', 'result': None, 'metadata': {'current_page': 1}}
    # TODO: you can request a page that may not have any results
    transactions = admin.get_transactions(
        range={"From": 0, "To": now},
        tags_any=["hi"],
        page=1)
    assert transactions == []

    # range-all
    transactions = admin.get_transactions(
        range={"From": 1541531208, "To": now},
        tags_all=["severity=warning"])
    assert len(transactions) > 141
    # page 0
    transactions_p0 = admin.get_transactions(
        range={"From": 1541531208, "To": now},
        tags_all=["severity=warning"],
        page=0)
    assert transactions_p0 == transactions[:100]
    # page 1
    transactions_p1 = admin.get_transactions(
        range={"From": 1541531208, "To": now},
        tags_all=["severity=warning"],
        page=1)
    assert transactions_p1 == transactions[100:200]

    # range-page
    # ascending order
    # this seems to be much more well-sorted than other "range" combos
    transactions = admin.get_transactions(
        range={"From": 0, "To": now},
        page=0)
    assert transactions == sorted(transactions, key=lambda x: x['timestamp'])
    # page 1
    transactions = admin.get_transactions(
        range={"From": 0, "To": now},
        page=1)
    assert transactions == sorted(transactions, key=lambda x: x['timestamp'])

    # lt-any
    # "last_transactions" ignores "tags_any"
    # TODO: I feel like this could be useful
    transactions = admin.get_transactions(
        last_transactions=101,
        tags_any=["hi"])
    assert len(transactions) == 101
    # page 0
    transactions_p0 = admin.get_transactions(
        last_transactions=101,
        tags_any=["hi"],
        page=0)
    assert len(transactions_p0) == 100
    assert transactions_p0 == transactions[:100]
    # page 1
    transactions_p1 = admin.get_transactions(
        last_transactions=101,
        tags_any=["hi"],
        page=1)
    assert len(transactions_p1) == 1
    assert transactions_p1 == transactions[100:200]

    # lt-all
    # "last_transactions" ignores "tags_all"
    transactions = admin.get_transactions(
        last_transactions=101,
        tags_all=['facility=daemon', 'severity=warning'])
    assert len(transactions) == 101
    # page 0
    transactions_p0 = admin.get_transactions(
        last_transactions=101,
        tags_all=['this should be ignored'],
        page=0)
    assert len(transactions_p0) == 100
    assert transactions_p0 == transactions[:100]
    # page 1
    transactions_p1 = admin.get_transactions(
        last_transactions=101,
        tags_all=["hi"],
        page=1)
    assert len(transactions_p1) == 1
    assert transactions_p1 == transactions[100:200]

    # any-page
    # TODO: when is 'tx_id' field returned?
    tags_any = ['severity=warning']
    transactions = admin.get_transactions(
        tags_any=tags_any,
        page=1)
    assert all([set(tags_any).intersection(trx['tags']) for trx in transactions])

    # all-page
    tags_all = ['appname=rsyslogd', 'severity=warning']
    transactions = admin.get_transactions(
        tags_all=tags_all,
        page=0)
    assert all([set(tags_all).issubset(trx['tags']) for trx in transactions])

    # TODO In general, 3+ parameters yield to the one with the highest priority: content_hash, transaction_hash, or page

    # content_hash and range and tags_any
    # TODO BUG: 'tags_any', 'range', and 'page' ignored when 'content_hash' is set
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     range={"From": 1541214478, "To": now},
    #     tags_any='a normal string')
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # page 0
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     range={"From": 1541214478, "To": now},
    #     tags_any='a normal string',
    #     page=0)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 1
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     range={"From": 1541214478, "To": now},
    #     tags_any='a normal string',
    #     page=1)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()

    # content_hash and range and tags_all
    # TODO BUG: 'tags_all', 'range', and 'page' ignored when 'content_hash' is set
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     range={"From": 1541214478, "To": now},
    #     tags_all="tag")
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 0
    # transactions = admin.get_transactions(
    #     content_hash="QmYWenD9s4amAtpf4rLKWjgndyvdad8HJ7uPVm1dEZMMkQ",
    #     range={"From": 0, "To": now},
    #     tags_all='a normal string',
    #     page=0)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 1
    # transactions = admin.get_transactions(
    #     content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #     range={"From": 0, "To": now},
    #     tags_all='a normal string',
    #     page=1)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()

    # content_hash and last_transactions and tags_any
    # TODO BUG: 'last_transactions' ignored when 'content_hash' set
    # transactions = admin.get_transactions(
    #         content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #         last_transactions=5,
    #         tags_any=["hi"])
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 0
    # transactions = admin.get_transactions(
    #         content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #         last_transactions=5,
    #         tags_any=["hi"],
    #         page=0)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 1
    # transactions = admin.get_transactions(
    #         content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #         last_transactions=5,
    #         tags_any=["hi"],
    #         page=1)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()

    # content_hash and last_transactions and tags_all
    # transactions = admin.get_transactions(
    #         content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #         last_transactions=5,
    #         tags_all=["hi"])
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 0
    # transactions = admin.get_transactions(
    #         content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #         last_transactions=5,
    #         tags_any=["hi"],
    #         page=0)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 1
    # transactions = admin.get_transactions(
    #         content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
    #         last_transactions=5,
    #         tags_any=["hi"],
    #         page=1)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()

    # transaction_hash and range and tags_any
    # Received: {'error': 'false', 'result': [{'merkle_proof': {}}], 'metadata': {'current_page': 0}}
    # Expected: {'error': 'false', 'result': None, 'metadata': {'current_page': 0}}
    # transactions = admin.get_transactions(
    #     transaction_hash="QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh",
    #     range={"From": 0, "To": now},
    #     tags_any=["hi"])
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 0
    # transactions = admin.get_transactions(
    #     transaction_hash="QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh",
    #     range={"From": 0, "To": now},
    #     tags_any=["hi"],
    #     page=0)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 1
    # transactions = admin.get_transactions(
    #     transaction_hash="QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh",
    #     range={"From": 0, "To": now},
    #     tags_any=["hi"],
    #     page=1)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()

    # transaction_hash and range and tags_all
    # Received: {'error': 'false', 'result': [{'merkle_proof': {}}], 'metadata': {'current_page': 0}}
    # Expected: {'error': 'false', 'result': None, 'metadata': {'current_page': 0}}
    # transactions = admin.get_transactions(
    #     transaction_hash="QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh",
    #     range={"From": 0, "To": now},
    #     tags_all=["tag1", "tag2"])
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 0
    # transactions = admin.get_transactions(
    #     transaction_hash="QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh",
    #     range={"From": 0, "To": now},
    #     tags_all=["hi"],
    #     page=0)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 1
    # transactions = admin.get_transactions(
    #     transaction_hash="QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh",
    #     range={"From": 0, "To": now},
    #     tags_all=["hi"],
    #     page=1)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()

    # transaction_hash and last_transactions and tags_any
    # Received: {'error': 'false', 'result': [{'merkle_proof': {}}], 'metadata': {'current_page': 0}}
    # Expected: {'error': 'false', 'result': None, 'metadata': {'current_page': 0}}
    # transactions = admin.get_transactions(
    #     transaction_hash="QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh",
    #     last_transactions=5,
    #     tags_any=["hi"])
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 0
    # transactions = admin.get_transactions(
    #     transaction_hash="QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh",
    #     last_transactions=5,
    #     tags_any=["hi"],
    #     page=0)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 1
    # transactions = admin.get_transactions(
    #     transaction_hash="QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh",
    #     last_transactions=5,
    #     tags_any=["hi"],
    #     page=1)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()

    # transaction_hash and last_transactions and tags_all
    # Received: {'error': 'false', 'result': [{'merkle_proof': {}}], 'metadata': {'current_page': 0}}
    # Expected: {'error': 'false', 'result': None, 'metadata': {'current_page': 0}}
    # transactions = admin.get_transactions(
    #     transaction_hash="QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh",
    #     last_transactions=5,
    #     tags_all=["hi"])
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 0
    # transactions = admin.get_transactions(
    #     transaction_hash="QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh",
    #     last_transactions=5,
    #     tags_all=["hi"],
    #     page=0)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()
    # # page 1
    # transactions = admin.get_transactions(
    #     transaction_hash="QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh",
    #     last_transactions=5,
    #     tags_all=["hi"],
    #     page=1)
    # for trx in transactions:
    #     print(trx)
    # print(len(transactions))
    # input()

    # plain, should fail
    try:
        admin.get_transactions()
    except APIError as e:
        assert str(e.args[0]) == 'Unknown parameters. Check spelling.'

    # return content on
    # works as you would expect
    transactions = admin.get_transactions(
        with_content=True,
        last_transactions=25
    )
    for trx in transactions:
        print(trx)

    # get file
    # returns a URL from which you can download the file
    transaction = admin.get_transactions(
        last_transactions=1,
        with_content=True
    )[0]
    print(transaction)


def test_get_users():
    # Get users default, currently > 100
    print(admin.get_users())

    # Get a specific user
    # Note, this is a search by name, so there isn't much that can go wrong here
    print(admin.get_users("lumberjack"))

    # Get a specific user that I know is not present
    print(admin.get_users("fake user"))


def test_normalize():
    string0 = ""
    string1 = "a normal string"
    string2 = "this string has 50 characters with some extra 日本語."
    string3 = "this string has more than 50 characters to break the tag limit"

    tags1 = [string1]
    try:
        admin._normalize(tags1)
    except ValueError as e:
        assert str(e) == "Tags cannot exceed 50 characters."
    print(1, 'OK')

    tags2 = [string1, string2]
    try:
        admin._normalize(tags2)
    except ValueError as e:
        assert str(e) == "Tags cannot exceed 50 characters."
    print(2, 'OK')

    tags3 = [string1, string2, string3]
    try:
        admin._normalize(tags3)
    except ValueError as e:
        assert str(e) == "Tags cannot exceed 50 characters."
    print(3, 'OK')

    tags4 = {"string1": string1, "string2": string2, "string3": string3}
    try:
        admin._normalize(tags4)
    except ValueError as e:
        assert str(e) == "Tags cannot exceed 50 characters."
    print(4, 'OK')

    tags5 = set(tags3)
    try:
        admin._normalize(tags5)
    except ValueError as e:
        assert str(e) == "Tags cannot exceed 50 characters."
    print(5, 'OK')

    # Coercion
    tl = admin._normalize(tags3, coerce=True)
    assert tl == '{"tags": ["a normal string", "this string has 50 characters with some extra 日本語.", "this string has more than 50 characters to break t"]}'
    print(6, 'OK')

    tl = admin._normalize(tags4, coerce=True)
    assert tl == '{"tags": ["string1=a normal string", "string2=this string has 50 characters with some ex", "string3=this string has more than 50 characters to"]}'
    print(7, 'OK')

    # Falsy string & one
    tl = admin._normalize([string0])
    assert tl == '{"tags": [""]}'
    print(8, 'OK')

    # One string
    tl = admin._normalize(string1)
    assert tl == '{"tags": ["a normal string"]}'
    print(9, 'OK')

    # key
    tl = admin._normalize(string1, key="tags_any")
    assert tl == '{"tags_any": ["a normal string"]}'
    print(10, 'OK')

    # dumps
    tl = admin._normalize(string1, dumps=False)
    assert tl == ["a normal string"]
    print(11, 'OK')

    # Data Type Deluge
    tl = admin._normalize({string3})
    assert tl == '{"tags": ["this string has more than 50 characters to break the tag limit"]}'
    print(12, 'OK')

    tl = admin._normalize(1)
    assert tl == '{"tags": ["1"]}'
    print(13, 'OK')

    tl = admin._normalize(b"byte string")
    assert tl == '{"tags": ["98", "121", "116", "101", "32", "115", "116", "114", "105", "110", "103"]}'
    print(14, 'OK')


def test_verify():
    # Verify some strings
    string1 = "a normal string"
    string2 = "with 日本語の文字 to test API encoding"
    string3 = "this string has 50 characters to test the tag lim."
    string4 = "this string has 50 characters with some extra 日本語."
    string5 = "this string has more than 50 characters to break the tag limit"

    assert admin.verify(content_string=string1)
    print(1, 'OK')

    assert admin.verify(content_string=string2)
    print(2, 'OK')

    assert admin.verify(content_string=string3)
    print(3, 'OK')

    assert admin.verify(content_string=string4)
    print(4, 'OK')

    assert admin.verify(content_string=string5)
    print(5, 'OK')

    # verify a string I know isn't present
    assert not admin.verify(content_string="a normal string 2 -- electric boogaloo")
    print(6, 'OK')

    # verify a string without permission
    admin.revoke('3STYa5OR6J8AWE97ClHhLx1jm2PB04bw', "can_read")
    try:
        lumberjack.verify(content_string=string1)
    except APIError as e:
        assert str(e.args[0]) == 'you are not authorized for this method'
    print(7, 'OK')
    admin.authorize('3STYa5OR6J8AWE97ClHhLx1jm2PB04bw', "can_read")

    # verify the hash for content I know is present
    trx = admin.add_object(string1, 'str')
    assert admin.verify(content_hash=trx["content_hash"])
    print(8, 'OK')

    # verify the hash for content I know is NOT present
    assert not admin.verify(content_hash="this is an obviously-fake hash")
    print(9, 'OK')

    # verify a content hash without permission
    admin.revoke('3STYa5OR6J8AWE97ClHhLx1jm2PB04bw', "can_read")
    try:
        lumberjack.verify(content_hash=trx["content_hash"])
    except APIError as e:
        assert str(e.args[0]) == 'you are not authorized for this method'
    print(10, 'OK')
    admin.authorize('3STYa5OR6J8AWE97ClHhLx1jm2PB04bw', "can_read")

    # verify a transaction hash I know is present
    assert admin.verify(trx["transaction_hash"])
    print(11, 'OK')

    # verify a transaction hash I know is NOT present
    assert not admin.verify(transaction_hash="another clearly-fake hash")
    print(12, 'OK')

    # verify a transaction hash without permission
    admin.revoke('3STYa5OR6J8AWE97ClHhLx1jm2PB04bw', "can_read")
    try:
        lumberjack.verify(transaction_hash=trx["transaction_hash"])
    except APIError as e:
        assert str(e.args[0]) == 'you are not authorized for this method'
    print(13, 'OK')
    admin.authorize('3STYa5OR6J8AWE97ClHhLx1jm2PB04bw', "can_read")

    # verify a file I know is present
    admin.add_file("hello_world.txt", tags=["testing", "hello world", "text"])
    assert admin.verify(filename="hello_world.txt")
    print(14, 'OK')

    # verify a file I know is NOT present
    with open("new_file.txt", "w") as file:
        file.write("verify_file 2: electric boogaloo")
    assert not admin.verify(filename="new_file.txt")
    print(15, 'OK')

    # verify a file without permission
    admin.revoke('3STYa5OR6J8AWE97ClHhLx1jm2PB04bw', "can_read")
    try:
        lumberjack.verify(filename="hello_world.txt")
    except APIError as e:
        assert str(e.args[0]) == 'you are not authorized for this method'
    print(16, 'OK')
    admin.authorize('3STYa5OR6J8AWE97ClHhLx1jm2PB04bw', "can_read")


def test_validate_secret_key():
    try:
        uledger.validate_secret_key('hi')
    except ValueError:
        print(1, 'OK')

    try:
        uledger.validate_secret_key('11111111')
    except ValueError:
        print(2, 'OK')

    try:
        uledger.validate_secret_key('1abcdefg')
    except ValueError:
        print(3, 'OK')

    try:
        uledger.validate_secret_key('1aBCDEFG')
    except ValueError:
        print(4, 'OK')

    uledger.validate_secret_key('1aB*****')
    print(5, 'OK')


def test_generate_secret_key():
    password = uledger.generate_secret_key()
    uledger.validate_secret_key(password)
    print(1, 'OK')


def run_test_suite():
    # test_add_bytes()
    test_add_file()
    test_add_object()
    test_new_confirmed_user()
    test_authorize()
    test_deactivate()
    test_get_content()
    test_get_transactions()
    test_get_users()
    test_normalize()
    test_verify()
    test_validate_secret_key()
    test_generate_secret_key()


if __name__ == "__main__":
    # run_test_suite()
    # for t in admin.get_transactions(range={'From': 1543701000, 'To': 1543701414}):
    #     print(t)
    print(uledger.validate_secret_key('SxPWYj*kK4G0Yc$#'))

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

""" This module is a test suite for the ULedger SDK.

Currently, the tests are NOT blockchain-agnostic. Please contact ULedger for
the appropriate blockchain credentials.
"""

import json
from multiprocessing.dummy import Pool as ThreadPool
import os
import random
import string
import sys
import time
import unittest

# Import the uledger package regardless of where this script is run from.
# This will resolve "attempted relative import with no known parent package."
# All three errors have been encountered on various installs of Python3.5+
try:
    from .. import uledger
except (ImportError, SystemError, ValueError):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    import uledger

with open(os.path.join(os.path.dirname(__file__), "creds.json")) as f:
    try:
        creds = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(
            "creds.txt was not present in the /tests directory.\n"
            "Please populate it using creds_template.json as a guide.\n"
            "admin should have all permissions. lumberjack should have rw.")
    url = creds['url']
    token = creds['token']

# The super-admin for the blockchain.
admin = uledger.BlockchainUser(
    url, token,  creds['admin']['access_key'], creds['admin']['secret_key'])

# A test user
lumberjack = uledger.BlockchainUser(
    url, token, creds['lumberjack']['access_key'], creds['lumberjack']['secret_key'])


class TestAddFile(unittest.TestCase):
    """ Tests the BlockchainUser.add_file() method. """
    def test_normal_file(self):
        tags = ['file']
        path = 'hello_world'
        with open(path, 'w') as file:
            file.write("hello world!")
        to = lumberjack.add_file(path, tags)
        self.assertIsInstance(to, dict, to)
        os.remove(path)

    def test_empty_file(self):
        tags = ['empty', 'file']
        path = 'empty.txt'
        open(path, 'w').close()
        to = lumberjack.add_file(path, tags)
        self.assertIsInstance(to, dict, to)
        os.remove(path)

    def test_really_big_file(self):
        tags = ['>50mb', 'file']
        path = 'really_big_file.txt'
        with open(path, mode='wb') as rbf:
            rbf.write(os.urandom(50 * 2**20 + 1))
        with self.assertRaises(OSError):
            lumberjack.add_file(path, tags=tags)
        os.remove(path)

    def test_context_binary_mode(self):
        path = 'text_mode.txt'
        with open(path, mode='w+b') as file:
            file.write(b'some content to record as binary')
            lumberjack.add_file(file)
        os.remove(path)

    def test_context_text_mode(self):
        path = 'binary_context.txt'
        with open(path, mode='w+') as file:
            file.write('some content to record as text')
            lumberjack.add_file(file)
        os.remove(path)


class TestAddBytes(unittest.TestCase):
    """ Tests the BlockchainUser.add() method with byte strings. """
    def test_normal_bytestring(self):
        to = lumberjack.add(b'hello world!')
        self.assertIsInstance(to, dict, to)

    def test_unusual_bytestring(self):
        to = lumberjack.add('雨の夜のブルース'.encode(), 'test.txt')
        self.assertIsInstance(to, dict, to)

    def test_unusual_bytestring2(self):
        to = lumberjack.add(b'\xe0\x87\x00\x35\x00\x30\x5b\x6d')
        self.assertIsInstance(to, dict, to)

    def test_empty_bytestring(self):
        to = lumberjack.add(b'')
        self.assertIsInstance(to, dict, to)

    def test_too_large_bytestring(self):
        bytestring = os.urandom(50 * 2**20 + 1)
        with self.assertRaises(OSError):
            lumberjack.add(bytestring)

    def test_filename(self):
        to = lumberjack.add(os.urandom(20), 'file.txt')
        self.assertIsInstance(to, dict, to)


class TestAddObjects(unittest.TestCase):
    """ Tests the BlockchainUser.add() method with serialized objects. """
    def test_str(self):
        lumberjack.add(str([1, 2, 3]))

    def test_repr(self):
        lumberjack.add(repr(lumberjack))

    def test_json(self):
        lumberjack.add(json.dumps({'a': 'dictionary'}))


class TestAddString(unittest.TestCase):
    """ Tests the BlockchainUser.add() method with plain strings. """
    sample_tags = ["sampleTag1", "sampleTag2"]

    def test_normal_string(self):
        to = lumberjack.add("a normal string", self.sample_tags)
        self.assertIsInstance(to, dict, to)

    def test_unicode(self):
        to = lumberjack.add(
            "with 日本語の文字 to test API decoding", self.sample_tags)
        self.assertIsInstance(to, dict, to)

    def test_error_message(self):
        with self.assertRaises(ValueError):
            lumberjack.add('"Error: some random text')


# This test is paranoid. Disable it if you want to go fast.
class TestAddUnexpectedStrings(unittest.TestCase):
    """ Tests the BlockchainUser.add() method with unexpected inputs. """
    def _check_and_assert(self, naughty_string):
        to = lumberjack.add(naughty_string, 'naughty string')
        self.assertIsInstance(to, dict, to)
        check = lumberjack.get_content(
            uledger.ipfs_hash(naughty_string)).decode()
        self.assertEqual(naughty_string, check)

    def test_small_list(self):
        slns = [
            '',
            '\n',
            '\0',
            '{"error": "fake error text"}',
            '["more fake text"]',
            '["even", "more", "fake", "text"]',
            '("some", "tuple")',
            '{"key": "value"}',
        ]
        pool = ThreadPool(os.cpu_count())
        pool.map(self._check_and_assert, slns)
        pool.close()
        pool.join()

    def test_big_list(self):
        with open("blns.json", "r") as blns_json:
            blns = json.load(blns_json)
        pool = ThreadPool(os.cpu_count())
        pool.map(self._check_and_assert, blns)
        pool.close()
        pool.join()


class TestTags(unittest.TestCase):
    """ Tests the API server's tag parsing behavior. """
    def test_50_ascii(self):
        to = lumberjack.add(
            "test 50 ascii",
            "this string has 50 characters to test the tag lim.",)
        self.assertIsInstance(to, dict, to)

    def test_50_unicode(self):
        to = lumberjack.add(
            "test 50 unicode"
            "this string has 50 characters with some extra 日本語.")
        self.assertIsInstance(to, dict, to)

    def test_over_50(self):
        with self.assertRaises(uledger.APIError) as e:
            lumberjack.add(
                "test over 50",
                tags="this string has more than 50 characters to break the tag limit")
            self.assertEqual(str(e), "")


class TestNormalize(unittest.TestCase):
    """ Tests the BlockchainUser._normalize() method. """
    def test_normalize_blank_string(self):
        tags = lumberjack._normalize("")
        self.assertEqual(tags, '{"tags": [""]}')

    def test_normalize_normal_string(self):
        tags = lumberjack._normalize("a normal string")
        self.assertEqual(tags, '{"tags": ["a normal string"]}')

    def test_normalize_long_string(self):
        tags = lumberjack._normalize("this string has more than 50 characters to break the tag limit")
        self.assertEqual(tags, '{"tags": ["this string has more than 50 characters to break the tag limit"]}')

    def test_normalize_iterable(self):
        tags = lumberjack._normalize(['a string', 'another string'])
        self.assertEqual(tags, '{"tags": ["a string", "another string"]}')

    def test_normalize_nested_iterable(self):
        tags = lumberjack._normalize(['a string', ['a nested string', 'and another']])
        self.assertEqual(tags, '{"tags": ["a string", "a nested string", "and another"]}')

    def test_normalize_none(self):
        tags = lumberjack._normalize(None)
        self.assertEqual(tags, '{"tags": []}')

    def test_normalize_dictionary(self):
        tags = lumberjack._normalize({"hi": "there", "another": 10})
        self.assertEqual(tags, '{"tags": ["hi=there", "another=10"]}')

    def test_normalize_coerce(self):
        tags = lumberjack._normalize(
            "this string has more than 50 characters to break the tag limit",
            coerce=True)
        self.assertEqual(tags, '{"tags": ["this string has more than 50 characters to break t"]}')

    def test_normalize_key(self):
        tags = lumberjack._normalize("hello", key="tags_any")
        self.assertEqual(tags, '{"tags_any": ["hello"]}')

    def test_normalize_dumps(self):
        tags = lumberjack._normalize("hello", dumps=False)
        self.assertEqual(tags, ['hello'])


class TestNewConfirmedUser(unittest.TestCase):
    """ Tests the BlockchainUser.new_confirmed_user() function. """
    @classmethod
    def setUpClass(cls):
        # random.choices is available beginning in Python3.6
        if sys.version_info[1] > 5:
            cls.name1 = ''.join(
                random.choices(string.ascii_letters, k=random.randint(3, 10)))
            cls.name2 = ''.join(
                random.choices(string.ascii_letters, k=random.randint(3, 10)))

        else:
            cls.name1 = ''.join([random.choice(string.ascii_letters)
                                 for _ in range(random.randint(3, 10))])
            cls.name2 = ''.join([random.choice(string.ascii_letters)
                                 for _ in range(random.randint(3, 10))])

    def test_name_only(self):
        to = admin.new_confirmed_user(self.name1)
        self.assertIsInstance(to, uledger.BlockchainUser, to)

    def test_secret_key(self):
        password = uledger.generate_secret_key()
        to = admin.new_confirmed_user(self.name2, password)
        self.assertIsInstance(to, uledger.BlockchainUser, to)

    def test_weak_secret_key(self):
        with self.assertRaises(ValueError):
            admin.new_confirmed_user(self.name2, "weak_password")


class TestPermissions(unittest.TestCase):
    """ Tests the BlockchainUser.set_permissions(), .get_permissions() and
     .deactivate() methods. """
    @classmethod
    def setUpClass(cls):
        cls.ak = lumberjack.access_key
        cls.activated = {
            'access_key': cls.ak,
            'can_add_permission': True,
            'can_add_user': True,
            'can_read': True,
            'can_write': True,
            'error': 'false'
        }
        cls.deactivated = {
            'error': 'false',
            'access_key': cls.ak
        }

    @classmethod
    def current_permissions(cls):
        return admin.set_permissions(lumberjack.access_key)

    def restore(self):
        return admin.set_permissions(self.ak, 'rw', 'up')

    def test_authorize_and_revoke_one(self):
        perms = admin.set_permissions(self.ak, 'u')
        self.assertTrue(perms['can_add_user'], "'can_add_user' not set.")
        perms = admin.set_permissions(self.ak, revoke='u')
        self.assertNotIn('can_add_user', perms, "Permission still present.")
        self.restore()

    def test_authorize_and_revoke_two(self):
        perms = admin.set_permissions(self.ak, 'up')
        self.assertTrue(perms['can_add_user'], "'can_add_user' not set.")
        self.assertTrue(perms['can_add_permission'], "'can_add_permission' not set.")

        perms = admin.set_permissions(self.ak, revoke='rw')
        self.assertNotIn('can_read', perms, "'can_read' still set.")
        self.assertNotIn('can_write', perms, "'can_write' still present.")

        self.restore()

    def test_authorize_and_revoke_all(self):
        perms = admin.set_permissions(self.ak, 'rwup')
        self.assertDictEqual(perms, self.activated)

        perms3 = admin.set_permissions(self.ak, revoke='rwup')
        self.assertDictEqual(perms3, self.deactivated)

        self.restore()

    def test_authorize_fake(self):
        with self.assertRaises(ValueError) as e:
            admin.set_permissions(self.ak, 'x')
            self.assertEqual(e.exception, "invalid authorize: 'x'")
        self.restore()

    def test_authorize_redundant(self):
        perms1 = admin.set_permissions(self.ak, 'r')
        perms2 = admin.set_permissions(self.ak, 'r')
        self.assertDictEqual(
            perms1, perms2, "Redundant authorization changed permissions")
        self.restore()

    def test_revoke_fake(self):
        with self.assertRaises(ValueError) as e:
            admin.set_permissions(self.ak, revoke='x')
            self.assertEqual(e.exception, "invalid revoke: 'x'")
        self.restore()

    def test_revoke_redundant(self):
        admin.set_permissions(self.ak, revoke='r')
        perms1 = self.current_permissions()
        perms2 = admin.set_permissions(self.ak, revoke='r')
        self.assertDictEqual(perms1, perms2)
        self.restore()

    def test_authorize_without_permission(self):
        admin.set_permissions(self.ak, revoke='p')
        with self.assertRaises(uledger.APIError) as e:
            lumberjack.set_permissions(self.ak, 'r')
            self.assertEqual(e.exception, "you are not authorized to add permission")
        self.restore()

    def test_authorize_bad_key(self):
        with self.assertRaises(uledger.APIError) as e:
            lumberjack.set_permissions("bad key", 'r')
            self.assertEqual(e.exception, "user does not exist")
        self.restore()

    def test_deactivate(self):
        perms = admin.deactivate(self.ak)
        self.assertDictEqual(perms, self.deactivated)
        self.restore()

    def test_deactivate_redundant(self):
        admin.deactivate(self.ak)
        perms = admin.deactivate(self.ak)
        self.assertDictEqual(perms, self.deactivated)
        self.restore()

    def test_deactivate_without_permission(self):
        admin.set_permissions(self.ak, revoke='r')
        with self.assertRaises(uledger.APIError) as e:
            lumberjack.deactivate(self.ak)
            self.assertEqual(e.exception, "you are not authorized to add permission")
        self.restore()

    def test_deactivate_self(self):
        admin.set_permissions(self.ak, 'p')
        perms = lumberjack.deactivate(self.ak)
        self.assertDictEqual(perms, self.deactivated)
        self.restore()

    def test_set_none(self):
        perms1 = self.current_permissions()
        perms2 = admin.set_permissions(self.ak)
        self.assertDictEqual(
            perms1, perms2, 'Blank set changed permissions.')
        self.restore()

    def test_set_and_revoke(self):
        perms1 = self.current_permissions()
        del perms1['can_read']
        perms2 = admin.set_permissions(self.ak, 'r', 'r')
        self.assertDictEqual(perms1, perms2)
        self.restore()

    def test_get_permissions(self):
        perms = admin.set_permissions(self.ak, 'rw', 'up')
        self.assertDictEqual(
            perms, {'error': 'false', 'access_key': self.ak,
                    'can_read': True, 'can_write': True})
        self.restore()


class TestGetTransactions(unittest.TestCase):
    """ Tests the BlockchainUser.get_transactions() method. """

    @classmethod
    def setUpClass(cls):
        cls.now = int(time.time())

    def test_content_hash(self):
        transactions = lumberjack.get_transactions(
            content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
            with_content=True)
        self.assertGreaterEqual(len(transactions), 371)

        for t in transactions:
            self.assertEqual(t['content'], 'a normal string', "content/hash mismatch: {}".format(t))

        transactions0 = lumberjack.get_transactions(
            content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
            page=0,
            with_content=True)
        self.assertEqual(len(transactions0), 100)

        for t0 in transactions0:
            self.assertIn(t0, transactions, "{} not in transactions".format(t0))

    def test_transaction_hash(self):

        transactions = lumberjack.get_transactions(
            transaction_hash='QmbV7dexRqHDk85PRzKE1ZPscUFx5zYQMurpFLC1GVsbYE')
        self.assertEqual(len(transactions), 1)

    def test_range(self):
        then = self.now - 3600
        transactions = lumberjack.get_transactions(
            range={"From": then, "To": self.now})
        self.assertEqual(transactions, sorted(transactions, key=lambda x: x["timestamp"]))
        for t in transactions:
            self.assertLessEqual(then, t['timestamp'])
            self.assertGreaterEqual(self.now, t['timestamp'])

        transactions0 = lumberjack.get_transactions(
            range={"From": then, "To": self.now}, page=0)
        self.assertEqual(transactions0, sorted(transactions, key=lambda x: x["timestamp"]))
        for t in transactions0:
            self.assertLessEqual(then, t['timestamp'])
            self.assertGreaterEqual(self.now, t['timestamp'])

    def test_last_transactions(self):
        transactions = lumberjack.get_transactions(last_transactions=101)
        self.assertEqual(len(transactions), 101)

        transactions0 = lumberjack.get_transactions(
            last_transactions=101, page=0)
        self.assertEqual(len(transactions0), 100)

        transactions1 = lumberjack.get_transactions(
            last_transactions=101, page=1)
        self.assertEqual(len(transactions1), 1)

        # This test is currently failing due to the page sorting issue.
        self.assertEqual(transactions, transactions0 + transactions1)

    def test_tags_any(self):
        transactions = lumberjack.get_transactions(tags_any=["hi"])
        transactions0 = lumberjack.get_transactions(tags_any=["hi"], page=0)
        # This is not as strong as it could be due to the page sorting issue.
        for t0 in transactions0:
            self.assertIn(t0, transactions)

    def test_tags_all(self):
        transactions = lumberjack.get_transactions(tags_all=['hi', 'there'])
        transactions0 = lumberjack.get_transactions(
            tags_all=['hi', 'there'], page=0)
        # This is not as strong as it could be due to the page sorting issue.
        for t0 in transactions0:
            self.assertIn(t0, transactions)

    def test_page(self):
        with self.assertRaises(uledger.APIError) as e:
            lumberjack.get_transactions(page=0)
            self.assertEqual(e.exception, "Unknown parameters. Check spelling.")

    def test_bad_content_hash(self):
        self.assertEqual(lumberjack.get_transactions(content_hash='hi'), [])

    def test_bad_transaction_hash(self):
        self.assertEqual(lumberjack.get_transactions(transaction_hash='hi'), [])

    def test_bad_range(self):
        # The SDK will shield us from stupid mistakes like negative numbers.
        transactions = lumberjack.get_transactions(range={"From": -1, "To": 0})
        self.assertEqual(len(transactions), 0)

        # The SDK will shield us from inverted ranges by inverting them back.
        transactions2 = lumberjack.get_transactions(range=(1, 0))
        self.assertEqual(len(transactions2), 0)

    def test_bad_lt(self):
        with self.assertRaises(uledger.APIError) as e:
            lumberjack.get_transactions(last_transactions=-1)
            self.assertEqual(e.exception, "value cannot be a negative integer")

        with self.assertRaises(uledger.APIError) as e:
            lumberjack.get_transactions(last_transactions='a')
            self.assertEqual(e.exception, 'last_transactions value must be an integer')

    def test_matching_hashes(self):
        with self.assertRaises(ValueError) as e:
            lumberjack.get_transactions(
                content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
                transaction_hash='Qmb4cFnvpxtbLaQxDCj1DXDWxS8Eori7M4AunDNNk5up3m')
            self.assertEqual(e.exception, "transaction_hash must be used alone.")

    def test_non_matching_hashes(self):
        with self.assertRaises(ValueError) as e:
            lumberjack.get_transactions(
                content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
                transaction_hash='QmbhGeh1yoUszaQgtaKnPyXnrJE4VWLmNewmAHm6uVyFRh')
            self.assertEqual(e.exception, "transaction_hash must be used alone.")

    def test_good_content_bad_transaction(self):
        with self.assertRaises(ValueError) as e:
            lumberjack.get_transactions(
                content_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ',
                transaction_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ')
            self.assertEqual(e.exception, "transaction_hash must be used alone.")

    def test_bad_content_good_transaction(self):
        with self.assertRaises(ValueError) as e:
            lumberjack.get_transactions(
                content_hash='hi',
                transaction_hash='QmXWBNjQzK2jYNjAuW2i9YuhAA9jZRv9ihLQNBVqT94qxZ')
            self.assertEqual(e.exception, "transaction_hash must be used alone.")

    def test_bad_content_bad_transaction(self):
        with self.assertRaises(ValueError) as e:
            lumberjack.get_transactions(
                content_hash='hi',
                transaction_hash='star')
            self.assertEqual(e.exception, "transaction_hash must be used alone.")

    # TODO content combinations

    def test_range_lt(self):
        transactions = lumberjack.get_transactions(
            range=(0, self.now), last_transactions=101)

        transactions0 = lumberjack.get_transactions(
            range=(0, self.now), last_transactions=101, page=0)

        # Currently failing due to page sorting issue.
        self.assertListEqual(transactions[:100], transactions0)

    def test_range_any(self):
        # tags_any appears to take priority over range; results aren't sorted
        transactions = lumberjack.get_transactions(
            range=(1541098870, 1541098879), tags_any=["there"])

        transactions0 = lumberjack.get_transactions(
            range=(1541098870, 1541098879), tags_any=["hi"], page=0)

        # Currently failing due to page sorting issue.
        self.assertListEqual(transactions[:100], transactions0)

    def test_range_all(self):
        transactions = lumberjack.get_transactions(
            range=(1541531208, self.now), tags_all=["severity=warning"])

        transactions0 = lumberjack.get_transactions(
            range=(1541531208, self.now), tags_all=["severity=warning"], page=0)

        # Currently failing due to page sorting issue.
        self.assertListEqual(transactions[:100], transactions0)

    def test_range_page(self):
        transactions = lumberjack.get_transactions(range=-3600)
        transactions0 = lumberjack.get_transactions(range=-3600, page=0)

        # Currently failing due to page sorting issue.
        self.assertListEqual(transactions[:100], transactions0)

    def test_lt_any(self):
        transactions = lumberjack.get_transactions(
            last_transactions=101,
            tags_any=["hi", "there"])
        self.assertEqual(len(transactions), 101)

        transactions0 = lumberjack.get_transactions(
            last_transactions=101,
            tags_any=["hi", "there"],
            page=0)
        self.assertEqual(len(transactions0), 100)

        transactions1 = lumberjack.get_transactions(
            last_transactions=101,
            tags_any=["hi", "there"],
            page=1)
        self.assertEqual(len(transactions1), 1)

        # Currently failing due to page sorting issue.
        self.assertListEqual(transactions, transactions0 + transactions1)

    def test_lt_all(self):
        transactions = lumberjack.get_transactions(
            last_transactions=101,
            tags_all=["hi", "there"])
        self.assertEqual(len(transactions), 101)

        transactions0 = lumberjack.get_transactions(
            last_transactions=101,
            tags_all=["hi", "there"],
            page=0)
        self.assertEqual(len(transactions0), 100)

        transactions1 = lumberjack.get_transactions(
            last_transactions=101,
            tags_all=["hi", "there"],
            page=1)
        self.assertEqual(len(transactions1), 1)

        # Currently failing due to page sorting issue.
        self.assertListEqual(transactions, transactions0 + transactions1)


class TestGetContent(unittest.TestCase):
    """ Tests the BlockchainUser.get_content() method. """
    def test_string_content(self):
        content = lumberjack.get_content(uledger.ipfs_hash("hello there"))
        self.assertEqual(content, b"hello there")

    def test_binary_content(self):
        test = b"why hello there!"
        lumberjack.add(test)
        content = lumberjack.get_content(uledger.ipfs_hash(test))
        self.assertEqual(content, test)

    def test_download(self):
        content = lumberjack.get_content(
            uledger.ipfs_hash("hello there"), download=True)
        self.assertEqual(content, None)
        self.assertTrue(os.path.exists(os.path.join(
                os.path.expanduser('~'), 'Downloads', uledger.ipfs_hash("hello there"))))

    def test_bad_hash(self):
        with self.assertRaises(uledger.APIError) as e:
            lumberjack.get_content(uledger.ipfs_hash("something I never recorded"))
            self.assertEqual(e.exception, "there is no transaction with given hash")

    def test_blank(self):
        content = lumberjack.get_content(uledger.ipfs_hash(''))
        self.assertEqual(content, b'')


class TestVerify(unittest.TestCase):
    """ Tests the BlockchainUser.verify() method. """
    def test_verify_normal_string(self):
        content_string = "a normal string"
        lumberjack.add(content_string)
        self.assertTrue(lumberjack.verify(content=content_string))

    def test_verify_unicode_string(self):
        content_string = "with 日本語の文字 to test API encoding"
        lumberjack.add(content_string)
        self.assertTrue(lumberjack.verify(content=content_string))

    def test_verify_fail(self):
        content_string = "this string shall not pass"
        self.assertFalse(lumberjack.verify(content=content_string))

    def test_verify_without_permission(self):
        admin.set_permissions(lumberjack.access_key, revoke="r")
        with self.assertRaises(uledger.APIError) as e:
            lumberjack.verify(content="a normal string")
            self.assertEqual(
                e.exception, 'you are not authorized for this method')
        admin.set_permissions(lumberjack.access_key, authorize="r")

    def test_verify_hash(self):
        content_hash = lumberjack.add("hello there")['content_hash']
        self.assertTrue(lumberjack.verify(content_hash=content_hash))

    def test_verify_bad_hash(self):
        self.assertFalse(lumberjack.verify(content_hash="fail"))

    def test_verify_transaction_hash(self):
        trx_hash = lumberjack.add("hello there")['transaction_hash']
        self.assertTrue(lumberjack.verify(transaction_hash=trx_hash))

    def test_verify_bad_transaction_hash(self):
        self.assertFalse(lumberjack.verify(transaction_hash='fail'))

    def test_verify_file(self):
        with open('test.txt', 'w+') as file:
            file.write('hi there')
            lumberjack.add_file('test.txt')
        self.assertTrue(lumberjack.verify(file='test.txt'))
        os.remove('test.txt')

    def test_verify_bad_file(self):
        with open('test.txt', 'w+b') as file:
            file.write(os.urandom(5))
        self.assertFalse(lumberjack.verify(file='test.txt'))
        os.remove('test.txt')


class TestGenerateSecretKey(unittest.TestCase):
    """ Tests the helpers.generate_secret_key() function. """
    def test_generate_secret_key(self):
        sk = uledger.generate_secret_key()
        self.assertTrue(uledger.validate_secret_key(sk))


class TestValidateSecretKey(unittest.TestCase):
    """ Tests the helpers.validate_secret_key() function. """
    def test_letters(self):
        self.assertFalse(uledger.validate_secret_key('hi'))

    def test_mix1(self):
        self.assertFalse(uledger.validate_secret_key('1abcdefg'))

    def test_mix2(self):
        self.assertFalse(uledger.validate_secret_key('1aBCDEFG'))

    def test_strong(self):
        self.assertTrue(uledger.validate_secret_key('1aB*****'))


if __name__ == "__main__":
    unittest.main()

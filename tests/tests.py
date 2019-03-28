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
from multiprocessing.dummy import Pool as ThreadPool
import unittest

# Import the uledger package regardless of where this script is run from.
# This will resolve "attempted relative import with no known parent package.
# All three errors have been encountered on various installs of Python3.5+
try:
    from .. import uledger
except (ImportError, SystemError, ValueError):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    import uledger
    from uledger import APIError

creds = json.load(open(os.path.join(os.path.dirname(__file__), "creds.txt")))
url = creds['url']
token = creds['token']

# The super-admin for the blockchain.
admin = uledger.BlockchainUser(
    url, token,  creds['admin']['access_key'], creds['admin']['secret_key'])

# A test user
lumberjack = uledger.BlockchainUser(
    url, token, creds['lumberjack']['access_key'], creds['lumberjack']['secret_key'])

'''
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


class TestAddString(unittest.TestCase):
    """ Tests the BlockchainUser.add_string() method. """
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
        with self.assertRaises(APIError) as e:
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


class TestAddBytes(unittest.TestCase):
    """ Tests the BlockchainUser.add_bytes() method. """
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


class TestAddObject(unittest.TestCase):
    """ Tests the BlockchainUser.add_object() method. """
    def test_str(self):
        lumberjack.add([1, 2, 3], 'str')

    def test_repr(self):
        lumberjack.add(lumberjack, 'repr')

    def test_json(self):
        lumberjack.add({'a': 'dictionary'}, 'json')


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

'''
class TestPermissions(unittest.TestCase):
    """ Tests the BlockchainUser.set_permissions(), .get_permissions() and
     .deactivate() methods. """
    @classmethod
    def setUpClass(cls):
        cls.ak = lumberjack.access_key
        cls.activated = {'can_read': True, 'can_write': True, 'can_add_user': True, 'can_add_permission': True}
        cls.revoked = {'can_read': False, 'can_write': False, 'can_add_user': False, 'can_add_permission': False}
        cls.deactivated = {'error': 'false', 'access_key': cls.ak}
        
    @classmethod
    def current_permissions(cls):
        return admin.set_permissions(lumberjack.access_key)

    def restore(self):
        return admin.set_permissions(self.ak, authorize='rw', revoke='pu')   

    def test_authorize_and_revoke_one(self):
        perms = admin.set_permissions(self.ak, authorize='u')
        self.assertTrue(perms['can_add_user'], "'can_add_user' not set.")
        perms = admin.set_permissions(self.ak, revoke='u')   
        self.assertFalse(perms['can_add_user'], "Permission still True.")
        self.restore()

    def test_authorize_and_revoke_two(self):
        perms = admin.set_permissions(self.ak, authorize='up')  
        self.assertTrue(perms['can_add_user'], "'can_add_user' not set.")
        self.assertTrue(perms['can_add_permission'], "'can_add_permission' not set.")

        perms = admin.set_permissions(self.ak, revoke='rw')     
        self.assertFalse(perms['can_read'], "'can_read' still True.")
        self.assertFalse(perms['can_write'], "'can_write' still True.")

        self.restore()

    def test_authorize_and_revoke_all(self):
        perms = admin.set_permissions(self.ak, authorize='rwup')
        self.assertDictEqual(perms, self.activated)

        perms3 = admin.set_permissions(self.ak, revoke='rwup')
        self.assertDictEqual(perms3, self.revoked)

        self.restore()

    def test_authorize_fake(self):
        with self.assertRaises(APIError) as e:
            admin.set_permissions(self.ak, authorize="fake_permission")
            self.assertEqual(str(e), 'value fake_permission is not proper')
        self.restore()

    def test_authorize_redundant(self):
        perms1 = admin.set_permissions(self.ak, authorize='r') 
        perms2 = admin.set_permissions(self.ak, authorize='r') 
        self.assertDictEqual(
            perms1, perms2, "Redundant authorization changed permissions")
        self.restore()

    def test_revoke_fake(self):
        with self.assertRaises(APIError) as e:
            admin.set_permissions(self.ak, revoke="fake_permission")
            self.assertEqual(str(e), 'value fake_permission is not proper')
        self.restore()

    def test_revoke_redundant(self):
        admin.set_permissions(self.ak, revoke='r') 
        perms1 = self.current_permissions()
        perms2 = admin.set_permissions(self.ak, revoke='r')
        self.assertDictEqual(perms1, perms2)
        self.restore()

    def test_authorize_without_permission(self):
        admin.set_permissions(self.ak, revoke='p')  
        with self.assertRaises(APIError) as e:
            lumberjack.set_permissions(self.ak, authorize='r') 
            self.assertEqual(e.exception, "you are not authorized to add permission")
        self.restore()

    def test_authorize_bad_key(self):
        with self.assertRaises(APIError) as e:
            lumberjack.set_permissions("bad key", authorize='r')
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
        admin.set_permissions(self.ak, revoke='p') 
        with self.assertRaises(APIError) as e:
            lumberjack.deactivate(self.ak)
            self.assertEqual(e.exception, "you are not authorized to add permission")
        self.restore()

    def test_deactivate_self(self):
        admin.set_permissions(self.ak, authorize='p')
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
        perms1['can_read'] = False
        perms2 = admin.set_permissions(self.ak, authorize='r', revoke='r')
        self.assertDictEqual(perms1, perms2)
        self.restore()

    def test_get_permissions(self):
        perms = admin.set_permissions(self.ak, authorize='rw', revoke='up')
        self.assertDictEqual(
            perms, {'can_add_user': False, 'can_add_permission': False, 
                    'can_read': True, 'can_write': True})
        self.restore()


class TestVerify(unittest.TestCase):
    """ Tests the BlockchainUser.verify() method. """
    def test_verify_normal_string(self):
        content_string = "a normal string"
        lumberjack.add(content_string)
        self.assertTrue(lumberjack.verify(content_string=content_string))

    def test_verify_unicode_string(self):
        content_string = "with 日本語の文字 to test API encoding"
        lumberjack.add(content_string)
        self.assertTrue(lumberjack.verify(content_string=content_string))

    def test_verify_fail(self):
        content_string = "this string shall not pass"
        self.assertFalse(lumberjack.verify(content_string=content_string))

    def test_verify_without_permission(self):
        admin.set_permissions(lumberjack.access_key, revoke="can_read")
        with self.assertRaises(APIError) as e:
            lumberjack.verify(content_string="a normal string")
            self.assertEqual(
                e.exception, 'you are not authorized for this method')
        admin.set_permissions(lumberjack.access_key, authorize="can_read")

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
        self.assertTrue(lumberjack.verify(filename='test.txt'))
        os.remove('test.txt')

    def test_verify_bad_file(self):
        with open('test.txt', 'w+b') as file:
            file.write(os.urandom(5))
        self.assertFalse(lumberjack.verify(filename='test.txt'))
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


# This test is paranoid. Disable it if you want to go fast.
'''
class TestNaughtyStrings(unittest.TestCase):
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
'''

if __name__ == "__main__":
    unittest.main()

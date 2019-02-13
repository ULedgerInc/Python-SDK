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

""" This is the core module for the ULedger SDK. It implements the
BlockchainUser class, which acts as an interface to the ULedger API.
"""

from collections import abc
import io
import json
import operator
import os
import time

import requests
from requests_toolbelt import MultipartEncoder

from . import helpers
from .exceptions import APIError


class BlockchainUser:
    """ A programmatic interface between a user and a ULedger blockchain.

    To create a BlockchainUser object, you will need a URL and API token for a
    blockchain and a key-pair belonging to one of its users.

    Attributes:
        url (str): A URL for a ULedger blockchain.
        token (str): The blockchain's API token.
        access_key (str): An access key for one of the blockchain's users.
        secret_key (str): The user's secret key.
    """
    def __init__(self, url, token, access_key, secret_key):
        self.url = url
        self.token = token
        self.access_key = access_key
        self.secret_key = secret_key

    def __repr__(self):
        return ("{}({}, {}, {}, {})".format(
            self.__class__.__name__,
            self.url, self.token, self.access_key, self.secret_key))

    def __str__(self):
        return str(self.__dict__)

    # ----------------
    # Internal Methods
    # ----------------

    def _add_stream(self, stream, filename='', tags=None, coerce=False):
        """ Adds binary content from an in-memory stream to the blockchain.

        The acting user must have 'can_write' permissions.

        Arguments:
            stream (io.BufferedIOBase, io.RawIOBase): A stream or file object
                to add to the blockchain. The stream cannot exceed 50MiB.
            filename (str): An optional filename to record as metadata. If left
                unspecified, the actual file name will be used if available with
                the stream's SHA2-256 multihash as a fallback.
            tags (any): Metadata to record alongside the binary content.
            coerce (bool): Force tags into the proper form (see _normalize()).

        Raises:
            ValueError: The stream began with b'"Error: '.
            OSError: The stream exceeded 50MiB.

        Returns:
            dict: the new Transaction Object
        """
        # If the API server encounters an error, it will respond with a message
        # starting with '"Error: '. But if someone wants to add one of those
        # strings to the blockchain, there would be no way to tell them apart.
        # To avoid this, byte strings starting with b'"Error: ' are disallowed.
        if stream.read(8) == b'"Error: ':
            raise ValueError('The stream cannot begin with '"Error: '")

        # Check if the stream contains more than 50MiB of content.
        # tell() shouldn't normally be needed since seek() should return the
        # current position, but sometimes seek() is poorly implemented and
        # returns None (such as tempfile.SpooledTemporaryFile).
        stream.seek(0, io.SEEK_END)
        if stream.tell() > 50 * 1024 * 1024:
            raise OSError("The stream cannot be larger than 50MiB.")
        stream.seek(0, io.SEEK_SET)

        if not filename:
            try:  # File objects will have a name, but io.BytesIO objects won't
                filename = stream.name
            except AttributeError:
                filename = helpers.ipfs_hash(stream.read()) + '.txt'
                stream.seek(0, io.SEEK_SET)

        fields = {
            "user": self._user(),
            "content_file": (filename, stream),
            "metadata": self._normalize(tags, coerce=coerce)
        }

        return self._call_api("/store/add", fields)["result"]

    def _call_api(self, endpoint, fields):
        """ Calls the API.

        Args:
            endpoint (str): An API endpoint to request from.
            fields (dict): Fields used to construct the multipart request.

        Returns:
            A dict with 0, 1, or 2+ Transaction Objects.

        Raises:
            APIError: Something went wrong with the API.
            requests.RequestException: Something went wrong with the request.
        """
        # Format the request information.
        url = self.url + endpoint
        data = MultipartEncoder(fields=fields)
        headers = {"Content-Type": data.content_type, "token": self.token}

        # Send the request and raise any errors that occurred.
        r = requests.post(url, data=data, headers=headers, timeout=10)
        r.raise_for_status()

        # Convert the response to a dictionary and check it for errors.
        r.encoding = 'utf-8'
        response = r.json()        # TODO decode to TransactionObject
        error = response["error"]
        if error != "false":
            raise APIError(error, fields)

        return response

    def _call_api2(self, endpoint, fields, download=False):
        """ Calls the API and streams its response.

        This function has two return types to help differentiate between
        transactions that are downloaded and transactions that contain empty
        strings or byte strings.

        Args:
            endpoint (str): An API endpoint to request from.
            fields (dict): Fields used to construct the multipart request.
            download (bool): If download is True, the response will be saved as
                a file in the Downloads folder instead of being returned.

        Returns:
            bytes: If the request was successful, the transaction content will
                be returned as a byte string.
            None: If the request was successful and download is True, then None
                will be returned.

        Raises:
            APIError: Something went wrong with the API.
            requests.RequestException: Something went wrong with the request.
        """
        # Format the request information
        url = self.url + endpoint
        data = MultipartEncoder(fields=fields)
        headers = {"Content-Type": data.content_type, "token": self.token}

        # Send the request and raise any errors that occurred.
        r = requests.post(url, data=data, headers=headers, timeout=10, stream=True)
        r.raise_for_status()

        # Check if the API server responded with an error message.
        if r.content[:8] == b'"Error: ':
            error_msg = r.content[8:].decode('utf-8').rstrip('\n\"')
            raise APIError(error_msg, fields)

        # Stream the response to a unique file in the user's Downloads folder.
        if download:
            filename = endpoint.rsplit(sep='=', maxsplit=1)[1]
            dest = os.path.join(os.path.expanduser('~/Downloads'), filename)
            with open(dest, 'wb') as f:
                for chunk in r.iter_content(chunk_size=4096):
                    if chunk:  # filter out keep-alive chunks
                        f.write(chunk)
            r.close()
            return None

        return r.content

    @staticmethod
    def _normalize(md, coerce=False, dumps=True, key="tags"):
        """ Normalizes data according to API metadata requirements.

        The API expects a list of no more than 50 metadata "tags". A tag is a
        string of no more than 50 UTF-8 characters. If you fail to meet these
        requirements, the API server will reject your request.

        Args:
            md (any): A collection of tags to be normalized. md may be a regular
                variable, None, or something with an __iter__() method. str and
                bytes objects will be treated as a single tag. Dictionaries will
                be converted into a list of key-value strings delimited by an
                '=', ['like=this']. Nested iterables will be flattened.
            coerce (bool): If True, md will be forcibly shortened to 50 tags.
            dumps (bool): If True, then the final list of metadata will be
                serialized into a JSON-formatted string.
            key (str): If dumps is set to True, this argument will be used to
                address the normalized metadata in the JSON string.
                e.g.: '{"<key>": "<normalized_metadata>"}'

        Returns:
            JSON: If dumps is True, a JSON-formatted string will be returned.
            [str]: If dumps is False, a list of strings will be returned.
        """
        if md is None:
            tag_list = []
        elif isinstance(md, str):
            tag_list = [md]
        elif isinstance(md, bytes):
            tag_list = [md.decode()]
        elif isinstance(md, dict):
            tag_list = ["{}={}".format(key, value) for key, value in md.items()]
        elif not isinstance(md, abc.Iterable):  # Something with __iter__()
            tag_list = [str(md)]
        else:
            tag_list = list(map(str, helpers.flatten(md)))

        if coerce:
            tag_list = tag_list[:50]
            for i, t in enumerate(tag_list):
                tag_list[i] = tag_list[i][:50]

        if dumps:
            return json.dumps({key: tag_list}, ensure_ascii=False)
        else:
            return tag_list

    def _user(self, **kwargs):
        """ Serializes the user's key pair and any number of keyword arguments
        into a JSON-formatted string.
        """
        return json.dumps({
            "access_key": self.access_key,
            "secret_key": self.secret_key,
            **kwargs
        }, ensure_ascii=False)

    # ---------------
    # User Management
    # ---------------

    def admin(self, name):
        """ Initializes the blockchain's super admin.

        Before sending any requests to a ULedger blockchain, you must first
        initialize the super admin. The super admin is a permanent entity that
        will preside over the blockchain and the rest of its users. The super
        admin will have access to all permissions and cannot be deleted.

        This method will set the super admin's access key and secret key using
        self.access_key and self.secret key. The secret key must be at least 8
        characters long and contain at least one lowercase, uppercase, digit,
        and punctuation character. For generating and validating secret keys,
        see helpers.generate_secret_key() and helpers.validate_secret_key().
        There are no restrictions on access keys.

        IT IS IMPERATIVE THAT YOU DO NOT LOSE ACCESS TO THE SUPER ADMIN.
        If you lose the super admin's secret key, a bad actor will be able to
        write to your blockchain, add malicious users, and modify permissions.

        This method can only be used once per blockchain.

        Args:
            name (str): A name for the super admin. Names can have duplicates.

        Returns:
            dict: The super admin's user information.
        """
        fields = {"user": self._user(
            admin_name=name, repeat_secret_key=self.secret_key)}
        return self._call_api("/store/admin", fields)

    def get_users(self, name="", access_key=""):
        """ Retrieves a list of users with access to the blockchain.

        The acting user must have 'can_read' permissions.

        Args:
            name (str): A user name to search for. If specified, the user(s)
                with the exact same name (if any) will be returned.
            access_key (str): An access key to search for. If specified, the
                associated user will be returned.

        Returns:
            [dict]: If a matching name or access key is found, the matching
                user(s) is/are returned as a list of dictionaries. If no
                arguments are supplied, every user will be returned instead.
            []: If no matching name or access key is found.
        """
        fields = {
            "user": self._user(),
            "name": name,
            "access_key": access_key
        }
        try:
            return self._call_api("/store/users", fields)["result"]
        except KeyError:  # "result" field not returned when no users are found
            return []

    def new_confirmed_user(self, name, secret_key=""):
        """ Adds a new user to the blockchain and confirms them.

        The acting user must have 'can_add_user' permissions.

        Args:
            name (str): A name for the new user. Names can have duplicates.
            secret_key (str): A secret key for the new user. If unspecified,
                the API server will assign you a random one. Secret keys must be
                at least 8 characters long and contain at least one lowercase,
                uppercase, digit, and punctuation character. For help, see
                helpers.generate_secret_key() and helpers.validate_secret_key().

        Returns:
            BlockchainUser: If all goes well, a BlockchainUser object created
                from the blockchain's URL and API token and the new user's key
                pair will be returned.

        Raises:
            ValueError: secret_key was not strong enough.
        """
        if secret_key and not helpers.validate_secret_key(secret_key):
            raise ValueError(
                'Your secret key must be 8 characters long and contain at'
                'least one lowercase, uppercase, digit, and punctuation mark.')

        # Create a new user.
        user = self._call_api(
            "/store/newUser", {"user": self._user(new_user_name=name)})
        access_key, temp_secret_key = user["access_key"], user["secret_key"]

        if not secret_key:
            secret_key = temp_secret_key

        # Confirm the new user.
        fields = {
            "user": json.dumps({
                "access_key": access_key,
                "old_secret_key": temp_secret_key,
                "new_secret_key": secret_key,
                "repeat_secret_key": secret_key
            }, ensure_ascii=False)
        }
        self._call_api("/store/confirmUser", fields)

        return self.__class__(self.url, self.token, access_key, secret_key)

    def set_permissions(self, target_access_key, authorize='', revoke=''):
        """ Grants and/or revokes permissions to/from a user.

        Permissions that are specified in both authorize and revoke will be
        revoked. Repeatedly modifying a permission does nothing. You can grant
        and revoke permissions from yourself. The super admin cannot have their
        permissions modified.

        Permissions are designated using character strings composed of 'r', 'w',
        'u', and 'p', which stand for 'can_read', 'can_write', 'can_add_user',
        and 'can_add_permission' respectively. Any combination is valid.

        The acting user must have 'can_add_permission' permissions.

        Args:
            target_access_key (str): A user to authorize.
            authorize (str): A string of characters designating permissions to
                to grant to the user.
            revoke (str): A string of characters designating permissions to
                revoke from the user.

        Returns:
            dict: If all goes well, the user's updated information (including
                their access key, name, ID, and permissions) will be returned.
        """
        permissions = helpers.permissions
        fields = {"user": self._user(
            user_to_auth_access_key=target_access_key,
            revoke=[permissions[c] for c in revoke if c in permissions],
            authorize=[permissions[c] for c in authorize if c in permissions])
        }
        return self._call_api("/store/authorize", fields)

    def get_permissions(self, target_access_key):
        """ Retrieves a user's current permissions.

        The acting user must have 'can_read' permissions.

        Args:
            target_access_key (str): A user to retrieve permissions from.

        Returns:
            dict: If all goes well, the user's current information (including
                their access key, name, ID, and permissions) will be returned.
        """
        return self.get_users(access_key=target_access_key)[0]

    def deactivate(self, target_access_key):
        """ Revokes all permissions from a user.

        The acting user must have 'can_add_permission' permissions.

        Args:
            target_access_key (str): A user to deactivate.

        Returns:
            dict: If all goes well, the user's access key and a dummy error
                message will be returned.
        """
        fields = {"user": self._user(
            user_to_auth_access_key=target_access_key, deactivate=True)}
        return self._call_api("/store/authorize", fields)

    # ---------------
    # Data Management
    # ---------------

    def add(self, data, tags=None, coerce=False):
        """ Adds string or bytes data to the blockchain.

        The acting user must have 'can_write' permissions.

        Args:
            data (string, bytes): Data to add to the blockchain.
            tags (any): Metadata to record alongside the data.
            coerce (bool): Force tags into the proper form (see _normalize()).

        Returns:
            dict: If all goes well, the new Transaction Object will be returned.

        Raises:
            ValueError: data began with '"Error: ' or b'"Error: '.
        """
        if isinstance(data, bytes):
            with io.BytesIO(data) as file:
                return self._add_stream(file, tags, coerce)

        # If the API server encounters an error, it will respond with a message
        # starting with '"Error: '. But if someone wants to add one of those
        # strings to the blockchain, there would be no way to tell them apart.
        # To avoid this, strings starting with '"Error: ' are disallowed.
        if isinstance(data, str) and data.startswith('"Error: '):
            raise ValueError("String data cannot begin with '\"Error: '")

        fields = {
            "user": self._user(),
            "content_string": data,
            "metadata": self._normalize(tags, coerce=coerce)
        }
        return self._call_api("/store/add", fields)["result"]

    def add_file(self, file, tags=None, coerce=False):
        """ Adds a file to the blockchain.

        The acting user must have 'can_write' permissions.

        Args:
            file (str, io.IOBase): A file to add to the blockchain.
                File paths and in-memory file objects are both supported.
                The raw file content cannot exceed 50 MiB.
            tags (any): Metadata to record alongside the file.
            coerce (bool): Force tags into the proper form (see _normalize()).

        Returns:
            dict: If all goes well, the new Transaction Object will be returned.
        """
        # If a file path was specified, open the file in binary mode.
        if isinstance(file, str):
            file = open(file, 'rb')

        # If a file object was provided in text mode, grab its raw stream.
        elif isinstance(file, io.TextIOWrapper):
            file = file.buffer.raw  # Underlying binary stream (undocumented)

        # Add the binary content from the file object to the blockchain.
        with file:
            file_name = os.path.basename(file.name)
            return self._add_stream(file, file_name, tags, coerce)

    def get_content(self, content_hash, download=False):
        """ Retrieves content from the blockchain.

        The acting user must have 'can_read' permissions.

        Args:
            content_hash (str): A SHA2-256 multihash to search for on the
                blockchain (see helpers.ipfs_hash()).
            download (bool): If True, the content retrieved from the blockchain
                will be saved to a file in your Downloads folder instead of
                being returned.

        Returns:
            bytes: If the content hash was found on the blockchain, the content
                it addresses will be returned as a byte string.
            None: If download is True.
        """
        endpoint = "/store/content?hash={}".format(content_hash)
        fields = {"user": self._user()}
        return self._call_api2(endpoint, fields, download)

    def get_transactions(self, coerce=False, with_content=False,
                         sort=True, reverse=False, **kwargs):
        """ Queries the blockchain for transactions.

        This method is intended to retrieve transaction metadata, not content.
        To reliably retrieve content from the blockchain, use get_content().

        You can specify any combination of query arguments with the following
        exceptions: (1) transaction_hash must be used alone, (2) if tags_any
        and tags_all are both specified, tags_all will be ignored, (3) page
        cannot be used alone.

        The acting user must have 'can_read' permissions.

        Args:
            coerce (bool): Force tags into the proper form (see _normalize()).
            with_content (bool): If True, a 'content' field will be populated
                for each Transaction Object when possible. If string content is
                encountered, it will be returned in the content field. If binary
                content is encountered, the content field will be populated with
                a URL that can be used to download it.
            sort (bool): If true, transactions will be returned in sorted order.
                Otherwise, sorted order is not guaranteed. Transactions will be
                sorted by timestamp.
            reverse (bool): If sort is True, reverse will be used to control
                the sorting order: False for ascending / chronological order,
                True for descending / reverse chronological order.

        Query Args (kwargs):
            transaction_hash (str): A transaction hash to search for on the
                blockchain. Each transaction on the blockchain has a unique
                transaction hash, so this query parameter will only ever match
                a single transaction.
            content_hash (str): A content hash to search for on the blockchain.
                Matching transactions must have a matching content hash.
            tags_all (any): Metadata to search for on the blockchain. Matching
                transactions must contain every tag specified here.
            tags_any (any): Metadata to search for on the blockchain. Matching
                transactions must match one or more of the tags specified here.
            last_transactions (int): A number of most recent transactions to
                retrieve from the blockchain in reverse chronological order.
                For example, if last_transactions is 10, the 10 most recent
                transactions will be retrieved.
            range (int, float, tuple): A time range to search on the blockchain.
                This can be an integer, float, or pair of integers / floats.
                If a single, negative number is specified, transactions on the
                range [0, time.time() - <num>] will be retrieved. If a single,
                positive number is specified, transactions on the range
                [<num>, time.time()] will be retrieved. if an (A, B) tuple is
                specified, transactions on the range [A, B] or [B, A] will be
                retrieved depending on whether A < B. Matching transactions must
                have been recorded to the blockchain during the specified range.
            page (int): A page of matching transactions to request from the API
                server. If specified, a page containing up to 100 matching
                transactions will be returned. If left unspecified, every
                matching transaction will be returned.

        Returns:
            [dict]: If matching transactions were found, they will be returned
                as a list of dictionaries (Transaction Objects).
            []: If no matches were found, an empty list will be returned.

        Raises:
            ValueError: An illegal combination of parameters was used.
        """
        # Ensure that transaction_hash is only ever used by itself to prevent
        # 'result': [{'merkle_proof': {}}]
        if kwargs.get("transaction_hash") and len(kwargs) > 1:
            raise ValueError("transaction_hash must be used alone.")
        elif kwargs.get("page") and len(kwargs) == 1:
            raise ValueError("page cannot be used alone.")

        # Handle any shortcuts used with the range argument.
        _range = kwargs.get("range")
        now = time.time()
        if isinstance(_range, (int, float)):
            if _range < 0:
                kwargs['range'] = {'From': now + _range, 'To': now}
            elif _range >= 0:
                kwargs['range'] = {'From': _range, 'To': now}
        elif isinstance(_range, tuple):
            a, b = _range[0], _range[1]
            if a < b:
                kwargs['range'] = {'From': _range[0], 'To': _range[1]}
            else:
                kwargs['range'] = {'From': _range[1], 'To': _range[0]}

        # Normalize any metadata that's present. This doubles as validation.
        try:
            kwargs["tags_any"] = self._normalize(
                kwargs["tags_any"], coerce=coerce, dumps=False, key="tags_any")
        except KeyError:
            try:
                kwargs["tags_all"] = self._normalize(
                    kwargs["tags_all"], coerce=coerce, dumps=False, key="tags_all")
            except KeyError:
                pass

        # Select the endpoint to use.
        if with_content:
            endpoint = "/store/getTransactionsWithContent"
        else:
            endpoint = "/store/getTransactions"

        # If 'page' exists and is an integer, request the one-and-only page.
        if isinstance(kwargs.get("page"), int):
            fields = {"user": self._user(), "metadata": json.dumps(kwargs)}
            try:
                transactions = self._call_api(endpoint, fields)["result"] or []
            except APIError as e:
                if str(e) == "No transactions for specified time range.":
                    transactions = []
                else:
                    raise

        # Otherwise get all of the pages via pagination.
        else:
            transactions = []
            kwargs["page"] = 0
            fields = {"user": self._user(), "metadata": json.dumps(kwargs)}
            while 1:
                try:
                    result = self._call_api(endpoint, fields)["result"]
                except APIError as e:
                    if str(e) == "No transactions for specified time range.":
                        break  # We've gone too far
                    else:
                        raise  # Elevate a legitimate error
                try:
                    transactions.extend(result)
                except TypeError:
                    break  # No results were found
                if len(transactions) < 100:
                    break  # The next page will be blank

                kwargs["page"] += 1
                fields["metadata"] = json.dumps(kwargs)

        if sort:
            transactions.sort(key=operator.itemgetter("timestamp"), reverse=reverse)

        return transactions

    def verify(self, transaction_hash='', content_hash='', content='', file=''):
        """ Checks whether a hash, string, or file is present on the blockchain.

        If multiple arguments are supplied, only one will be considered.
        Arguments are prioritized from left to right:
            transaction_hash > content_hash > content > file

        The acting user must have 'can_read' permissions.

        Args:
            transaction_hash (str): A transaction hash to verify.
            content_hash (str): A content hash to verify.
            content (str): A content string to verify.
            file (str): A path to a file to verify.

        Returns:
            True: If the verification succeeded, True will be returned.
            False: If the verification failed, False will be returned.
        """
        fields = {"user": self._user()}

        if transaction_hash:
            fields["metadata"] = json.dumps({"transaction_hash": transaction_hash})
        elif content_hash:
            fields["metadata"] = json.dumps({"content_hash": content_hash})
        elif content:
            string_hash = helpers.ipfs_hash(content)
            fields["metadata"] = json.dumps({"content_hash": string_hash})
        elif file:
            with open(file, mode='rb') as f:
                file_hash = helpers.ipfs_hash(f.read())
            fields["metadata"] = json.dumps({"content_hash": file_hash})

        try:
            self._call_api("/store/verify", fields)
        except APIError as e:
            if str(e) == 'The transaction is not registered.':
                return False
            else:
                raise

        return True

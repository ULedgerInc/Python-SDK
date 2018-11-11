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
       In general, you can add data, query data, and manage users.

Example:
    import uledger
    jackson = uledger.BlockchainUser("url", "token", "access_key", "secret_key")
    jackson.add_string("hello world!")

Once you put data on a ULedger blockchain, you cannot delete or modify it.
Check that your data is clean and proper BEFORE you record it to the blockchain.

References:
    https://stackoverflow.com/a/2164383
    https://stackoverflow.com/a/2466207
    https://stackoverflow.com/a/16696317
"""

from collections.abc import Iterable
import json
import operator
import os

import requests
from requests_toolbelt import MultipartEncoder

from . import helpers
from .exceptions import APIError


class BlockchainUser:
    """ Creates an interface between a user and a blockchain.

    Every ULedger blockchain has its own URL, API token, and users (as well
    as a controlling super admin). Each user has their own unique access key,
    secret key, and permissions.

    To send requests to a blockchain, you will need its URL, token, and a
    key-pair belonging to one of its users. The user in question must also
    have permission to perform the requested action.

    WARNING: IF YOU LOSE YOUR SECRET KEY, YOU CANNOT GET IT BACK OR RESET IT.
    It is your responsibility to store your secret key and keep it secure;
    treat it like you would any other password.

    Users can have any combination of 'can_read', 'can_write', 'can_add_user',
    and 'can_add_permission' permissions. The super admin has all four
    permissions and cannot have their permissions modified by anyone.

    'can_read': the user can read content from the blockchain
    'can_write': the user can write content to the blockchain
    'can_add_user': the user can add more users to the blockchain
    'can_add_permission': the user can grant or revoke permissions

    Many of the methods in this class return dictionaries built from
    Transaction Objects. See the API guide for details.

    Args:
        url (str): the url to a ULedger blockchain
        token (str): the blockchain's API token
        access_key (str): the access key for one of the blockchain's users
        secret_key (str): the user's secret key
    """
    def __init__(self, url, token, access_key, secret_key):
        self.url = url
        self.token = token
        self.access_key = access_key
        self.secret_key = secret_key

    def __repr__(self):
        return (f"{self.__class__.__name__}({self.url}, {self.token}, "
                f"{self.access_key}, {self.secret_key})")

    def __str__(self):
        return str(self.__dict__)

    # ----------------
    # Internal Methods
    # ----------------

    def _call_api(self, endpoint, fields):
        """ Calls the API and returns its response. This is an internal method
        that you should never need to call directly.

        Args:
            endpoint (str): the API endpoint to request from
            fields (dict): the fields used to construct the multipart request

        Raises:
            APIError: if something went wrong with the API
            requests.exceptions.RequestException: if an error was encountered
                while making the request

        Returns:
            dict: if the response included a single transaction object,
                it will be returned as a dictionary.
            list of dict: if the response included multiple transaction objects,
                they will be returned as a list of dictionaries.
        """
        # Format the request information.
        url = f"{self.url}{endpoint}"
        data = MultipartEncoder(fields=fields)
        headers = {"Content-Type": data.content_type, "token": self.token}

        # Send the request and raise any errors that occurred.
        r = requests.post(url, data=data, headers=headers, timeout=10)
        r.raise_for_status()

        # Convert the response to a dictionary and check it for errors.
        r.encoding = 'utf-8'
        response = r.json()
        error = response["error"]
        if error != "false":  # == True
            raise APIError(error, response)

        return response

    def _call_api2(self, endpoint, fields, download=False):
        """ Calls the API and streams its response. This is an internal method
        built specifically for the 'getContent' endpoint that you should never
        need to call directly.

        Args:
            endpoint (str): the API endpoint to request from
            fields (dict): the fields used to construct the multipart request
            download (bool): if download is True, then any files that are
                sent back with the response will be downloaded. Otherwise,
                those files will be ignored.

        Raises:
            APIError: if something went wrong with the API
            requests.exceptions.RequestException: if something went wrong with
                the request

        Returns:
            dict: if the response included a single transaction object,
                it will be returned as a dictionary.
            list of dict: if the response included multiple transaction objects,
                they will be returned as a list of dictionaries.
        """
        # Format the request information
        url = f"{self.url}{endpoint}"
        data = MultipartEncoder(fields=fields)
        headers = {"Content-Type": data.content_type, "token": self.token}

        # Send the request and raise any errors that occurred.
        r = requests.post(url, data=data, headers=headers, timeout=10, stream=True)
        r.raise_for_status()

        # Stream any file in the response to the Downloads folder.
        # TODO this may fail for files without extensions
        if download and "." in r.headers["Content-Disposition"]:
            filename = endpoint.rsplit(sep='=', maxsplit=1)[1]
            dest = os.path.join(os.path.expanduser("~"), "Downloads", filename)
            with open(dest, 'wb') as f:
                for chunk in r.iter_content(chunk_size=4096):
                    if chunk:  # filter out keep-alive chunks
                        f.write(chunk)
            r.close()
            return None

        # Convert the response to text and check it for API errors.
        r.encoding = 'utf-8'
        response = r.text  # set to 'replace' by default
        if response.startswith('"Error: '):  # == True
            error_msg = response[8:].strip('\"\n')
            raise APIError(error_msg)

        return response

    @staticmethod
    def _normalize(md, coerce=False, dumps=True, key="tags"):
        """ Normalizes data according to the API metadata requirements.

        When you record data to the blockchain, you can also record metadata.
        The API strictly expects a list strings (tags). The list may contain
        up to 50 tags. Each tag can be up to 50 characters long.

        This method will accept *any* regular data type and any object that
        provides the __iter()__ method and flatten it into a list of strings.
        Dictionaries will be converted into a list of key-value strings
        delimited by an '=' ['like=this', ...].

        Args:
            md (any): the variable or iterable that will be normalized into
                a metadata list. md can be None, a regular data type,
                a dictionary, or any iterable that supports __iter__().
                str and bytes objects are treated as a single value rather
                than as an iterable.
            coerce (bool): if coerce is set to True, the metadata list will be
                forcibly shortened to 50 tags of no more than 50 characters
                each. Otherwise, the originally data will not be modified.
                If you fail to meet the metadata requirements, the API server
                will reject your transaction and return an error.
            dumps(bool): if dumps is set to True, then the final list will
                also be serialized into a JSON-formatted string.
            key (str): if dumps is set to True, then this argument will be
                used to form the key-value pair with the normalized metedata
                for the JSON string.

        Returns:
            JSON: if dumps is True, the normalized metadata will be returned
                as a JSON-formatted string.
            list of str: if dumps is False, the normalized metadata will be
                returned as a list of strings.
        """
        if md is None:
            tag_list = []
        elif isinstance(md, str):
            tag_list = [md]
        elif isinstance(md, dict):
            tag_list = [f"{key}={value}" for key, value in md.items()]
        elif not isinstance(md, Iterable):
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
        """ Serializes any number of keyword arguments along with the user's
        access key and secret key into a JSON-formatted string.
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
        """ Creates the initial admin user.

        This is an unusual method that can only be used once per blockchain.
        When a blockchain is first created, no users are created along with it.
        Instead, you would use this method to create the super admin.

        The super admin comes with all permissions and cannot be deleted.
        However, this makes it imperative that you keep the super admin's
        secret key safe and secure so that it will not be lost or abused.

        The super admin's access key and secret key will be set from
        self.access_key and self.secret_key when this method is called.
        There are no restrictions on access keys, but the API requires all
        secret keys to be at least 8 characters long and contain one lowercase
        letter, one uppercase letter, one digit, and one punctuation mark.
        Use the helpers.generate_secret_key() function to generate one.

        Args:
            name (str): the name to give to the super admin

        Returns:
            dict: a dictionary with the admin's user information
        """
        fields = {"user": self._user(
            admin_name=name, repeat_secret_key=self.secret_key)}
        return self._call_api("/store/admin", fields)

    def authorize(self, target_access_key, *permissions):
        """ Grants permissions to a user.

        Repeatedly granting a permission does nothing. You can grant permissions
        to yourself. The super admin cannot have their permissions modified.

        The acting user must have 'can_add_permission' permissions.

        Args:
            target_access_key (str): the user to authorize
            permissions (list of str): permissions to grant to the user.
                When calling this method, simply specify any combination of
                'can_read', 'can_write', 'can_add_user', or 'can_add_permission'
                as parameters or as a list of strings.

        Returns:
            dict: the user's updated information including their access
                key and any permissions they now have access to
        """
        fields = {"user": self._user(
            user_to_auth_access_key=target_access_key, authorize=permissions)}
        return self._call_api("/store/authorize", fields)

    def confirm_user(self, access_key, old_secret_key, new_secret_key=""):
        """ Confirms a new user.

        After adding a user to the blockchain, you must also confirm them.
        The API server will reject requests from unconfirmed users.

        To confirm a user, they must first be added through the new_user method.
        However, when possible, we recommend that you use new_confirmed_user()
        instead of using new_user() and confirm_user() separately; it's easier
        to use and provides better continuity.

        The acting user must have 'can_add_user' permissions.

        Args:
            access_key (str): the user-to-confirm's access key
            old_secret_key (str): the user-to-confirm's temporary secret key
            new_secret_key (str): the user-to-confirm's new secret key.
                If new_secret_key is not specified, old_secret_key will become
                the user's new permanent secret key.

        Returns:
            BlockchainUser: created from your blockchain's URL and token
                and the confirmed user's access key and secret key
        """
        if not new_secret_key:
            new_secret_key = old_secret_key

        fields = {
            "user": json.dumps({
                "access_key": access_key,
                "old_secret_key": old_secret_key,
                "new_secret_key": new_secret_key,
                "repeat_secret_key": new_secret_key
            }, ensure_ascii=False)}

        self._call_api("/store/confirmUser", fields)
        return self.__class__(self.url, self.token, access_key, new_secret_key)

    def deactivate(self, target_access_key):
        """ Removes all permissions from a user.

        Deactivating a user multiple times does nothing. You can deactivate
        yourself. The super admin cannot be deactivated.

        The acting user must have 'can_add_permission' permissions.

        Args:
            target_access_key (str): the user to deactivate
        """
        fields = {"user": self._user(
            user_to_auth_access_key=target_access_key, deactivate=True)}
        return self._call_api("/store/authorize", fields)

    def get_users(self, name=""):
        """ Gets a list of users with access to the blockchain.

        The acting user must have 'can_read' permissions.

        Args:
            name (str): user name to search for. If name is specified, the
                user or users with the exact same name will be returned.
                If name is left unspecified, a list of every user on the
                acting user's blockchain will be returned.

        Returns:
            []: if no matches are found
            list of dict: if a matching name is found, the matching user(s)
                is/are returned as a list of dictionaries.
        """
        fields = {"user": self._user(), "name": name}
        try:
            return self._call_api("/store/users", fields)["result"]
        except KeyError:  # "result" field not returned when no users are found
            return []

    def new_user(self, name):
        """ Adds a user to the blockchain.

        Once a new user is created, they MUST be confirmed with the
        confirm_user() method before they can take any actions. Unconfirmed
        users will have all of their requests rejected.

        When possible, we recommend that you use new_confirmed_user() instead
        of using new_user() and confirm_user() separately; it's easier to use
        and provides better continuity.

        The acting user must have 'can_add_user' permissions.

        Args:
            name (str): a name for the new user. Users can share names.

        Returns:
            (access_key, secret_key): the new user's key pair
        """
        fields = {"user": self._user(new_user_name=name)}
        response = self._call_api("/store/newUser", fields)
        return response["access_key"], response["secret_key"]

    def new_confirmed_user(self, name, new_secret_key=""):
        """ Adds a user to the blockchain and immediately confirms them.

        The acting user must have 'can_add_user' permissions.

        When possible, we recommend that you use new_confirmed_user() instead
        of using new_user() and confirm_user() separately; it's easier to use
        and provides better continuity.

        Args:
            name (str): a name for the new user. Users can share names.
            new_secret_key(str): the user's new secret key. new_secret_key
                must be at least 8 characters long and contain at least one
                lowercase, uppercase, digit, and punctuation character.
                Use helpers.generate_secret_key to generate a secret key.
                If new_secret_key is not specified, the user's temporary secret
                key will become their permanent secret key.

        Returns:
            BlockchainUser: created from your blockchain's URL and token
                and the confirmed user's new access key and secret key
        """
        access_key, secret_key = self.new_user(name)
        return self.confirm_user(access_key, secret_key, new_secret_key)

    def revoke(self, target_access_key, *permissions):
        """ Revokes permissions from a user.

        Revoking a permission multiple times does nothing. You can revoke
        permissions from yourself. The super admin cannot have any of their
        permissions revoked.

        The acting user must have 'can_add_permission' permissions.

        Args:
            target_access_key (str): the user to revoke permissions from
            permissions (list of str): permissions to revoke from the user.
                When calling this method, simply specify any combination of
                'can_read', 'can_write', 'can_add_user', or 'can_add_permission'
                as parameters or as a list of strings.

        Returns:
            dict: the user's updated information including their access
                key and any permissions they still have access to
        """
        fields = {"user": self._user(
            user_to_auth_access_key=target_access_key,
            revoke=permissions)}
        return self._call_api("/store/authorize", fields)

    # ------------------
    # Content Management
    # ------------------

    def add_file(self, filename, tags=None, coerce=False):
        """ Adds a file to the blockchain.

        The blockchain accepts arbitrary data, so you can add any kind of
        file, from raw text to executables and compressed archives. However,
        the API prohibits files over 50MB.

        The acting user must have 'can_write' permissions.

        Args:
            filename (str): the name of / path to the file to upload
            tags (any): metadata to record alongside the file
            coerce (bool): whether the metadata should be coerced into proper
                form before the request (see _normalize() for details)

        Raises:
            OSError: if the file is more than 50MB

        Returns:
            dict: the new transaction's Transaction Object
        """
        if os.stat(filename).st_size > 52428800:
            raise OSError("The maximum file size is 50MB.")

        fields = {
            "user": self._user(),
            "content_file": (filename, open(filename, mode='rb')),
            "metadata": self._normalize(tags, coerce=coerce)
        }

        return self._call_api("/store/add", fields)["result"]

    def add_string(self, content_string, tags=None, coerce=False):
        """ Adds a string to the blockchain.

        The acting user must have 'can_write' permissions.

        Args:
            content_string (str): the string to record to the blockchain
            tags (any): metadata to record to the blockchain
            coerce (bool): whether the metadata should be coerced into proper
                form before the request (see _normalize() for details)

        Returns:
            dict: the new transaction's Transaction Object
        """
        fields = {
            "user": self._user(),
            "content_string": content_string,
            "metadata": self._normalize(tags, coerce=coerce)
        }

        return self._call_api("/store/add", fields)["result"]

    def get_content(self, content_hash, download=False):
        """ Requests the content indexed by content_hash.

        Each piece of content stored on the blockchain is indexed by its
        SHA2-256 multihash. This method will search the blockchain for a
        multihash and return the content that created it. This is very similar
        to the scheme used by the InterPlanetary File System protocol.

        The acting user must have 'can_read' permissions.

        Args:
            content_hash (str): a multihash to search for in the blockchain
            download (bool): when set to True and content_hash points to a file,
                then the file will be downloaded. Otherwise the file content
                will be ignored.

        Returns:
            str: if content_hash points to a string, the string is returned
            None: if content_hash points to a file or does not appear on the
                blockchain, None is returned
        """
        endpoint = f"/store/content?hash={content_hash}"
        fields = {"user": self._user()}
        return self._call_api2(endpoint, fields, download=download)

    def get_transactions(self, coerce=False, with_content=False,
                         ensure_order=True, reverse=True, **kwargs):
        """ Queries the blockchains for transactions.

        The acting user must have 'can_read' permissions.

        Args:
            coerce (bool): if set to True, any metadata specified with tags_any
                or tags_all will be forcibly normalized (see _normalize()).
            with_content (bool): if set to True, transaction content will be
                returned when possible.
            ensure_order (bool): if set to True, transactions will be returned
                in sorted order. By default, transactions are not guaranteed
                to be returned in sorted order.
            reverse (bool): if ensure_order is True, reverse will control the
                order. If reverse is False, then the transactions will be sorted
                in ascending order. If reverse if True, they will be sorted in
                descending order.

        Query Parameters:
            transaction_hash (str): a transaction hash to search for on the
                blockchain. Each transaction on the blockchain has a unique
                transaction hash, so this query parameter will only ever match
                a single transaction. Incompatible with other query parameters.
            content_hash (str): a content hash to search for on the blockchain.
            tags_all (any): metadata to search for on the blockchain.
                In order to match, a transaction must contain every tag
                specified here. Incompatible with tags_any.
            tags_any (any): metadata to search for on the blockchain.
                In order to match, a transaction must contain one or more of
                the tags specified here. Incompatible with tags_all.
            last_transactions (int): the number of most recent transactions to
                to request from the blockchain
            range (dict): a time range to search on the blockchain. This must
                be a {"From": A, "To": B} dictionary where A and B are Unix
                timestamps. A and be must be non-negative integers and A must
                be less than or equal to B. Matching transactions must have
                been recorded to the blockchain during this interval.
            page (int): the page of matching transactions to request from the
                API server. If specified, a page containing up to 100 matching
                transactions will be returned. If left unspecified, every
                matching transaction will be returned.

        Returns:
            list of dict: if matching transactions were found, they will be
                returned as a list of dictionaries
            []: if no matches were found, an empty list will be returned
        """
        # Validate parameters: tags_any and tags_all can't be used together,
        # and transaction_hash can only be used by itself.
        if (kwargs.get("tags_any") and kwargs.get("tags_all")
                or (kwargs.get("transaction_hash") and len(kwargs) > 1)):
            raise ValueError("Illegal parameter combination.")

        # Normalize any metadata that's present.
        try:
            kwargs["tags_any"] = self._normalize(
                kwargs["tags_any"], coerce=coerce, dumps=False, key="tags_any")
        except KeyError:
            pass
        try:
            kwargs["tags_all"] = self._normalize(
                kwargs["tags_all"], coerce=coerce, dumps=False, key="tags_all")
        except KeyError:
            pass

        # Select endpoint
        if with_content:
            endpoint = "/store/getTransactionsWithContent"
        else:
            endpoint = "/store/getTransactions"

        transactions = []

        # If 'page' exists and is an integer, request the one-and-only page.
        if isinstance(kwargs.get("page"), int):
            fields = {"user": self._user(), "metadata": json.dumps(kwargs)}
            transactions = self._call_api(endpoint, fields)["result"] or []  # catch None asap

        # Otherwise get all of the pages via pagination.
        else:
            kwargs["page"] = 0
            fields = {"user": self._user(), "metadata": json.dumps(kwargs)}
            while 1:
                try:
                    result = self._call_api(endpoint, fields)["result"]
                except APIError as e:
                    if str(e.args[0]) == "No transactions for the specified time range.":
                        break  # We've gone too far
                    else:
                        raise  # Elevate a legitimate error
                try:
                    transactions.extend(result)
                except TypeError:
                    break  # No results were found (None loaded from r.json())
                if len(transactions) < 100:
                    break  # The next page will be blank

                kwargs["page"] += 1
                fields["metadata"] = json.dumps(kwargs)  # TODO do less work?

        if ensure_order:
            transactions.sort(key=operator.itemgetter("timestamp"), reverse=reverse)

        return transactions

    def verify(self, transaction_hash="", content_hash="",
               content_string="", filename=""):
        """ Verifies whether some content or its hash appears on the blockchain.

        The acting user must have 'can_read' permissions.

        Args:
            transaction_hash (str): the transaction hash you want to verify.
                Transaction hashes are returned from Transaction Objects.
            content_hash (str): the SHA2-256 multihash of the content you
                want to verify. Use helpers.ipfs_hash() to create this hash.
            content_string (str): the string you want to verify
            filename (str): the name of or path to the file to verify

        Returns:
            True: if the content was recorded on the blockchain
            False: if the content was not recorded on the blockchain
        """
        fields = {"user": self._user()}
        if transaction_hash:
            fields["metadata"] = json.dumps({"transaction_hash": transaction_hash})
        elif content_hash:
            fields["metadata"] = json.dumps({"content_hash": content_hash})
        elif content_string:
            fields["content_string"] = content_string
        elif filename:
            fields["content_file"] = (filename, open(filename, mode='rb'))

        try:
            self._call_api("/store/verify", fields)
        except APIError as e:
            if e.args[0] == 'The transaction is not registered.':
                return False
            else:
                raise
        return True

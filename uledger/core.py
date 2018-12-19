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

""" This is the core module for the ULedger SDK. It implements the
BlockchainUser class, whose objects act as interfaces to the ULedger API. """

from collections import abc
import io
import json
import operator
import os

import requests
from requests_toolbelt import MultipartEncoder

from . import helpers
from .exceptions import APIError


class BlockchainUser:
    """ A programmatic interface between a user and a ULedger blockchain.

    Every ULedger blockchain has its own URL, API token, and users (as well
    as a controlling super admin). Each user has their own unique access key,
    secret key, and permissions.

    To create a BlockchainUser object, you will need its URL, token, and a
    key-pair belonging to one of its users. The user in question must also
    have permission to perform the requested action.

    WARNING: IF YOU LOSE YOUR SECRET KEY, YOU CANNOT GET IT BACK OR RESET IT.
    It is your responsibility to store your secret key and keep it secure;
    treat it like you would any other password.

    Users can have any combination of 'can_read', 'can_write', 'can_add_user',
    and 'can_add_permission' permissions. The super admin has all four
    permissions and cannot have their permissions modified by anyone.
    Users with 'can_add_permission' permissions are effectively admins and can
    grant and revoke every permission from any user except the super admin.

    'can_read': the user can read content from the blockchain
    'can_write': the user can write content to the blockchain
    'can_add_user': the user can add new users to the blockchain
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
        return ("{0}({1}, {2}, {3}, {4})".format(
            self.__class__.__name__, self.url, self.token, self.access_key,
            self.secret_key))

    def __str__(self):
        return str(self.__dict__)

    # ----------------
    # Internal Methods
    # ----------------

    def _add_stream(self, stream, filename, tags=None, coerce=False):
        """ Adds content from a stream or file object to the blockchain.

        The acting user must have 'can_write' permissions.

        Argmuents:
            stream (io.IOBase): the stream or file object to record to the
                blockchain. The stream cannot exceed 50MB. The stream object
                should probably belong to a subclass of io.IOBase, but any
                file object should work as long as it supports proper seek(),
                tell(), and read() methods.
            filename (str): the filename to record as metadata in the new
                blockchain transaction.
            tags (any): metadata to record alongside the stream
            coerce (bool): coerce (bool): if True, forces the metadata (tags)
                into proper form (see _normalize() for details).

        Raises:
            ValueError: if the stream begins with '"Error: '
            OSError: if the stream contains more than 50MB of content

        Returns:
            dict: the new transaction's Transaction Object
        """
        if stream.read(8) == b'"Error: ':
            raise ValueError('The stream cannot begin with '"Error: '")

        # Check if the stream contains more than 50MB of content.
        # tell() shouldn't normally be needed since seek() should return the
        # current position, but sometimes seek() is poorly implemented and
        # returns None like with  tempfile.SpooledTemporaryFile.
        stream.seek(0, os.SEEK_END)
        if stream.tell() > 50 * 1024 * 1024:
            raise OSError("The stream cannot be larger than 50MB.")
        stream.seek(0, os.SEEK_SET)

        fields = {
            "user": self._user(),
            "content_file": (filename, stream),
            "metadata": self._normalize(tags, coerce=coerce)
        }

        return self._call_api("/store/add", fields)["result"]

    def _call_api(self, endpoint, fields):
        """ Calls the API.

        Args:
            endpoint (str): the API endpoint to request from
            fields (dict): the fields used to construct the multipart request

        Raises:
            APIError: if something went wrong with the API
            requests.RequestException: if something went wrong with the request

        Returns:
            dict: the API response with 0, 1, or 2+ Transaction Objects
        """
        # Format the request information.
        url = "{0}{1}".format(self.url, endpoint)
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

    def _call_api2(self, endpoint, fields, download=False, decode=False):
        """ Calls the API and streams its response.

        This method prefers to return the raw response content as a
        bytestring, but you can set decode to True to try and have it
        decode the response content using utf-8. Alternatively, you
        can set download to True to have the raw content written to a
        file in your Downloads folder instead.

        # TODO allow tag-based decoding behavior

        Args:
            endpoint (str): the API endpoint to request from
            fields (dict): the fields used to construct the multipart request
            decode (bool): try to decode the response bytestring using utf-8.
                If decoding fails, the bytestring will be used as a fallback.
            download (bool): if download is True, the raw response bytestring
                will be saved to the Downloads folder instead of being returned.

        Raises:
            APIError: if something went wrong with the API
            requests.RequestException: if something went wrong with the request

        Returns:
            bytes: if decode is False
            str: if decode is True and decoding succeeds
            None: if download is True
        """
        # Format the request information
        url = "{0}{1}".format(self.url, endpoint)
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

        # Try to decode the content using utf-8.
        # If decoding fails, fall back to the raw response bytestring.
        if decode:
            r.encoding = 'utf-8'
            try:
                response = r.text
            except UnicodeDecodeError:
                response = r.content
        else:
            response = r.content

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
                str and bytes objects are treated as a single value.
            coerce (bool): if coerce is set to True, the metadata list will be
                forcibly shortened to 50 tags of no more than 50 characters
                each. If False, the original data will not be modified.
                If you fail to meet the metadata requirements, the API server
                will reject your transaction and return an error.
            dumps(bool): if dumps is set to True, then the final list of
                metadata will be serialized into a JSON-formatted string.
            key (str): if dumps is set to True, key will be used to form the
                key-value pair with the normalized metadata for the JSON.
                e.g.: json.dumps({key: normalized_metadata})

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
            tag_list = ["{0}={1}".format(key, value)
                        for key, value in md.items()]
        elif not isinstance(md, abc.Iterable):
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
        Use uledger.helpers.generate_secret_key() to generate a random one.

        Args:
            name (str): the name to give to the super admin

        Returns:
            dict: a dictionary with the admin's user information
        """
        fields = {"user": self._user(
            admin_name=name, repeat_secret_key=self.secret_key)}
        return self._call_api("/store/admin", fields)

    def confirm_user(self, access_key, old_secret_key, new_secret_key=""):
        """ Confirms a new user.

        After adding a user to the blockchain, you must also confirm them.
        The API server will reject all requests from unconfirmed users.

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

    def get_users(self, name="", access_key=""):
        """ Gets a list of users with access to the blockchain.

        This function takes 0-1 arguments. If no arguments are given, every
        user on the blockchain will be returned. If a name or access_key is
        specified, the matching user(s) will be returned instead. name and
        access_key cannot be specified together.

        The acting user must have 'can_read' permissions.

        Args:
            name (str): a user name to search for. If a name is specified, the
                user(s) with the exact same name (if any) will be returned.
            access_key (str): an access key to search for. If an access key is
                specified, the matching user will be returned.

        Returns:
            list of dict: if a matching name or access key is found, the
                matching user(s) is/are returned as a list of dictionaries.
                If no arguments are specified, this will be a list of every
                user on the blockchain instead.
            []: if no matching name or access key is found
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

    def new_user(self, name):
        """ Adds a user to the blockchain.

        Once a new user is created, they MUST be confirmed with the
        confirm_user() method before they can take any actions. Unconfirmed
        users will have all of their requests rejected by the API server.

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
        """ Adds a user to the blockchain and confirms them.

        The acting user must have 'can_add_user' permissions.

        When possible, we recommend that you use this method instead of using
        new_user() and confirm_user() separately; it's easier to use and
        provides better continuity.

        Args:
            name (str): a name for the new user. Users can share names.
            new_secret_key(str): the user's new secret key. new_secret_key
                must be at least 8 characters long and contain at least one
                lowercase, uppercase, digit, and punctuation character.
                Use helpers.generate_secret_key to generate a secret key.
                If new_secret_key is not specified, the user's temporary secret
                key will become their permanent secret key.

        Raises:
            ValueError: if new_secret_key does not contain at least one
                lowercase, uppercase, digit, and punctuation mark

        Returns:
            BlockchainUser: created from your blockchain's URL and token
                and the confirmed user's new access key and secret key
        """
        if new_secret_key and not helpers.validate_secret_key(new_secret_key):
            raise ValueError(
                'Your secret key must be 8 characters long and contain at'
                'least one lowercase, uppercase, digit, and punctuation mark.')
        access_key, secret_key = self.new_user(name)
        return self.confirm_user(access_key, secret_key, new_secret_key)

    def set_permissions(self, target_access_key, authorize=None, revoke=None):
        """ Sets permissions for a target user.

        Revocation takes precedence over authorization. Permissions specified
        in both authorize and revoke will ultimately be set to False.

        Repeatedly modifying a permission does nothing. You can grant and
        revoke permissions from yourself. The super admin cannot have their
        permissions modified.

        The acting user must have 'can_add_permission' permissions.
        The target user must be confirmed.

        Args:
            target_access_key (str): the user to authorize
            authorize (str, list, tuple): a list, tuple, or space-separated
                string of permissions to grant to the user
            revoke (str, list, tuple): a list, tuple, or space-separates string
                of permissions to revoke from the user

        Returns:
            dict: the user's updated information including their access
                key and any permissions they still have access to
        """
        # Wrap permission strings in a list. Now single permissions can be
        # provided as strings rather than inside of a list or tuple.
        if isinstance(authorize, str):
            authorize = [authorize]
        if isinstance(revoke, str):
            revoke = [revoke]

        # JSON is especially effective here because lists and tuples are both
        # encoded as arrays, meaning this method can implicitly accept either.
        fields = {"user": self._user(
            user_to_auth_access_key=target_access_key,
            authorize=authorize, revoke=revoke)}

        return self._call_api("/store/authorize", fields)

    def get_permissions(self, target_access_key):
        """ Returns a user's current set of permissions.

        Args:
            target_access_key (str): the user to retrieve permissions from
        """
        return self.get_users(access_key=target_access_key)[0]

    def deactivate(self, target_access_key):
        """ Removes all permissions from a user.

        This method has the same behavior and conditions as set_permissions().

        Args:
            target_access_key (str): the user to deactivate

        Returns:
            {"access_key": target_access_key, "error": False}
        """
        fields = {"user": self._user(
            user_to_auth_access_key=target_access_key, deactivate=True)}
        return self._call_api("/store/authorize", fields)

    # ---------------
    # Data Management
    # ---------------

    def add_bytes(self, b, filename="", tags=None, coerce=False):
        """ Adds a bytestring to the blockchain.

        The acting user must have 'can_write' permissions.

        Args:
            b (bytes): bytestring to add to the blockchain. Cannot exceed 50MB.
            filename (str): an optional file name to store as metadata.
                If you don't set a file name, it will be set to the IPFS hash
                of the bytestring with a '.txt' extension.
            tags (any): metadata to record alongside the bytestring
            coerce (bool): if True, forces the metadata (tags) into proper
                form (see _normalize() for details)

        Returns:
            dict: the new transaction's Transaction Object.
        """
        if not filename:
            filename = helpers.ipfs_hash(b) + '.txt'
        with io.BytesIO(b) as stream:
            return self._add_stream(stream, filename, tags, coerce)

    def add_file(self, path, tags=None, coerce=False):
        """ Adds a file to the blockchain.

        The file must be 50MB or less or your request will be rejected.
        File names are used for metadata but not for server-side storage,
        so there is no risk of a directory traversal attack.

        The acting user must have 'can_write' permissions.

        Args:
            path (str): the absolute path to the file you want to add.
            tags (any): metadata to record alongside the file
            coerce (bool): if True, forces the metadata (tags) into proper
                form (see _normalize() for details).

        Returns:
            dict: the new transaction's Transaction Object.
        """
        filename = os.path.basename(path)
        with open(path, 'rb') as stream:
            return self._add_stream(stream, filename, tags, coerce)

    def add_object(self, obj, mode, tags=None, coerce=False, **kwargs):
        """ Serializes an object and adds it to the blockchain.

        If you would like to extend this function's JSON encoding capabilities,
        (for example, if you're using objects that can't naturally be converted
        to JSON), you can subclass json.JSONEncoder and pass it to this method
        as a keyword argument using 'cls=<MyJSONEncoder>'.

        The acting user must have 'can_write' permissions.

        Args:
            obj (any): the object to record to the blockchain.
            mode (str): controls how the object will be converted into a string.
                'str' will use the object's __str__ method. 'repr' will use
                the object's __repr__ method. 'json' will serialize the object
                as a JSON-formatted string using a JSONEncoder.
            tags (any): metadata to record alongside the serialized object
            coerce (bool): if True, forces the metadata (tags) into proper
                form (see _normalize() for details).
            kwargs (any): keyword arguments to control JSON serialization.
                These are just the kwargs available in json.dumps().

        Raises:
            ValueError: if mode is not 'json', 'str', or 'repr'
                        or if the object's serialization begins with '"Error: '

        Returns:
            dict: the new transaction's Transaction Object
        """
        if mode == 'str':
            obj_string = str(obj)
        elif mode == 'repr':
            obj_string = repr(obj)
        elif mode == 'json':
            obj_string = json.dumps(obj, **kwargs)
        else:
            raise ValueError("'mode' must be 'json', 'str', or 'repr'.")

        # Serializations starting with '"Error: ' are disallowed because the
        # API server uses the same pattern to designate actual error messages.
        if obj_string.startswith('"Error: '):
            raise ValueError(
                "Serializations cannot begin with '\"Error: '")

        fields = {
            "user": self._user(),
            "content_string": obj_string,
            "metadata": self._normalize(tags, coerce=coerce)
        }

        return self._call_api("/store/add", fields)["result"]

    def add_string(self, string, tags=None, coerce=False):
        """ Adds a string to the blockchain.

        Use this method to store simple string literals. If you are interested
        in object storage, you can use add_object() or serialize the object
        yourself and add the serialization to the blockchain with this method.

        The acting user must have 'can_write' permissions.

        Args:
            string (str): the string to add to the blockchain
            tags (any): metadata to record alongside the serialized object
            coerce (bool): if True, forces the metadata (tags) into proper
                form (see _normalize() for details).

        Raises:
            ValueError: if the string begins with '"Error: '

        Returns:
            dict: the new transaction's Transaction Object
        """
        if string.startswith('"Error: '):
            raise ValueError(
                "Serializations cannot begin with '\"Error: '")

        fields = {
            "user": self._user(),
            "content_string": string,
            "metadata": self._normalize(tags, coerce=coerce)
        }

        return self._call_api("/store/add", fields)["result"]

    def get_content(self, content_hash, download=False, decode=False):
        """ Retrieves content on the blockchain from its hash.

        Each piece of content stored on the blockchain is indexed by its
        SHA2-256 multihash. This method will search the blockchain for a
        multihash and return the content that created it. This is similar
        to the scheme used by the InterPlanetary File System protocol.
        Use uledger.helpers.ipfs_hash() to create a SHA2-256 multihash.

        By default, the content will be returned as a bytestring. However,
        you can set decode to True to try and decode the content with utf-8.
        Alternatively, you can set download to True to have this function write
        the content to a file in your Downloads folder instead of returning it.

        The acting user must have 'can_read' permissions.

        Args:
            content_hash (str): a multihash to search for in the blockchain
            decode (bool): try to decode the response bytestring using utf-8.
                If decoding fails, the bytestring will be used as a fallback.
            download (bool): if download is True, the raw response bytestring
                will be saved to the Downloads folder instead of being returned.

        Returns:
            bytes: if decode is False or if decoding fails
            str: if decode is True and decoding succeeds
            None: if download is True
        """
        endpoint = "/store/content?hash={0}".format(content_hash)
        fields = {"user": self._user()}
        return self._call_api2(endpoint, fields, download, decode)

    def get_transactions(self, coerce=False, with_content=False,
                         sort=True, reverse=False, **kwargs):
        """ Queries the blockchain for transactions.

        This method is intended to retrieve transaction metadata, not content.
        If you're interested in retrieving content from the blockchain, use
        get_content(). This method *can* retrieve string content added to the
        blokchain with add_object() or add_string(), but will only return a URL
        for binary content added with add_bytes() or add_file().

        The acting user must have 'can_read' permissions.

        Args:
            coerce (bool): if True, forces the metadata (tags) into proper
                form (see _normalize() for details).
            with_content (bool): if set to True, a 'content' field will be
                populated for each Transaction Object when possible. If string
                content is encountered, it will be added to the content field.
                If file content is encountered, the content field will be
                populated with a URL that can be used to download the file.
                A file 'extension' field will also be populated.
            sort (bool): if set to True, transactions will be returned in
                sorted order. By default, transactions are not guaranteed
                to be returned in sorted order.
            reverse (bool): if ensure_order is True, reverse will be used to
                control the sorting order: False for ascending order (default)
                and True for descending order.

        Query Args (kwargs):
            transaction_hash (str): a transaction hash to search for on the
                blockchain. Each transaction on the blockchain has a unique
                transaction hash, so this query parameter will only ever match
                a single transaction. transaction_hash is incompatible with
                other query parameters and must be used alone.
            content_hash (str): a content hash to search for on the blockchain.
            tags_all (any): metadata to search for on the blockchain.
                In order to match, a transaction must contain every tag
                specified here. tags_all cannot be used with tags_any.
            tags_any (any): metadata to search for on the blockchain.
                In order to match, a transaction must contain one or more of
                the tags specified here. tags_any cannot be used with tags_all.
            last_transactions (int): the number of most recent transactions to
                request from the blockchain
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
        # Ensure that transaction_hash is only ever used by itself to prevent
        # 'result': [{'merkle_proof': {}}]
        if kwargs.get("transaction_hash") and len(kwargs) > 1:
            raise ValueError("Illegal parameter combination.")

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
            transactions = self._call_api(endpoint, fields)["result"] or []

        # Otherwise get all of the pages via pagination.
        else:
            transactions = []
            kwargs["page"] = 0
            fields = {"user": self._user(), "metadata": json.dumps(kwargs)}
            while 1:
                try:
                    result = self._call_api(endpoint, fields)["result"]
                except APIError as e:
                    if str(e) == "No transactions for the specified time range.":
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
                fields["metadata"] = json.dumps(kwargs)  # TODO do less work?

        if sort:
            transactions.sort(key=operator.itemgetter("timestamp"), reverse=reverse)

        return transactions

    def verify(self, transaction_hash="", content_hash="",
               content_string="", filename=""):
        """ Checks whether a hash, string, or file appears on the blockchain.

        Only one parameter will be used, prioritized from left to right:
            transaction_hash > content_hash > content_string > filename.

        The acting user must have 'can_read' permissions.

        Args:
            transaction_hash (str): the transaction hash you want to verify.
            content_hash (str): the SHA2-256 multihash of the content you
                want to verify (see helpers.ipfs_hash()).
            content_string (str): the string you want to verify
            filename (str): the name of / the path to the file to verify

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
            with open(filename, mode='rb') as file:
                fields["content_file"] = (filename, file)

        try:
            self._call_api("/store/verify", fields)
        except APIError as e:
            if str(e) == 'The transaction is not registered.':
                return False
            else:
                raise
        return True

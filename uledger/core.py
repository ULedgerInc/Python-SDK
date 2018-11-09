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
It will take care of blockchain-related boilerplate so you don't have to.

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
    """ Creates an object representing a user with access to the blockchain. """
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

    def _call_api(self, endpoint, fields):
        """ Calls the API. """
        url = f"{self.url}{endpoint}"
        data = MultipartEncoder(fields=fields)
        headers = {"Content-Type": data.content_type, "token": self.token}

        r = requests.post(url, data=data, headers=headers, timeout=10)
        r.raise_for_status()

        r.encoding = 'utf-8'
        response = r.json()
        error = response["error"]
        if error != "false":
            raise APIError(error, response)
        return response

    def _call_api2(self, endpoint, fields, download=False):
        """ Calls the API and streams the response to handle raw data. """
        url = f"{self.url}{endpoint}"
        data = MultipartEncoder(fields=fields)
        headers = {"Content-Type": data.content_type, "token": self.token}

        r = requests.post(url, data=data, headers=headers, timeout=10, stream=True)
        r.raise_for_status()

        # download a file assuming their ".extension" formatting
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

        r.encoding = 'utf-8'
        response = r.text  # set to 'replace' by default
        if response.startswith('"Error: '):
            error_msg = response[8:].strip('\"\n')
            raise APIError(error_msg)

        return response

    @staticmethod
    def _normalize(md, coerce=False, dumps=True, key="tags"):
        """ Normalizes metadata according to the API tag list requirements. """
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
        """ Formats the 'user' field for a Multipart Request. """
        return json.dumps({
            "access_key": self.access_key,
            "secret_key": self.secret_key,
            **kwargs
        }, ensure_ascii=False)

    def add_file(self, filename, tags=None, coerce=False):
        """ Adds a file to the blockchain. """
        if os.stat(filename).st_size > 52428800:  # 50MB, or 5 * 2**20
            raise OSError("The maximum file size is 50MB.")

        fields = {
            "user": self._user(),
            "content_file": (filename, open(filename, mode='rb')),
            "metadata": self._normalize(tags, coerce=coerce)
        }

        return self._call_api("/store/add", fields)["result"]

    def add_string(self, content_string, tags=None, coerce=False):
        """ Adds a string to the blockchain. """
        # JSON-formatted strings are required, not normal-formatted strings.
        fields = {
            "user": self._user(),
            "content_string": content_string,
            "metadata": self._normalize(tags, coerce=coerce)
        }

        return self._call_api("/store/add", fields)["result"]

    def admin(self, name):
        """ Creates the initial admin user. Can only be called once. """
        fields = {"user": self._user(
            admin_name=name, repeat_secret_key=self.secret_key)}
        return self._call_api("/store/admin", fields)

    def authorize(self, target_access_key, *permissions):
        """ Grants permissions to a user. """
        fields = {"user": self._user(
            user_to_auth_access_key=target_access_key, authorize=permissions)}
        return self._call_api("/store/authorize", fields)

    def confirm_user(self, access_key, old_secret_key, new_secret_key=""):
        """ Confirms a user. """
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
        """ Deletes a user. """
        # does user just need permission or does user need to be an admin?
        fields = {"user": self._user(
            user_to_auth_access_key=target_access_key, deactivate=True)}
        return self._call_api("/store/authorize", fields)

    def get_content(self, content_hash, download=False):
        """ Resolves a content hash and retrieves its content. """
        endpoint = f"/store/content?hash={content_hash}"
        fields = {"user": self._user()}
        return self._call_api2(endpoint, fields, download=download)

    def get_transactions(self, coerce=False, with_content=False, ensure_order=True, reverse=True, **kwargs):
        """ Retrieves transactions from the blockchain. """
        # Validate parameters
        if (kwargs.get("tags_any") and kwargs.get("tags_all")
                or (kwargs.get("transaction_hash") and len(kwargs) > 1)):  # prevents 'result': [{'merkle_proof': {}}]

            raise ValueError("Illegal parameter combination.")

        # Normalize metadata
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

        # if 'page' exists and is an integer, request the one-and-only page
        if isinstance(kwargs.get("page"), int):
            fields = {"user": self._user(), "metadata": json.dumps(kwargs)}
            transactions = self._call_api(endpoint, fields)["result"] or []  # catch None asap

        # otherwise get all of the pages via pagination
        else:
            kwargs["page"] = 0
            fields = {"user": self._user(), "metadata": json.dumps(kwargs)}
            while 1:
                try:
                    result = self._call_api(endpoint, fields)["result"]
                except APIError as e:
                    if str(e.args[0]) == "No transactions for the specified time range.":  # "range" specific error
                        break  # over-page
                    else:
                        raise  # elevate error
                try:
                    transactions.extend(result)
                except TypeError:
                    break  # no results were found (None loaded from r.json())
                if len(transactions) < 100:
                    break  # shortcut

                kwargs["page"] += 1
                fields["metadata"] = json.dumps(kwargs)  # TODO do less work?

        if ensure_order:
            transactions.sort(key=operator.itemgetter("timestamp"), reverse=reverse)

        return transactions

    def get_users(self, name=""):
        """ Gets a list of users on the blockchain. """
        fields = {"user": self._user(), "name": name}
        try:
            return self._call_api("/store/users", fields)["result"]
        except KeyError:  # "result" field not returned when no users are found
            return []

    def new_user(self, name):
        """ Adds a user to the blockchain. """
        fields = {"user": self._user(new_user_name=name)}
        response = self._call_api("/store/newUser", fields)
        return response["access_key"], response["secret_key"]

    def new_confirmed_user(self, name, password=""):
        """ Adds a confirmed user to the blockchain.

        We recommend that you use this entrypoint instead of using new_user()
        and confirm_user() separately as users *must* be confirmed before
        they are allowed to use the blockchain.
        """
        access_key, secret_key = self.new_user(name)
        return self.confirm_user(access_key, secret_key, password)

    def revoke(self, target_access_key, *permissions):
        """ Revokes permissions from a user. """
        fields = {"user": self._user(
            user_to_auth_access_key=target_access_key,
            revoke=permissions)}
        return self._call_api("/store/authorize", fields)

    def verify(self, transaction_hash="", content_hash="", content_string="", filename=""):
        fields = {"user": self._user()}
        if transaction_hash:
            fields["metadata"] = json.dumps({"transaction_hash": transaction_hash})
        elif content_hash:
            fields["metadata"] = json.dumps({"content_hash": content_hash})
        elif content_string:
            fields["content_string"] = content_string
        elif filename:
            fields["content_file"] = (filename, open(filename, mode='rb'))
            # This operates the same way as the following:
            # with open(filepath, mode="rb") as file:
            #     file_hash = helpers.ipfs_hash(file.read())
            # fields["metadata"] = json.dumps({"content_hash": file_hash})

        try:
            self._call_api("/store/verify", fields)
        except APIError as e:
            if e.args[0] == 'The transaction is not registered.':
                return False
            else:
                raise
        return True

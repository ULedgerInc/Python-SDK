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

""" This module contains the exceptions used by the ULedger SDK. """


class ULError(Exception):
    """ The base class for exceptions in this module. """


class APIError(ULError):
    """ This error indicates that something went wrong with the API. This could
    be anything from an unexpected argument to status messages about users,
    transactions, or queries.

    APIErrors have a normal error message but will also store the offending
    request fields as an additional attribute. This way the fields are
    available for debugging but stay hidden by default.
    """
    def __init__(self, message, fields):
        super().__init__(message)
        self.fields = fields

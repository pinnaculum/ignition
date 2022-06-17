'''
This Source Code Form is subject to the terms of the
Mozilla Public License, v. 2.0. If a copy of the MPL
was not distributed with this file, You can obtain one
at http://mozilla.org/MPL/2.0/.
'''

CRLF = "\r\n"
EOL = "\n"

# Gemini-Protocol Mechanical Constants
GEMINI_SCHEME = 'gemini'
GEMINI_PORT = 1965
GEMINI_DEFAULT_MIME_TYPE = 'text/gemini; charset=utf-8'
GEMINI_DEFAULT_ENCODING = 'utf-8'
GEMINI_RESPONSE_HEADER_SEPARATOR = "\\s+"
GEMINI_URL_MAXLENGTH = 1024
GEMINI_RESPONSE_HEADER_META_MAXLENGTH = 1024
GEMINI_MAXIMUM_BODY_SIZE = 2 ** 32

# One-character response codes
RESPONSE_STATUS_ERROR = "0"
RESPONSE_STATUS_INPUT = "1"
RESPONSE_STATUS_SUCCESS = "2"
RESPONSE_STATUS_REDIRECT = "3"
RESPONSE_STATUS_TEMP_FAILURE = "4"
RESPONSE_STATUS_PERM_FAILURE = "5"
RESPONSE_STATUS_CLIENTCERT_REQUIRED = "6"

# Two-character response codes
RESPONSE_STATUSDETAIL_ERROR_NETWORK = "00"
RESPONSE_STATUSDETAIL_ERROR_DNS = "01"
RESPONSE_STATUSDETAIL_ERROR_HOST = "02"
RESPONSE_STATUSDETAIL_ERROR_TLS = "03"
RESPONSE_STATUSDETAIL_ERROR_PROTOCOL = "04"
RESPONSE_STATUSDETAIL_INPUT = "10"
RESPONSE_STATUSDETAIL_INPUT_SENSITIVE = "11"
RESPONSE_STATUSDETAIL_SUCCESS = "20"
RESPONSE_STATUSDETAIL_REDIRECT_TEMPORARY = "30"
RESPONSE_STATUSDETAIL_REDIRECT_PERMANENT = "31"
RESPONSE_STATUSDETAIL_TEMP_FAILURE = "40"
RESPONSE_STATUSDETAIL_TEMP_FAILURE_UNAVAILABLE = "41"
RESPONSE_STATUSDETAIL_TEMP_FAILURE_CGI = "42"
RESPONSE_STATUSDETAIL_TEMP_FAILURE_PROXY = "43"
RESPONSE_STATUSDETAIL_TEMP_FAILURE_SLOW_DOWN = "44"
RESPONSE_STATUSDETAIL_PERM_FAILURE = "50"
RESPONSE_STATUSDETAIL_PERM_FAILURE_NOT_FOUND = "51"
RESPONSE_STATUSDETAIL_PERM_FAILURE_GONE = "52"
RESPONSE_STATUSDETAIL_PERM_FAILURE_PROXY_REFUSED = "53"
RESPONSE_STATUSDETAIL_PERM_FAILURE_BAD_REQUEST = "59"
RESPONSE_STATUSDETAIL_CLIENTCERT_REQUIRED = "60"
RESPONSE_STATUSDETAIL_CLIENTCERT_REQUIRED_NOT_AUTHORIZED = "61"
RESPONSE_STATUSDETAIL_CLIENTCERT_REQUIRED_NOT_VALID = "62"

# ignition application defaults
DEFAULT_REQUEST_TIMEOUT = 30
DEFAULT_HOSTS_FILE = '.known_hosts'

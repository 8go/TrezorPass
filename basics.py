from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import logging
from encoding import unpack

"""
This file contains some constant variables like version numbers,
default values, etc.
"""

# Name of application
NAME = u'TrezorPass'

# Name of software version
VERSION_STR = u'v4.4'

# Date of software version
VERSION_DATE_STR = u'June 2017'

# default log level
DEFAULT_LOG_LEVEL = logging.INFO  # CRITICAL, ERROR, WARNING, INFO, DEBUG

# short acronym used for name of logger
LOGGER_ACRONYM = u'tp'

# location of logo image
LOGO_IMAGE = u'icons/TrezorPass.svg'

# file extension for encrypted files with plaintext filename
PWDB_FILEEXT = u'.pwdb'

# Data storage version, format of PWDB file
# Very important for compatibility.
# Version 1 stores only the password in the value part of the key-value pair
# Version 2 stores password and comments in the value part of the key-value pair
# Version 2 software opens a version 1 pwdb file and stores it as version 2;
#           version 1 software cannot open a version 2 pwdb file.
#           i.e. v2 is backwards compatible (v2 software can open v1 dbpw file)
#           but not forwards compatible (v1 software cannot open v2 dbpw file).
PWDB_FILEFORMAT_VERSION = 2

# size limit of the combined password + commens length
# MAX_SIZE_OF_PASSWDANDCOMMENTS limit is arbitrary,
# could handle larger size, but set to 4K for safety
# GUI .ui file also has a safety restriction
MAX_SIZE_OF_PASSWDANDCOMMENTS = 4096

# clear clipboard after CLIPBOARD_TIMEOUT_IN_SEC seconds after copy with ^C;
# if set to 0 then clipboard will not be cleared
# Common user mistake is to not click their Trezor after ^C and
# then be surprised that their clipboard is empty
CLIPBOARD_TIMEOUT_IN_SEC = 10  # clear clipboard after 10 seconds


class Magic(object):
    """
    Few magic constant definitions so that we know which nodes to search
    for keys.
    """

    headerStr = b'TZPW'
    hdr = unpack("!I", headerStr)

    # for unlocking wrapped AES-CBC key
    unlockNode = [hdr, unpack("!I", b'ULCK')]
    # for generating keys for individual password groups
    groupNode = [hdr, unpack("!I", b'GRUP')]
    # the unlock and backup key is written in this weird way to fit display nicely
    unlockKey = b'Decrypt master  key?'  # string to derive wrapping key from

    # for unlocking wrapped backup private RSA key
    backupNode = [hdr, unpack("!I", b'BKUP')]
    # string to derive backup wrapping key from
    backupKey = b'Decrypt backup  key?'

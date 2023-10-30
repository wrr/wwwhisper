"""Regexp to validates email that is used by BrowserId.

From node-validator, Copyright (c) 2010 Chris O'Hara:
https://github.com/chriso/node-validator/blob/master/lib/validators.js
https://github.com/chriso/node-validator/blob/master/LICENSE
"""

# pylint: disable=line-too-long
EMAIL_VALIDATION_RE = r"^(?:[\w\!\#\$\%\&\'\*\+\-\/\=\?\^\`\{\|\}\~]+\.)*[\w\!\#\$\%\&\'\*\+\-\/\=\?\^\`\{\|\}\~]+@(?:(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-](?!\.)){0,61}[a-zA-Z0-9]?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9\-](?!$)){0,61}[a-zA-Z0-9]?)|(?:\[(?:(?:[01]?\d{1,2}|2[0-4]\d|25[0-5])\.){3}(?:[01]?\d{1,2}|2[0-4]\d|25[0-5])\]))$"

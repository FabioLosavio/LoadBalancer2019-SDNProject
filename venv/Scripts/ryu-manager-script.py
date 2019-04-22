#!C:\Users\fabio\PycharmProjects\progettoSDN\venv\Scripts\python.exe
# EASY-INSTALL-ENTRY-SCRIPT: 'ryu==4.31','console_scripts','ryu-manager'
__requires__ = 'ryu==4.31'
import re
import sys
from pkg_resources import load_entry_point

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(
        load_entry_point('ryu==4.31', 'console_scripts', 'ryu-manager')()
    )

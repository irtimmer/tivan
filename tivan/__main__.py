# SPDX-License-Identifier: GPL-2.0+

import argparse
import getpass

from source.mseven6 import MSEven6
from parser.binxml import ResultSet

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str, required=True, help='host to connect to')
    parser.add_argument('--username', type=str, required=True, help='username for login')
    parser.add_argument('--password', type=str, required=False, help='password for login')
    parser.add_argument('--domain', type=str, default='WORKSTATION', required=False, help='domain for login')

    args = parser.parse_args()
    if not args.password:
        args.password = getpass.getpass()

    source = MSEven6(args.host, args.username, args.password, args.domain)
    source.connect()

    for event in source.query():
        print(ResultSet(event).xml())

if __name__ == '__main__':
    main()

# SPDX-License-Identifier: GPL-2.0+

import getpass
import click

from source.mseven6 import MSEven6
from parser.binxml import ResultSet

@click.command(help='Pull logs via RPC from Windows host')
@click.option('--host', help='Host to connect to', required=True)
@click.option('--username', help='Username for login', required=True)
@click.option('--password', help='Password for login')
@click.option('--domain', default='WORKSTATION', help='Domain for login')
@click.option('--path', default='security', help='Path to eventlog')
@click.option('--query', default='*', help='Query for filtering events')
def cli(host, username, password, domain, path, query):
    if not password:
        password = getpass.getpass()

    source = MSEven6(host, username, password, domain)
    source.connect()

    for event in source.query(path, query):
        print(ResultSet(event).xml())

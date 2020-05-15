# SPDX-License-Identifier: GPL-2.0+

import click
import os
import importlib
import pkgutil

class CommandCLI(click.MultiCommand):

    def list_commands(self, ctx):
        return map(lambda x: x[1], pkgutil.iter_modules([os.path.dirname(__file__) + '/commands']))

    def get_command(self, ctx, name):
        return importlib.import_module('commands.%s' % name).cli

if __name__ == '__main__':
    CommandCLI(help='Tivan the Log Collector')()

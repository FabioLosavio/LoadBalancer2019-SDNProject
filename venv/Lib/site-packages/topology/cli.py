import click
from pkg_resources import iter_entry_points
from click_plugins import with_plugins
import api
from topology.core import utils
from topology.core.constants import DEFAULT_TOPOLOGY
import logging
import coloredlogs
import sys

coloredlogs.install(level='INFO', fmt='%(asctime)s %(levelname)s %(message)s')

class MutuallyExclusiveOption(click.Option):
    def __init__(self, *args, **kwargs):
        self.mutually_exclusive = set(kwargs.pop('mutually_exclusive', []))
        help = kwargs.get('help', '')
        if self.mutually_exclusive:
            ex_str = ', '.join(self.mutually_exclusive)
            kwargs['help'] = help + (
                ' NOTE: This argument is mutually exclusive with '
                ' arguments: [' + ex_str + '].'
            )
        super(MutuallyExclusiveOption, self).__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        if self.mutually_exclusive.intersection(opts) and self.name in opts:
            raise click.UsageError(
                "Illegal usage: `{}` is mutually exclusive with "
                "arguments `{}`.".format(
                    self.name,
                    ', '.join(self.mutually_exclusive)
                )
            )

        return super(MutuallyExclusiveOption, self).handle_parse_result(
            ctx,
            opts,
            args
        )

@with_plugins(iter_entry_points('topology.plugins'))
@click.group()
def topology():
    pass


@topology.command()
@click.argument('filename', type=click.Path(), default='topo.yml')
@click.option('--data', cls=MutuallyExclusiveOption, mutually_exclusive=["json"],
              type=click.STRING, help="Dictionary String")
@click.option('--json', cls=MutuallyExclusiveOption, mutually_exclusive=["data"],
              type=click.File(mode='r'), help="JSON filename")
def create(filename, data, json):
    """Create Topology File"""
    if data:
        try:
            data = utils.json_loads_byteified(data)
        except ValueError:
            raise click.BadParameter('data does not appear to be a valid json string')
        api.create_topology(filename, **data)
    elif json:
        try:
            json = utils.json_load_byteified(json)
        except ValueError, e:
            # raise click.BadParameter('json file does not appear to contain valid json')
            logging.error(e)
            sys.exit(0)
        api.create_topology(filename, **json)
    else:
        api.create_topology(filename, **DEFAULT_TOPOLOGY)


@topology.command()
@click.argument('filename', type=click.Path(), default='topo.yml')
@click.option('--format', type=click.Choice(['yaml', 'yml', 'json']), default='yaml', help="Output Format")
def read(filename, format):
    """Read Topology File"""
    topo = api.read_topology(filename)
    if format == 'json':
        click.echo(topo.to_json())
    else:
        click.echo(topo.to_yaml())


@topology.command()
@click.argument('filename', type=click.Path(), default='topo.yml')
def delete(filename):
    """Delete Topology File"""
    api.delete_topology(filename)


cli = click.CommandCollection(sources=[topology])

if __name__ == '__main__':
    cli()

import os
import yaml
from core.topology import Topology


def create_topology(filename, **kwargs):
    _kwargs = kwargs
    topo = Topology()
    topo.set_properties(_kwargs)
    topo.validate()
    stream = file(filename, 'w')
    yaml.dump(topo.__dict__, stream, default_flow_style=False)


def read_topology(filename):
    stream = file(filename, 'r')
    topo_props = yaml.load(stream)
    topo = Topology()
    topo.set_properties(topo_props)
    topo.validate()
    return topo


def delete_topology(filename):
    os.remove(filename)

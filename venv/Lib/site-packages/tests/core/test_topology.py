import pytest
from topology.core.topology import Topology
from topology.core.policies import topology_mandatory_fields_set, all_fields_mandatory

@pytest.fixture(scope='module')
def mock_topo_props(request):
    return {
        'controllers': [{
            'name': 'test_controller',
            'protocol': 'https',
            'ip': '127.0.0.1',
            'port': 8443,
            'user': 'admin',
            'password': 'admin'
        }],
        'links': [{
            'source': 'switch_1',
            'destination': 'switch_2'
        }],
        'switches': [{
            'name': 'switch_1',
            'dpid': '123',
            'protocol': 'OpenFlow13'
        },{
            'name': 'switch_2',
            'dpid': '456',
            'protocol': 'OpenFlow13'
        }],
        'customers': [{
            'connects_to': 'test_endpoint_name',
            'customer': 'test_customer',
            'hostname': 'test_host_name',
            'port': 20
        }]
    }

def test_set_properties(mock_topo_props):
    topo = Topology()
    topo.set_properties(mock_topo_props)
    assert topo.controllers == mock_topo_props['controllers']
    assert topo.links == mock_topo_props['links']
    assert topo.switches == mock_topo_props['switches']
    assert topo.customers == mock_topo_props['customers']


def test_validate(mock_topo_props):
    topo = Topology()
    topo.set_properties(mock_topo_props)
    assert topo.validate(topology_mandatory_fields_set) is True
    with pytest.raises(AttributeError):
        topo.validate(all_fields_mandatory)




ALL_TOPOLOGY_PROPS = {'controllers', 'hosts', 'switches', 'links', 'interfaces', 'customers'}
MANDATORY_TOPOLOGY_PROPS = {'controllers', 'customers'}

ALL_CONTROLLER_PROPS = {'name', 'protocol', 'vip', 'ip', 'port', 'user', 'password',
                        'timeout', 'ssh_user', 'ssh_password', 'ssh_port'}
MANDATORY_CONTROLLER_PROPS = {'name', 'protocol', 'ip', 'port', 'user', 'password'}
ID_CONTROLLER_PROPS = {'name', 'ip'}

ALL_HOST_PROPS = {'name', 'ip', 'mask', 'type', 'user', 'password', 'port', 'mac', 'gw'}
MANDATORY_HOST_PROPS = {'name', 'ip'}
ID_HOST_PROPS = {'name', 'ip'}

ALL_SWITCH_PROPS = {'name', 'dpid', 'type', 'user', 'password', 'ip', 'port', 'protocol'}
MANDATORY_SWITCH_PROPS = {'name', 'dpid', 'protocol'}
ID_SWITCH_PROPS = {'name', 'dpid', 'ip'}

ALL_LINK_PROPS = {'destination', 'destination_port', 'source', 'source_port'}
MANDATORY_LINK_PROPS = {'destination', 'source'}
ID_LINK_PROPS = {'destination', 'destination_port', 'source', 'source_port'}

ALL_INTERFACE_PROPS = {'name', 'switch'}
MANDATORY_INTERFACE_PROPS = {'name', 'switch'}
ID_INTERFACE_PROPS = {'name'}

ALL_CUSTOMER_PROPS = {'hostname', 'port', 'connects_to', 'customer'}
MANDATORY_CUSTOMER_PROPS = {'hostname', 'port', 'connects_to', 'customer'}
ID_CUSTOMER_PROPS = {'hostname', 'port', 'connects_to', 'customer'}

DEFAULT_TOPOLOGY = {
        'controllers': [{
            'name': 'test_controller',
            'protocol': 'https',
            'ip': '127.0.0.1',
            'port': 8443,
            'user': 'admin',
            'password': 'admin'
        }],
        'hosts': [],
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
        'interfaces': [],
        'customers': [{
             'customer': 'test_customer',
             'connects_to': 'test_endpoint_name',
             'hostname': 'test_host_name',
             'port': 20
        }]
    }

import policies
import json
import yaml

DEFAULT_POLICY = policies.topology_mandatory_fields_set

class Topology(object):
    def __init__(self):
        self.controllers = []
        self.hosts = []
        self.switches = []
        self.links = []
        self.interfaces = []
        self.customers = []

    def set_properties(self, props):
        self._set_list_property('controllers', policies.valid_controller_properties, props.get('controllers', []))
        self._set_list_property('hosts', policies.valid_host_properties, props.get('hosts', []))
        self._set_list_property('switches', policies.valid_switch_properties, props.get('switches', []))
        self._set_list_property('links', policies.valid_link_properties, props.get('links', []))
        self._set_list_property('interfaces', policies.valid_interface_properties, props.get('interfaces', []))
        self._set_list_property('customers', policies.valid_customer_properties, props.get('customers', []))

    def validate(self, policy=DEFAULT_POLICY, props=None):
        if props is None:
            props = [p for p in vars(self) if getattr(self, p)]
        return policy(props)

    def _set_list_property(self, prop_name, policy, values):
        list_prop = []
        for value in values:
            if self.validate(policy, value):
                if prop_name is 'switches' and type(value['dpid']) is int:
                    value['dpid'] = str(value.get('dpid'))
                list_prop.append(value)
        setattr(self, prop_name, list_prop)

    def to_yaml(self):
        return yaml.dump(self.__dict__, default_flow_style=False)

    def to_json(self):
        return json.dumps(self.__dict__, indent=4)

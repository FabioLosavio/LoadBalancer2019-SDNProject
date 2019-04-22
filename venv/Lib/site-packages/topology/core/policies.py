import constants
import logging
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')


def all_fields_mandatory(props):
    return valid_properties(constants.ALL_TOPOLOGY_PROPS, constants.ALL_TOPOLOGY_PROPS, props)


def topology_mandatory_fields_set(props):
    return valid_properties(constants.ALL_TOPOLOGY_PROPS, constants.MANDATORY_TOPOLOGY_PROPS, props)


def valid_controller_properties(props):
    return valid_properties(constants.ALL_CONTROLLER_PROPS, constants.MANDATORY_CONTROLLER_PROPS, props)


def valid_controller_id_property(props):
    return valid_id_prop(constants.ID_CONTROLLER_PROPS, props)


def valid_host_properties(props):
    return valid_properties(constants.ALL_HOST_PROPS, constants.MANDATORY_HOST_PROPS, props)


def valid_host_id_property(props):
    return valid_id_prop(constants.ID_HOST_PROPS, props)


def valid_switch_properties(props):
    return valid_properties(constants.ALL_SWITCH_PROPS, constants.MANDATORY_SWITCH_PROPS, props)


def valid_switch_id_property(props):
    return valid_id_prop(constants.ID_SWITCH_PROPS, props)


def valid_link_properties(props):
    return valid_properties(constants.ALL_LINK_PROPS, constants.MANDATORY_LINK_PROPS, props)


def valid_link_id_property(props):
    return valid_id_prop(constants.ID_LINK_PROPS, props)


def valid_interface_properties(props):
    return valid_properties(constants.ALL_INTERFACE_PROPS, constants.MANDATORY_INTERFACE_PROPS, props)


def valid_interface_id_property(props):
    return valid_id_prop(constants.ID_INTERFACE_PROPS, props)


def valid_customer_properties(props):
    return valid_properties(constants.ALL_CUSTOMER_PROPS, constants.MANDATORY_CUSTOMER_PROPS, props)


def valid_customer_id_property(props):
    return valid_id_prop(constants.ID_CUSTOMER_PROPS, props)


def valid_properties(all_props, mandatory_props, props):

    invalid_props = set(props).difference(all_props)
    missing_props = mandatory_props.difference(props)

    if invalid_props:
        message = "Invalid properties set: {}"
        logging.error(message.format(', '.join(invalid_props)))
        logging.info("properties of object in error: {}".format(', '.join(str(e) for e in props.keys())))
        logging.info("values of object in error: {}".format(', '.join(str(e) for e in props.values())))

    elif missing_props:
        message = "Mandatory properties not set: {}"
        logging.error(message.format(', '.join(missing_props)))
        try:
            logging.info("properties of object in error: {}".format(', '.join(str(e) for e in props.keys())))
            logging.info("values of object in error: {}".format(', '.join(str(e) for e in props.values())))
        except AttributeError:
            logging.error("Failed to print values of object. Object has no values")
            raise

    return True


def valid_id_prop(id_props, props):
    if (id_props.difference(props)) > 2:
        return True
    else:
        message = "ERROR: Invalid IDs in: {}"
        logging.error(message.format(', '.join(props)))

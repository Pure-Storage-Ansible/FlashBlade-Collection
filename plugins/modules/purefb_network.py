#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2017, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
---
module: purefb_network
version_added: "1.0.0"
short_description:  Manage network interfaces in a Pure Storage FlashBlade
description:
    - This module manages network interfaces on Pure Storage FlashBlade.
    - When creating a network interface a subnet must already exist with
      a network prefix that covers the IP address of the interface being
      created.
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - Interface Name.
    required: true
    type: str
  state:
    description:
      - Create, delete or modifies a network interface.
    required: false
    default: present
    choices: [ "present", "absent" ]
    type: str
  address:
    description:
      - IP address of interface.
    required: false
    type: str
  services:
    description:
      - Define which services are configured for the interfaces.
    required: false
    choices: [ "data", "replication" ]
    default: data
    type: list
    elements: str
  itype:
    description:
      - Type of interface.
    required: false
    choices: [ "vip" ]
    default: vip
    type: str
  server:
    description:
    - The server to use this interface for data ingress.
    - Requires the I(services) of the interface to include I(data)
    type: str
    version_added: 1.20.0
extends_documentation_fragment:
    - purestorage.flashblade.purestorage.fb
"""

EXAMPLES = """
- name: Create new network interface named foo for the whole array
  purestorage.flashblade.purefb_network:
    name: foo
    address: 10.21.200.23
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Create new network interface named foo for server object bar
  purestorage.flashblade.purefb_network:
    name: foo2
    server: bar
    address: 10.21.200.23
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Change IP address of network interface named foo
  purestorage.flashblade.purefb_network:
    name: foo
    state: present
    address: 10.21.200.123
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete network interface named foo
  purestorage.flashblade.purefb_network:
    name: foo
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = """
"""

HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import (
        NetworkInterface,
        Reference,
    )
except ImportError:
    HAS_PYPURECLIENT = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


SERVER_API_VERSION = "2.16"


def get_iface(module, blade):
    """Return Filesystem or None"""
    res = blade.get_network_interfaces(names=[module.params["name"]])
    if res.status_code == 200:
        return list(res.items)[0]
    else:
        return None


def create_iface(module, blade):
    """Create Network Interface"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        if SERVER_API_VERSION in api_version and module.params["server"]:
            res = blade.post_network_interfaces(
                names=[module.params["name"]],
                network_interface=NetworkInterface(
                    address=module.params["address"],
                    services=module.params["services"],
                    type=module.params["itype"],
                    server=Reference(name=module.params["server"]),
                ),
            )
        else:
            res = blade.post_network_interfaces(
                names=module.params["name"],
                network_interface=NetworkInterface(
                    address=module.params["address"],
                    services=module.params["services"],
                    type=module.params["itype"],
                ),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Interface {0} creation failed. Error: {1}".format(
                    module.params["address"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def modify_iface(module, blade):
    """Modify Network Interface IP address"""
    changed = False
    failed = False
    failedmsg = None
    iface = get_iface(module, blade)
    if module.params["address"] != iface.address:
        changed = True
        if not module.check_mode:
            res = blade.patch_network_interfaces(
                names=[module.params["name"]],
                network_interface=NetworkInterface(address=module.params["address"]),
            )
            if res.status_code != 200:
                failed = True
                failedmsg = res.errors[0].message
    if set(module.params["services"]) != set(iface.services):
        changed = True
        if not module.check_mode:
            res = blade.patch_network_interfaces(
                names=[module.params["name"]],
                network_interface=NetworkInterface(services=module.params["services"]),
            )
            if res.status_code != 200:
                failed = True
                failedmsg = res.errors[0].message
    if hasattr(iface, "server") and module.params["server"] != iface.server.name:
        changed = True
        if not module.check_mode:
            res = blade.patch_network_interfaces(
                names=[module.params["name"]],
                network_interface=NetworkInterface(
                    server=Reference(name=module.params["address"])
                ),
            )
            if res.status_code != 200:
                failed = True
                failedmsg = res.errors[0].message
    if failed:
        module.fail_json(
            msg="Failed to modify Interface {0}. Error: {1}".format(
                module.params["name"], failedmsg
            )
        )
    module.exit_json(changed=changed)


def delete_iface(module, blade):
    """Delete Network Interface"""
    changed = True
    if not module.check_mode:
        res = blade.delete_network_interfaces(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete network {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            state=dict(type="str", default="present", choices=["present", "absent"]),
            address=dict(type="str"),
            server=dict(type="str"),
            services=dict(
                type="list",
                elements="str",
                default="data",
                choices=["data", "replication"],
            ),
            itype=dict(type="str", default="vip", choices=["vip"]),
        )
    )

    required_if = [["state", "present", ["address"]]]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PYPURECLIENT:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    state = module.params["state"]
    blade = get_system(module)
    api_version = list(blade.get_versions().items)
    iface = get_iface(module, blade)

    if state == "present" and not iface:
        create_iface(module, blade)
    elif state == "present" and iface:
        modify_iface(module, blade)
    elif state == "absent" and iface:
        delete_iface(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

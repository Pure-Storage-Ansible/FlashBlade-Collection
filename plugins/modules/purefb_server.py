#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2024, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefb_server
version_added: '1.20.0'
short_description: Manage FlashBlade servers
description:
- Add, update or delete FlashBlade servers
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the server
    type: str
    required: true
  state:
    description:
    - Define whether the Object Store Virtual Host should be added or deleted
    default: present
    choices: [ absent, present ]
    type: str
  dns:
    description:
    - The DNS configuration to be used for this server
    type: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Add server
  purestorage.flashblade.purefb_server:
    name: myserver
    dns: mydns
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3

- name: Delete server
  purestorage.flashblade.purefb_server:
    name: myserver
    state: absent
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3
"""

RETURN = r"""
"""

HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import Server, ServerPost, Reference
except ImportError:
    HAS_PYPURECLIENT = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

MIN_REQUIRED_API_VERSION = "2.16"


def delete_server(module, blade):
    """Delete server object"""
    changed = True
    if not module.check_mode:
        res = blade.delete_servers(
            names=[module.params["name"]], cascade_delete="directory-services"
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete server {0}. Error: {1}".format(
                    module.params["name"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def update_server(module, blade):
    """Update server object"""
    changed = False
    current_dns = list(blade.get_servers(names=[module.params["name"]]).items)[
        0
    ].dns.name
    if current_dns != module.params["dns"]:
        changed = True
        res = blade.patch_servers(
            names=[module.params["name"]],
            server=Server(dns=[Reference(name=module.params["dns"])]),
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to update server {0}. Error: {1}".format(
                    module.params["name"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def add_server(module, blade):
    """Add server object"""
    changed = True
    if not module.check_mode:
        if module.params("dns"):
            server = ServerPost(dns=[Reference(name=module.params["dns"])])
        else:
            server = ServerPost()
        res = blade.post_servers(
            names=[module.params["name"]],
            server=server,
            create_ds=module.params["name"] + "_nfs",
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to add server {0}. Error: {1}".format(
                    module.params["name"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            name=dict(type="str", required=True),
            dns=dict(type="str"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    if not HAS_PYPURECLIENT:
        module.fail_json(msg="py-pure-client sdk is required for this module")
    blade = get_system(module)
    api_version = list(blade.get_versions().items)

    if MIN_REQUIRED_API_VERSION not in api_version:
        module.fail_json(
            msg="FlashBlade REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )
    state = module.params["state"]

    exists = bool(blade.get_servers(names=[module.params["name"]]).status_code == 200)

    if not exists and state == "present":
        add_server(module, blade)
    elif exists and state == "present":
        update_server(module, blade)
    elif exists and state == "absent":
        delete_server(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

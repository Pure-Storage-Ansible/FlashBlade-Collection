#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2020, Simon Dodsley (simon@purestorage.com)
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
module: purefb_inventory
version_added: '1.0.0'
short_description: Collect information from Pure Storage FlashBlade
description:
  - Collect information from a Pure Storage FlashBlade running the
    Purity//FB operating system. By default, the module will collect basic
    information including hosts, host groups, protection
    groups and volume counts. Additional information can be collected
    based on the configured set of arguements.
author:
  - Pure Storage ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
extends_documentation_fragment:
  - purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: collect FlashBlade inventory
  purestorage.flashblade.purefb_inventory:
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
  register: blade_info
- name: show default information
  debug:
    msg: "{{ blade_info['purefb_info'] }}"

"""

RETURN = r"""
purefb_inventory:
  description: Returns the inventory information for the FlashBlade
  returned: always
  type: complex
  sample: {
        "blades": {
            "CH1.FB1": {
                "model": "FB-17TB",
                "serial": "PPCXA1942AFF5",
                "slot": 1,
                "status": "healthy"
            }
        },
        "chassis": {
            "CH1": {
                "index": 1,
                "model": null,
                "serial": "PMPAM163402AE",
                "slot": null,
                "status": "healthy"
            }
        },
        "controllers": {},
        "ethernet": {
            "CH1.FM1.ETH1": {
                "model": "624410002",
                "serial": "APF16360021PRV",
                "slot": 1,
                "speed": 40000000000,
                "status": "healthy"
            }
        },
        "fans": {
            "CH1.FM1.FAN1": {
                "slot": 1,
                "status": "healthy"
            }
        },
        "modules": {
            "CH1.FM1": {
                "model": "EFM-110",
                "serial": "PSUFS1640002C",
                "slot": 1,
                "status": "healthy"
            },
            "CH1.FM2": {
                "model": "EFM-110",
                "serial": "PSUFS1640004A",
                "slot": 2,
                "status": "healthy"
            }
        },
        "power": {
            "CH1.PWR1": {
                "model": "DS1600SPE-3",
                "serial": "M0500E00D8AJZ",
                "slot": 1,
                "status": "healthy"
            }
        },
        "switch": {}
    }
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    purefb_argument_spec,
)


def generate_hardware_dict(blade):
    hw_info = {
        "fans": {},
        "controllers": {},
        "blades": {},
        "chassis": {},
        "ethernet": {},
        "modules": {},
        "power": {},
        "switch": {},
    }
    components = blade.hardware.list_hardware(filter="type='fm'")
    for component in range(0, len(components.items)):
        component_name = components.items[component].name
        hw_info["modules"][component_name] = {
            "slot": components.items[component].slot,
            "status": components.items[component].status,
            "serial": components.items[component].serial,
            "model": components.items[component].model,
            "identify": getattr(
                components.items[component], "identify_enabled", "None"
            ),
        }
    components = blade.hardware.list_hardware(filter="type='eth'")
    for component in range(0, len(components.items)):
        component_name = components.items[component].name
        hw_info["ethernet"][component_name] = {
            "slot": components.items[component].slot,
            "status": components.items[component].status,
            "serial": components.items[component].serial,
            "model": components.items[component].model,
            "speed": components.items[component].speed,
        }
    components = blade.hardware.list_hardware(filter="type='fan'")
    for component in range(0, len(components.items)):
        component_name = components.items[component].name
        hw_info["fans"][component_name] = {
            "slot": components.items[component].slot,
            "status": components.items[component].status,
            "identify": getattr(
                components.items[component], "identify_enabled", "None"
            ),
        }
    components = blade.hardware.list_hardware(filter="type='fb'")
    for component in range(0, len(components.items)):
        component_name = components.items[component].name
        hw_info["blades"][component_name] = {
            "slot": components.items[component].slot,
            "status": components.items[component].status,
            "serial": components.items[component].serial,
            "model": components.items[component].model,
            "temperature": getattr(components.items[component], "temperature", "None"),
            "identify": getattr(
                components.items[component], "identify_enabled", "None"
            ),
        }
    components = blade.hardware.list_hardware(filter="type='pwr'")
    for component in range(0, len(components.items)):
        component_name = components.items[component].name
        hw_info["power"][component_name] = {
            "slot": components.items[component].slot,
            "status": components.items[component].status,
            "serial": components.items[component].serial,
            "model": components.items[component].model,
        }
    components = blade.hardware.list_hardware(filter="type='xfm'")
    for component in range(0, len(components.items)):
        component_name = components.items[component].name
        hw_info["switch"][component_name] = {
            "slot": components.items[component].slot,
            "status": components.items[component].status,
            "serial": components.items[component].serial,
            "model": components.items[component].model,
        }
    components = blade.hardware.list_hardware(filter="type='ch'")
    for component in range(0, len(components.items)):
        component_name = components.items[component].name
        hw_info["chassis"][component_name] = {
            "slot": components.items[component].slot,
            "index": components.items[component].index,
            "status": components.items[component].status,
            "serial": components.items[component].serial,
            "model": components.items[component].model,
        }
    components = blade.hardware.list_hardware(filter="type='bay'")
    for component in range(0, len(components.items)):
        component_name = components.items[component].name
        hw_info["chassis"][component_name] = {
            "slot": components.items[component].slot,
            "index": components.items[component].index,
            "status": components.items[component].status,
            "serial": components.items[component].serial,
            "model": components.items[component].model,
            "identify": getattr(
                components.items[component], "identify_enabled", "None"
            ),
        }

    return hw_info


def main():
    argument_spec = purefb_argument_spec()

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    blade = get_blade(module)

    module.exit_json(changed=False, purefb_info=generate_hardware_dict(blade))


if __name__ == "__main__":
    main()

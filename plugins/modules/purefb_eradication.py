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
module: purefb_eradication
version_added: '1.17.0'
short_description: Configure Pure Storage FlashBlade Eradication Timer
description:
- Configure the eradication timer for destroyed items on a FlashBlade.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  manual_eradication:
    description:
    - Set manual eradication status on the arrya level.
    type: str
    choices: [ "all-enabled", "file-disabled", "object-disabled", "all-disabled" ]
  eradication_delay:
    description:
    - Configures the eradication delay in days for destroyed
      filesystems and snapshots.
    - Allowed values are integers from 1 to 30. Default is 1
    default: 1
    type: int
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Set eradication timer to 30 days
  purestorage.flashblade.purefb_eradication:
    eradication_delay: 30
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Set eradication timer to 1 day but disabled for buckets
  purestorage.flashblade.purefb_eradication:
    manual_eradication: object-disabled
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flashblade import Array, ArrayEradicationConfig
except ImportError:
    HAS_PURESTORAGE = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

SEC_PER_DAY = 86400000
ERADICATION_API_VERSION = "2.13"


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            eradication_delay=dict(type="int", default=1),
            manual_eradication=dict(
                type="str",
                choices=[
                    "all-enabled",
                    "file-disabled",
                    "object-disabled",
                    "all-disabled",
                ],
            ),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    if not 30 >= module.params["eradication_delay"] >= 1:
        module.fail_json(msg="Eradication Timer must be between 1 and 30 days.")
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    blade = get_system(module)
    api_version = list(blade.get_versions().items)
    changed = False
    if ERADICATION_API_VERSION in api_version:
        eradication_config = list(blade.get_arrays().items)[0].eradication_config
        current_config = {
            "delay": eradication_config.eradication_delay,
            "manual": eradication_config.manual_eradication,
        }
        if (
            module.params["eradication_delay"]
            and module.params["eradication_delay"]
            != current_config.eradication_delay / SEC_PER_DAY
        ):
            new_delay = module.params["eradication_delay"] * SEC_PER_DAY
        else:
            new_delay = current_config.eradication_delay
        if (
            module.params["manual_eradication"]
            and module.params["manual_eradication"] != current_config.manual_eradication
        ):
            new_manual = module.params["manual_eradication"]
        else:
            new_manual = current_config.manula_eradication
        new_config = {"delay": new_delay, "manual": new_manual}
        if new_config != current_config:
            changed = True
            if not module.check_mode:
                eradication_config = ArrayEradicationConfig(
                    eradication_delay=new_delay, manula_eradication=new_manual
                )
                res = blade.patch_arrays(
                    array=Array(eradication_config=eradication_config)
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to change Eradication Config. Error: {0}".format(
                            res.errors[0].message
                        )
                    )
    else:
        module.fail_json(
            msg="Purity version does not support changing Eradication Configuration"
        )
    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()

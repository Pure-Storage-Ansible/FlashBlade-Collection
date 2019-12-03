#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: purefb_user
version_added: '2.10'
short_description: Modify FlashBlade local user account password
description:
- Modify local user's password on a Pure Stoage FlashBlade.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the local user account
    type: str
    default: pureuser
  password:
    description:
    - Password for the local user.
    type: str
    required: true
  old_password:
    description:
    - If changing an existing password, you must provide the old password for security
    type: str
    required: true
extends_documentation_fragment:
- purestorage.fb
'''

EXAMPLES = r'''
- name: Change password for local user (NOT IDEMPOTENT)
  purefb_user:
    password: anewpassword
    old_password: apassword
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
'''

RETURN = r'''
'''

HAS_PURITY_FB = True
try:
    from purity_fb import Admin
except ImportError:
    HAS_PURITY_FB = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import get_blade, purefb_argument_spec

MIN_REQUIRED_API_VERSION = '1.3'


def get_user(module, blade):
    """Return Local User Account or None"""
    user = None
    users = blade.admins.list_admins(expose=True)
    for acct in range(0, len(users)):
        if users.items[acct].name == module.params['name']:
            user = users.items[acct]
    return user


def update_user(module, blade):
    """Create or Update Local User Account"""
    changed = False
    if module.params['password']:
        if module.params['password'] != module.params['old_password']:
            try:
                newAdmin = Admin()
                newAdmin.password = module.params['password']
                newAdmin.old_password = module.params['old_password']
                blade.admins.update_admins(names=[module.params['name']], admin=newAdmin)
                changed = True
            except Exception:
                module.fail_json(msg='Local User {0}: Password reset failed. '
                                 'Check old password.'.format(module.params['name']))
        else:
            module.fail_json(msg='Local User Account {0}: Password change failed - '
                             'Check both old and new passwords'.format(module.params['name']))
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(dict(
        name=dict(required=True, type='str', default='pureuser'),
        password=dict(required=True, type='str', no_log=True),
        old_password=dict(required=True, type='str', no_log=True),
        api=dict(type='bool', default=False),
    ))

    module = AnsibleModule(argument_spec,
                           supports_check_mode=False)

    if not HAS_PURITY_FB:
        module.fail_json(msg='purity_fb sdk is required for this module')

    blade = get_blade(module)
    api_version = blade.api_version.list_versions().versions
    if MIN_REQUIRED_API_VERSION not in api_version:
        module.fail_json(msg="Purity//FB must be upgraded to support this module.")

    update_user(module, blade)

    module.exit_json(changed=False)


if __name__ == '__main__':
    main()

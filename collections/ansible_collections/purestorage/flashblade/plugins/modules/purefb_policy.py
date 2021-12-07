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
module: purefb_policy
version_added: '1.0.0'
short_description: Manage FlashBlade policies
description:
- Manage policies for filesystem, file replica links and object store access
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete policy.
    - Copy is applicable only to Object Store Access Policies Rules
    default: present
    type: str
    choices: [ absent, present, copy ]
  target:
    description:
    - Name of policy to copy rule to
    type: str
    version_added: "1.9.0"
  target_rule:
    description:
    - Name of the rule to copy the exisitng rule to.
    - If not defined the existing rule name is used.
    type: str
    version_added: "1.9.0"
  policy_type:
    description:
    - Type of policy
    default: snapshot
    type: str
    choices: [ snapshot, access ]
    version_added: "1.9.0"
  account:
    description:
    - Name of Object Store account policy applies to.
    - B(Special Case) I(pure:policy) is used for the system-wide S3 policies
    type: str
    version_added: "1.9.0"
  rule:
    description:
    - Name of the rule for the Object Store Access Policy
    - Rules in system-wide policies cannot be deleted or modified
    type: str
    version_added: "1.9.0"
  effect:
    description:
    - Allow S3 requests that match all of the I(actions) item selected.
      Rules are additive.
    type: str
    default: allow
    choices: [ allow ]
    version_added: "1.9.0"
  actions:
    description:
    - List of permissions to grant.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
    choices: [ s3:*,
              s3:AbortMultipartUpload,
              s3:CreateBucket,
              s3:DeleteBucket,
              s3:DeleteObject,
              s3:DeleteObjectVersion,
              s3:ExtendSafemodeRetentionPeriod,
              s3:GetBucketAcl,
              s3:GetBucketLocation,
              s3:GetBucketVersioning,
              s3:GetLifecycleConfiguration,
              s3:GetObject,
              s3:GetObjectAcl,
              s3:GetObjectVersion,
              s3:ListAllMyBuckets,
              s3:ListBucket,
              s3:ListBucketMultipartUploads,
              s3:ListBucketVersions,
              s3:ListMultipartUploadParts,
              s3:PutBucketVersioning,
              s3:PutLifecycleConfiguration,
              s3:PutObject ]
    version_added: "1.9.0"
  object_resources:
    description:
    - List of bucket names and object paths, with a wildcard (*) to
      specify objects in a bucket; e.g., bucket1, bucket1/*, bucket2,
      bucket2/*.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
    version_added: "1.9.0"
  source_ips:
    description:
    - List of IPs and subnets from which this rule should allow requests;
      e.g., 10.20.30.40, 10.20.30.0/24, 2001:DB8:1234:5678::/64.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
    version_added: "1.9.0"
  s3_prefixes:
    description:
    - List of 'folders' (object key prefixes) for which object listings
      may be requested.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
    version_added: "1.9.0"
  s3_delimiters:
    description:
    - List of delimiter characters allowed in object list requests.
    - Grants permissions to list 'folder names' (prefixes ending in a
      delimiter) instead of object keys.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
    version_added: "1.9.0"
  ignore_enforcement:
    description:
    - Certain combinations of actions and other rule elements are inherently
      ignored if specified together in a rule.
    - If set to true, operations which attempt to set these combinations will fail.
    - If set to false, such operations will instead be allowed.
    type: bool
    default: True
    version_added: "1.9.0"
  user:
    description:
    - User in the I(account) that the policy is granted to.
    type: str
    version_added: "1.9.0"
  force_delete:
    description:
    - Force the deletion of a Object Store Access Policy is this
      has attached users.
    - WARNING This can have undesired side-effects.
    - System-wide policies cannot be deleted
    type: bool
    default: False
    version_added: "1.9.0"
  name:
    description:
    - Name of the policy
    type: str
  enabled:
    description:
    - State of policy
    type: bool
    default: True
  every:
    description:
    - Interval between snapshots in seconds
    - Range available 300 - 31536000 (equates to 5m to 365d)
    type: int
  keep_for:
    description:
    - How long to keep snapshots for
    - Range available 300 - 31536000 (equates to 5m to 365d)
    - Must not be set less than I(every)
    type: int
  at:
    description:
    - Provide a time in 12-hour AM/PM format, eg. 11AM
    type: str
  timezone:
    description:
    - Time Zone used for the I(at) parameter
    - If not provided, the module will attempt to get the current local timezone from the server
    type: str
  filesystem:
    description:
    - List of filesystems to add to a policy on creation
    - To amend policy members use the I(purefb_fs) module
    type: list
    elements: str
  replica_link:
    description:
    - List of filesystem replica links to add to a policy on creation
    - To amend policy members use the I(purefb_fs_replica) module
    type: list
    elements: str
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create a simple snapshot policy with no rules
  purefb_policy:
    name: test_policy
    policy_type: snapshot
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a snapshot policy and connect to existing filesystems and filesystem replica links
  purefb_policy:
    name: test_policy_with_members
    policy_type: snapshot
    filesystem:
    - fs1
    - fs2
    replica_link:
    - rl1
    - rl2
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a snapshot policy with rules
  purefb_policy:
    name: test_policy2
    policy_type: snapshot
    at: 11AM
    keep_for: 86400
    every: 86400
    timezone: Asia/Shanghai
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a snapshot policy
  purefb_policy:
    name: test_policy
    policy_type: snapshot
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create an empty object store access policy
  purefb_policy:
    name: test_os_policy
    account: test
    policy_type: access
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create an empty object store access policy and assign user
  purefb_policy:
    name: test_os_policy
    account: test
    policy_type: access
    user: fred
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a object store access policy with simple rule
  purefb_policy:
    name: test_os_policy_rule
    policy_type: access
    account: test
    rule: rule1
    actions: "s3:*"
    object_resources: "*"
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a rule from an object store access policy
  purefb_policy:
    name: test_os_policy_rule
    account: test
    policy_type: access
    rule: rule1
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a user from an object store access policy
  purefb_policy:
    name: test_os_policy_rule
    account: test
    user: fred
    policy_type: access
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete an object store access policy with attached users (USE WITH CAUTION)
  purefb_policy:
    name: test_os_policy_rule
    account: test
    policy_type: access
    force_delete: true
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete an object store access policy with no attached users
  purefb_policy:
    name: test_os_policy_rule
    account: test
    policy_type: access
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Copy an object store access policy rule to another exisitng policy
  purefb_policy:
    name: test_os_policy_rule
    policy_type: access
    account: test
    target: "account2/anotherpolicy"
    target_rule: new_rule1
    state: copy
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

HAS_PURITYFB = True
try:
    from purity_fb import Policy, PolicyRule, PolicyPatch
except ImportError:
    HAS_PURITYFB = False

HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import (
        PolicyRuleObjectAccessCondition,
        PolicyRuleObjectAccessPost,
        PolicyRuleObjectAccess,
    )
except ImportError:
    HAS_PYPURECLIENT = False

HAS_PYTZ = True
try:
    import pytz
except ImportError:
    HAS_PYTX = False

import os
import re
import platform

from ansible.module_utils.common.process import get_bin_path
from ansible.module_utils.facts.utils import get_file_content
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    get_system,
    purefb_argument_spec,
)


MIN_REQUIRED_API_VERSION = "1.9"
ACCESS_POLICY_API_VERSION = "2.2"


def _convert_to_millisecs(hour):
    if hour[-2:] == "AM" and hour[:2] == "12":
        return 0
    elif hour[-2:] == "AM":
        return int(hour[:-2]) * 3600000
    elif hour[-2:] == "PM" and hour[:2] == "12":
        return 43200000
    return (int(hour[:-2]) + 12) * 3600000


def _findstr(text, match):
    for line in text.splitlines():
        if match in line:
            found = line
    return found


def _get_local_tz(module, timezone="UTC"):
    """
    We will attempt to get the local timezone of the server running the module and use that.
    If we can't get the timezone then we will set the default to be UTC

    Linnux has been tested and other opersting systems should be OK.
    Failures cause assumption of UTC

    Windows is not supported and will assume UTC
    """
    if platform.system() == "Linux":
        timedatectl = get_bin_path("timedatectl")
        if timedatectl is not None:
            rcode, stdout, stderr = module.run_command(timedatectl)
            if rcode == 0 and stdout:
                line = _findstr(stdout, "Time zone")
                full_tz = line.split(":", 1)[1].rstrip()
                timezone = full_tz.split()[0]
                return timezone
            else:
                module.warn("Incorrect timedatectl output. Timezone will be set to UTC")
        else:
            if os.path.exists("/etc/timezone"):
                timezone = get_file_content("/etc/timezone")
            else:
                module.warn("Could not find /etc/timezone. Assuming UTC")

    elif platform.system() == "SunOS":
        if os.path.exists("/etc/default/init"):
            for line in get_file_content("/etc/default/init", "").splitlines():
                if line.startswith("TZ="):
                    timezone = line.split("=", 1)[1]
                    return timezone
        else:
            module.warn("Could not find /etc/default/init. Assuming UTC")

    elif re.match("^Darwin", platform.platform()):
        systemsetup = get_bin_path("systemsetup")
        if systemsetup is not None:
            rcode, stdout, stderr = module.execute(systemsetup, "-gettimezone")
            if rcode == 0 and stdout:
                timezone = stdout.split(":", 1)[1].lstrip()
            else:
                module.warn("Could not run systemsetup. Assuming UTC")
        else:
            module.warn("Could not find systemsetup. Assuming UTC")

    elif re.match("^(Free|Net|Open)BSD", platform.platform()):
        if os.path.exists("/etc/timezone"):
            timezone = get_file_content("/etc/timezone")
        else:
            module.warn("Could not find /etc/timezone. Assuming UTC")

    elif platform.system() == "AIX":
        aix_oslevel = int(platform.version() + platform.release())
        if aix_oslevel >= 61:
            if os.path.exists("/etc/environment"):
                for line in get_file_content("/etc/environment", "").splitlines():
                    if line.startswith("TZ="):
                        timezone = line.split("=", 1)[1]
                        return timezone
            else:
                module.warn("Could not find /etc/environment. Assuming UTC")
        else:
            module.warn(
                "Cannot determine timezone when AIX os level < 61. Assuming UTC"
            )

    else:
        module.warn("Could not find /etc/timezone. Assuming UTC")

    return timezone


def delete_os_policy(module, blade):
    """Delete Object Store Access Policy, Rule, or User

    If rule is provided then delete the rule if it exists.
    If user is provided then remove grant from user if granted.
    If no user or rule provided delete the whole policy.
    Cannot delete a policy with attached users, so delete all users
    if the force_delete option is selected.
    """

    changed = False
    policy_name = module.params["account"] + "/" + module.params["name"]
    policy_delete = True
    if module.params["rule"]:
        policy_delete = False
        res = blade.get_object_store_access_policies_rules(
            policy_names=[policy_name], names=[module.params["rule"]]
        )
        if res.status_code == 200 and res.total_item_count != 0:
            changed = True
            if not module.check_mode:
                res = blade.delete_object_store_access_policies_object_store_rules(
                    policy_names=[policy_name], names=[module.params["rule"]]
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to delete users from policy {0}. Error: {1} - {2}".format(
                            policy_name, res.errors[0].context, res.errors[0].message
                        )
                    )

    if module.params["user"]:
        member_name = module.params["account"] + "/" + module.params["user"]
        policy_delete = False
        res = blade.get_object_store_access_policies_object_store_users(
            policy_names=[policy_name], member_names=[member_name]
        )
        if res.status_code == 200 and res.total_item_count != 0:
            changed = True
            if not module.check_mode:
                member_name = module.params["account"] + "/" + module.params["user"]
                res = blade.delete_object_store_access_policies_object_store_users(
                    policy_names=[policy_name], member_names=[member_name]
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to delete users from policy {0}. Error: {1} - {2}".format(
                            policy_name, res.errors[0].context, res.errors[0].message
                        )
                    )

    if policy_delete:
        if module.params["account"].lower() == "pure:policy":
            module.fail_json(msg="System-Wide policies cannot be deleted.")
        policy_users = list(
            blade.get_object_store_access_policies_object_store_users(
                policy_names=[policy_name]
            ).items
        )
        if len(policy_users) == 0:
            changed = True
            if not module.check_mode:
                res = blade.delete_object_store_access_policies(names=[policy_name])
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to delete policy {0}. Error: {1}".format(
                            policy_name, res.errors[0].message
                        )
                    )
        else:
            if module.params["force_delete"]:
                changed = True
                if not module.check_mode:
                    for user in range(0, len(policy_users)):
                        res = blade.delete_object_store_access_policies_object_store_users(
                            member_names=[policy_users[user].member.name],
                            policy_names=[policy_name],
                        )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to delete user {0} from policy {1}, "
                                "Error: {2}".format(
                                    policy_users[user].member,
                                    policy_name,
                                    res.errors[0].message,
                                )
                            )
                    res = blade.delete_object_store_access_policies(names=[policy_name])
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to delete policy {0}. Error: {1}".format(
                                policy_name, res.errors[0].message
                            )
                        )
            else:
                module.fail_json(
                    msg="Policy {0} cannot be deleted with connected users".format(
                        policy_name
                    )
                )
    module.exit_json(changed=changed)


def create_os_policy(module, blade):
    """Create Object Store Access Policy"""
    changed = True
    policy_name = module.params["account"] + "/" + module.params["name"]
    if not module.check_mode:
        res = blade.post_object_store_access_policies(names=[policy_name])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create access policy {0}.".format(policy_name)
            )
        if module.params["rule"]:
            if not module.params["actions"] or not module.params["object_resources"]:
                module.fail_json(
                    msg="Parameters `actions` and `object_resources` "
                    "are required to create a new rule"
                )
            conditions = PolicyRuleObjectAccessCondition(
                source_ips=module.params["source_ips"],
                s3_delimiters=module.params["s3_delimiters"],
                s3_prefixes=module.params["s3_prefixes"],
            )
            rule = PolicyRuleObjectAccessPost(
                actions=module.params["actions"],
                resources=module.params["object_resources"],
                conditions=conditions,
            )
            res = blade.post_object_store_access_policies_rules(
                policy_names=policy_name,
                names=[module.params["rule"]],
                enforce_action_restrictions=module.params["ignore_enforcement"],
                rule=rule,
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create rule {0} to policy {1}. Error: {2}".format(
                        module.params["rule"], policy_name, res.errors[0].message
                    )
                )
        if module.params["user"]:
            member_name = module.params["account"] + "/" + module.params["user"]
            res = blade.post_object_store_access_policies_object_store_users(
                member_names=[member_name], policy_names=[policy_name]
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to add users to policy {0}. Error: {1} - {2}".format(
                        policy_name, res.errors[0].context, res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def update_os_policy(module, blade, policy):
    """Update Object Store Access Policy"""
    changed = False
    policy_name = module.params["account"] + "/" + module.params["name"]
    if module.params["rule"]:
        current_policy_rule = blade.get_object_store_access_policies_rules(
            policy_names=[policy_name], names=[module.params["rule"]]
        )
        if current_policy_rule.status_code != 200:
            conditions = PolicyRuleObjectAccessCondition(
                source_ips=module.params["source_ips"],
                s3_delimiters=module.params["s3_delimiters"],
                s3_prefixes=module.params["s3_prefixes"],
            )
            rule = PolicyRuleObjectAccessPost(
                actions=module.params["actions"],
                resources=module.params["object_resources"],
                conditions=conditions,
            )
            res = blade.post_object_store_access_policies_rules(
                policy_names=policy_name,
                names=[module.params["rule"]],
                enforce_action_restrictions=module.params["ignore_enforcement"],
                rule=rule,
            )
        else:
            old_policy_rule = list(current_policy_rule.items)[0]
            current_rule = {
                "actions": old_policy_rule.actions,
                "resources": old_policy_rule.resources,
                "ips": getattr(old_policy_rule.conditions, "source_ips", None),
                "prefixes": getattr(old_policy_rule.conditions, "s3_prefixes", None),
                "delimiters": getattr(
                    old_policy_rule.conditions, "s3_delimiters", None
                ),
            }
            if module.params["actions"]:
                new_actions = sorted(module.params["actions"])
            else:
                new_actions = sorted(current_rule["actions"])
            if module.params["object_resources"]:
                new_resources = sorted(module.params["object_resources"])
            else:
                new_resources = sorted(current_rule["resources"])
            if module.params["s3_prefixes"]:
                new_prefixes = sorted(module.params["s3_prefixes"])
            elif current_rule["prefixes"]:
                new_prefixes = sorted(current_rule["prefixes"])
            else:
                new_prefixes = None
            if module.params["s3_delimiters"]:
                new_delimiters = sorted(module.params["s3_delimiters"])
            elif current_rule["delimiters"]:
                new_delimiters = sorted(current_rule["delimiters"])
            else:
                new_delimiters = None
            if module.params["source_ips"]:
                new_ips = sorted(module.params["source_ips"])
            elif current_rule["ips"]:
                new_ips = sorted(current_rule["source_ips"])
            else:
                new_ips = None
            new_rule = {
                "actions": new_actions,
                "resources": new_resources,
                "ips": new_ips,
                "prefixes": new_prefixes,
                "delimiters": new_delimiters,
            }
            if current_rule != new_rule:
                changed = True
                if not module.check_mode:
                    conditions = PolicyRuleObjectAccessCondition(
                        source_ips=new_rule["ips"],
                        s3_prefixes=new_rule["prefixes"],
                        s3_delimiters=new_rule["delimiters"],
                    )
                    rule = PolicyRuleObjectAccess(
                        actions=new_rule["actions"],
                        resources=new_rule["resources"],
                        conditions=conditions,
                    )
                    res = blade.patch_object_store_access_policies_rules(
                        policy_names=[policy_name],
                        names=[module.params["rule"]],
                        rule=rule,
                        enforce_action_restrictions=module.params["ignore_enforcement"],
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update rule {0} in policy {1}. Error: {2}".format(
                            module.params["rule"], policy_name, res.errors[0].message
                        )
                    )
    if module.params["user"]:
        member_name = module.params["account"] + "/" + module.params["user"]
        res = blade.get_object_store_access_policies_object_store_users(
            policy_names=[policy_name], member_names=[member_name]
        )
        if res.status_code != 200 or (
            res.status_code == 200 and res.total_item_count == 0
        ):
            changed = True
            if not module.check_mode:
                res = blade.post_object_store_access_policies_object_store_users(
                    member_names=[member_name], policy_names=[policy_name]
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to add user {0} to policy {1}. Error: {2}".format(
                            member_name, policy_name, res.errors[0].message
                        )
                    )
    module.exit_json(changed=changed)


def copy_os_policy_rule(module, blade):
    """Copy an existing policy rule to a new policy"""
    changed = True
    policy_name = module.params["account"] + "/" + module.params["name"]
    if not module.params["target_rule"]:
        module.params["target_rule"] = module.params["rule"]
    if (
        blade.get_object_store_access_policies_rules(
            policy_names=[module.params["target"]], names=[module.params["target_rule"]]
        ).status_code
        == 200
    ):
        module.fail_json(
            msg="Target rule {0} already exists in policy {1}".format(
                module.params["target_rule"], policy_name
            )
        )
    current_rule = list(
        blade.get_object_store_access_policies_rules(
            policy_names=[policy_name], names=[module.params["rule"]]
        ).items
    )[0]
    if not module.check_mode:
        conditions = PolicyRuleObjectAccessCondition(
            source_ips=current_rule.conditions.source_ips,
            s3_delimiters=current_rule.conditions.s3_delimiters,
            s3_prefixes=current_rule.conditions.s3_prefixes,
        )
        rule = PolicyRuleObjectAccessPost(
            actions=current_rule.actions,
            resources=current_rule.resources,
            conditions=conditions,
        )
        res = blade.post_object_store_access_policies_rules(
            policy_names=module.params["target"],
            names=[module.params["target_rule"]],
            enforce_action_restrictions=module.params["ignore_enforcement"],
            rule=rule,
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to copy rule {0} from policy {1} to policy {2}. "
                "Error: {3}".format(
                    module.params["rule"],
                    policy_name,
                    module.params["target"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def delete_policy(module, blade):
    """Delete policy"""
    changed = True
    if not module.check_mode:
        try:
            blade.policies.delete_policies(names=[module.params["name"]])
        except Exception:
            module.fail_json(
                msg="Failed to delete policy {0}.".format(module.params["name"])
            )
    module.exit_json(changed=changed)


def create_policy(module, blade):
    """Create snapshot policy"""
    changed = True
    if not module.check_mode:
        try:
            if module.params["at"] and module.params["every"]:
                if not module.params["every"] % 86400 == 0:
                    module.fail_json(
                        msg="At time can only be set if every value is a multiple of 86400"
                    )
                if not module.params["timezone"]:
                    module.params["timezone"] = _get_local_tz(module)
                    if module.params["timezone"] not in pytz.all_timezones_set:
                        module.fail_json(
                            msg="Timezone {0} is not valid".format(
                                module.params["timezone"]
                            )
                        )
            if not module.params["keep_for"]:
                module.params["keep_for"] = 0
            if not module.params["every"]:
                module.params["every"] = 0
            if module.params["keep_for"] < module.params["every"]:
                module.fail_json(
                    msg="Retention period cannot be less than snapshot interval."
                )
            if module.params["at"] and not module.params["timezone"]:
                module.params["timezone"] = _get_local_tz(module)
                if module.params["timezone"] not in set(pytz.all_timezones_set):
                    module.fail_json(
                        msg="Timezone {0} is not valid".format(
                            module.params["timezone"]
                        )
                    )

            if module.params["keep_for"]:
                if not 300 <= module.params["keep_for"] <= 34560000:
                    module.fail_json(
                        msg="keep_for parameter is out of range (300 to 34560000)"
                    )
                if not 300 <= module.params["every"] <= 34560000:
                    module.fail_json(
                        msg="every parameter is out of range (300 to 34560000)"
                    )
                if module.params["at"]:
                    attr = Policy(
                        enabled=module.params["enabled"],
                        rules=[
                            PolicyRule(
                                keep_for=module.params["keep_for"] * 1000,
                                every=module.params["every"] * 1000,
                                at=_convert_to_millisecs(module.params["at"]),
                                time_zone=module.params["timezone"],
                            )
                        ],
                    )
                else:
                    attr = Policy(
                        enabled=module.params["enabled"],
                        rules=[
                            PolicyRule(
                                keep_for=module.params["keep_for"] * 1000,
                                every=module.params["every"] * 1000,
                            )
                        ],
                    )
            else:
                attr = Policy(enabled=module.params["enabled"])
            blade.policies.create_policies(names=[module.params["name"]], policy=attr)
        except Exception:
            module.fail_json(
                msg="Failed to create policy {0}.".format(module.params["name"])
            )
        if module.params["filesystem"]:
            try:
                blade.file_systems.list_file_systems(names=module.params["filesystem"])
                blade.policies.create_policy_filesystems(
                    policy_names=[module.params["name"]],
                    member_names=module.params["filesystem"],
                )
            except Exception:
                blade.policies.delete_policies(names=[module.params["name"]])
                module.fail_json(
                    msg="Failed to connect filesystems to policy {0}, "
                    "or one of {1} doesn't exist.".format(
                        module.params["name"], module.params["filesystem"]
                    )
                )
        if module.params["replica_link"]:
            for link in module.params["replica_link"]:
                remote_array = (
                    blade.file_system_replica_links.list_file_system_replica_links(
                        local_file_system_names=[link]
                    )
                )
                try:
                    blade.policies.create_policy_file_system_replica_links(
                        policy_names=[module.params["name"]],
                        member_names=[link],
                        remote_names=[remote_array.items[0].remote.name],
                    )
                except Exception:
                    blade.policies.delete_policies(names=[module.params["name"]])
                    module.fail_json(
                        msg="Failed to connect filesystem replicsa link {0} to policy {1}. "
                        "Replica Link {0} does not exist.".format(
                            link, module.params["name"]
                        )
                    )
    module.exit_json(changed=changed)


def update_policy(module, blade, policy):
    """Update snapshot policy"""
    changed = False
    if not policy.rules:
        current_policy = {
            "time_zone": None,
            "every": 0,
            "keep_for": 0,
            "at": 0,
            "enabled": policy.enabled,
        }
    else:
        if policy.rules[0].keep_for != 0:
            policy.rules[0].keep_for = int(policy.rules[0].keep_for / 1000)
        if policy.rules[0].every != 0:
            policy.rules[0].every = int(policy.rules[0].every / 1000)

        current_policy = {
            "time_zone": policy.rules[0].time_zone,
            "every": policy.rules[0].every,
            "keep_for": policy.rules[0].keep_for,
            "at": policy.rules[0].at,
            "enabled": policy.enabled,
        }
    if not module.params["every"]:
        every = 0
    else:
        every = module.params["every"]
    if not module.params["keep_for"]:
        keep_for = 0
    else:
        keep_for = module.params["keep_for"]
    if module.params["at"]:
        at_time = _convert_to_millisecs(module.params["at"])
    else:
        at_time = None
    if not module.params["timezone"]:
        timezone = _get_local_tz(module)
    else:
        timezone = module.params["timezone"]
    if at_time:
        new_policy = {
            "time_zone": timezone,
            "every": every,
            "keep_for": keep_for,
            "at": at_time,
            "enabled": module.params["enabled"],
        }
    else:
        new_policy = {
            "time_zone": None,
            "every": every,
            "keep_for": keep_for,
            "at": None,
            "enabled": module.params["enabled"],
        }
    if (
        new_policy["time_zone"]
        and new_policy["time_zone"] not in pytz.all_timezones_set
    ):
        module.fail_json(
            msg="Timezone {0} is not valid".format(module.params["timezone"])
        )

    if current_policy != new_policy:
        if not module.params["at"]:
            module.params["at"] = current_policy["at"]
        if not module.params["keep_for"]:
            module.params["keep_for"] = current_policy["keep_for"]
        if not module.params["every"]:
            module.params["every"] = current_policy["every"]
        if module.params["at"] and module.params["every"]:
            if not module.params["every"] % 86400 == 0:
                module.fail_json(
                    msg="At time can only be set if every value is a multiple of 86400"
                )
        if module.params["keep_for"] < module.params["every"]:
            module.fail_json(
                msg="Retention period cannot be less than snapshot interval."
            )
        if module.params["at"] and not module.params["timezone"]:
            module.params["timezone"] = _get_local_tz(module)
            if module.params["timezone"] not in set(pytz.all_timezones_set):
                module.fail_json(
                    msg="Timezone {0} is not valid".format(module.params["timezone"])
                )

        changed = True
        if not module.check_mode:
            try:
                attr = PolicyPatch()
                attr.enabled = module.params["enabled"]
                if at_time:
                    attr.add_rules = [
                        PolicyRule(
                            keep_for=module.params["keep_for"] * 1000,
                            every=module.params["every"] * 1000,
                            at=at_time,
                            time_zone=timezone,
                        )
                    ]
                else:
                    attr.add_rules = [
                        PolicyRule(
                            keep_for=module.params["keep_for"] * 1000,
                            every=module.params["every"] * 1000,
                        )
                    ]
                attr.remove_rules = [
                    PolicyRule(
                        keep_for=current_policy["keep_for"] * 1000,
                        every=current_policy["every"] * 1000,
                        at=current_policy["at"],
                        time_zone=current_policy["time_zone"],
                    )
                ]
                blade.policies.update_policies(
                    names=[module.params["name"]], policy_patch=attr
                )
            except Exception:
                module.fail_json(
                    msg="Failed to update policy {0}.".format(module.params["name"])
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(
                type="str", default="present", choices=["absent", "present", "copy"]
            ),
            policy_type=dict(
                type="str", default="snapshot", choices=["snapshot", "access"]
            ),
            enabled=dict(type="bool", default=True),
            timezone=dict(type="str"),
            name=dict(type="str"),
            at=dict(type="str"),
            every=dict(type="int"),
            keep_for=dict(type="int"),
            filesystem=dict(type="list", elements="str"),
            replica_link=dict(type="list", elements="str"),
            account=dict(type="str"),
            target=dict(type="str"),
            target_rule=dict(type="str"),
            rule=dict(type="str"),
            user=dict(type="str"),
            effect=dict(type="str", default="allow", choices=["allow"]),
            actions=dict(
                type="list",
                elements="str",
                choices=[
                    "s3:*",
                    "s3:AbortMultipartUpload",
                    "s3:CreateBucket",
                    "s3:DeleteBucket",
                    "s3:DeleteObject",
                    "s3:DeleteObjectVersion",
                    "s3:ExtendSafemodeRetentionPeriod",
                    "s3:GetBucketAcl",
                    "s3:GetBucketLocation",
                    "s3:GetBucketVersioning",
                    "s3:GetLifecycleConfiguration",
                    "s3:GetObject",
                    "s3:GetObjectAcl",
                    "s3:GetObjectVersion",
                    "s3:ListAllMyBuckets",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:ListBucketVersions",
                    "s3:ListMultipartUploadParts",
                    "s3:PutBucketVersioning",
                    "s3:PutLifecycleConfiguration",
                    "s3:PutObject",
                ],
            ),
            object_resources=dict(type="list", elements="str"),
            source_ips=dict(type="list", elements="str"),
            s3_prefixes=dict(type="list", elements="str"),
            s3_delimiters=dict(type="list", elements="str"),
            ignore_enforcement=dict(type="bool", default=True),
            force_delete=dict(type="bool", default=False),
        )
    )

    required_together = [["keep_for", "every"]]
    required_if = [["policy_type", "access", ["account", "name"]]]

    module = AnsibleModule(
        argument_spec,
        required_together=required_together,
        required_if=required_if,
        supports_check_mode=True,
    )

    if not HAS_PURITYFB:
        module.fail_json(msg="purity-fb sdk is required for this module")
    if not HAS_PYTZ:
        module.fail_json(msg="pytz is required for this module")

    state = module.params["state"]
    blade = get_blade(module)
    versions = blade.api_version.list_versions().versions
    if module.params["policy_type"] == "access":
        if ACCESS_POLICY_API_VERSION not in versions:
            module.fail_json(
                msg="Minimum FlashBlade REST version required: {0}".format(
                    MIN_REQUIRED_API_VERSION
                )
            )
        if not HAS_PYPURECLIENT:
            module.fail_json(msg="py-pure-client sdk is required for this module")
        blade = get_system(module)
        try:
            policy = list(
                blade.get_object_store_access_policies(
                    names=[module.params["account"] + "/" + module.params["name"]]
                ).items
            )[0]
        except AttributeError:
            policy = None
        if module.params["user"]:
            policy_name = module.params["account"] + "/" + module.params["name"]
            member_name = module.params["account"] + "/" + module.params["user"]
            res = blade.get_object_store_users(filter='name="member_name"')
            if res.status_code != 200:
                module.fail_json(
                    msg="User {0} does not exist in account {1}".format(
                        module.params["user"], module.params["account"]
                    )
                )
        if policy and state == "present":
            update_os_policy(module, blade, policy)
        elif state == "present" and not policy:
            create_os_policy(module, blade)
        elif state == "absent" and policy:
            delete_os_policy(module, blade)
        elif state == "copy" and module.params["target"] and module.params["rule"]:
            if "/" not in module.params["target"]:
                module.fail_json(
                    msg='Incorrect format for target policy. Must be "<account>/<name>"'
                )
            if (
                blade.get_object_store_access_policies(
                    names=[module.params["target"]]
                ).status_code
                != 200
            ):
                module.fail_json(
                    msg="Target policy {0} does not exist".format(
                        module.params["target"]
                    )
                )
            copy_os_policy_rule(module, blade)
    else:
        if MIN_REQUIRED_API_VERSION not in versions:
            module.fail_json(
                msg="Minimum FlashBlade REST version required: {0}".format(
                    MIN_REQUIRED_API_VERSION
                )
            )
        try:
            policy = blade.policies.list_policies(names=[module.params["name"]]).items[
                0
            ]
        except Exception:
            policy = None

        if policy and state == "present":
            update_policy(module, blade, policy)
        elif state == "present" and not policy:
            create_policy(module, blade)
        elif state == "absent" and policy:
            delete_policy(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()

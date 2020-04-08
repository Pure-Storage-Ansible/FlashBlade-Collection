
purefb_policy -- Manage FlashBlade policies
===========================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Manage policies for filesystem and file replica links



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1
- netaddr
- pytz



Parameters
----------

  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  state (optional, str, present)
    Create or delete policy


  every (optional, int, None)
    Interval between snapshots in seconds

    Range available 300 - 31536000 (equates to 5m to 365d)


  name (True, str, None)
    Name of the policy


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  timezone (optional, str, None)
    Time Zone used for the *at* parameter

    If not provided, the module will attempt to get the current local timezone from the server


  keep_for (optional, int, None)
    How long to keep snapshots for

    Range available 300 - 31536000 (equates to 5m to 365d)

    Must not be set less than *every*


  enabled (optional, bool, True)
    State of policy


  at (optional, str, None)
    Provide a time in 12-hour AM/PM format, eg. 11AM





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Create a simple policy with no rules
      purefb_policy:
        name: test_policy
        fb_url: 10.10.10.2
        api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
    - name: Create a policy with rules
      purefb_policy:
        name: test_policy2
        at: 11AM
        keep_for: 86400
        every: 86400
        timezone: Asia/Shanghai
        fb_url: 10.10.10.2
        api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
    - name: Delete a policy
      purefb_policy:
        name: test_policy
        state: absent
        fb_url: 10.10.10.2
        api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


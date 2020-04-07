
purefb_user -- Modify FlashBlade local user account password
============================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Modify local user's password on a Pure Stoage FlashBlade.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1
- netaddr
- pytz



Parameters
----------

  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  password (True, str, None)
    Password for the local user.


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  name (optional, str, pureuser)
    The name of the local user account


  old_password (True, str, None)
    If changing an existing password, you must provide the old password for security





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Change password for local user (NOT IDEMPOTENT)
      purefb_user:
        password: anewpassword
        old_password: apassword
        fb_url: 10.10.10.2
        api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


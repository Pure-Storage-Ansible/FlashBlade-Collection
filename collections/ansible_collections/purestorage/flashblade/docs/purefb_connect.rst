
purefb_connect -- Manage replication connections between two FlashBlades
========================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Manage replication connections to specified remote FlashBlade system



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1
- netaddr
- pytz



Parameters
----------

  target_url (True, str, None)
    Management IP address of target FlashBlade system


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  target_api (optional, str, None)
    API token for target FlashBlade system


  encrypted (optional, bool, False)
    Define if replication connection is encrypted


  state (optional, str, present)
    Create or delete replication connection


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Create a connection to remote FlashBlade system
      purefb_connect:
        target_url: 10.10.10.20
        target_api: 9c0b56bc-f941-f7a6-9f85-dcc3e9a8f7d6
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592
    - name: Delete connection to target FlashBlade system
      purefb_connect:
        state: absent
        target_url: 10.10.10.20
        target_api: 9c0b56bc-f941-f7a6-9f85-dcc3e9a8f7d6
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


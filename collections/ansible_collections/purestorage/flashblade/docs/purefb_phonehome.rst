
purefb_phonehome -- Enable or Disable Pure Storage FlashBlade Phone Home
========================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Enablke or Disable Remote Phone Home for a Pure Storage FlashBlade.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1
- netaddr
- pytz



Parameters
----------

  state (optional, str, present)
    Define state of phone home


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


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

    
    - name: Enable Remote Phone Home
      purefb_phonehome:
        fb_url: 10.10.10.2
        api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
    - name: Disable Remote Phone Home
      purefb_phonehome:
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


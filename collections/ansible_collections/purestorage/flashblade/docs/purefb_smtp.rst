
purefb_smtp -- Configure SMTP for Pure Storage FlashBlade
=========================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Configure SMTP for a Pure Storage FlashBlade.

Whilst there can be no relay host, a sender domain must be configured.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1



Parameters
----------

  host (optional, str, None)
    Relay server name


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  domain (True, str, None)
    Domain name for alert messages


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

    
    - name: Configure SMTP settings
      purefb_smtp:
        host: hostname
        domain: xyz.com
        fb_url: 10.10.10.2
        api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


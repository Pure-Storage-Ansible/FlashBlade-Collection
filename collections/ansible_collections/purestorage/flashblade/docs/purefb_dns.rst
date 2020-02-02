
purefb_dns -- Configure Pure Storage FlashBlade DNS settings
============================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Set or erase DNS configuration for Pure Storage FlashBlades.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1



Parameters
----------

  search (optional, list, None)
    Ordered list of domain names to search


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  nameservers (optional, list, None)
    List of up to 3 unique DNS server IP addresses. These can be IPv4 or IPv6 - No validation is done of the addresses is performed.


  domain (optional, str, None)
    Domain suffix to be appended when perofrming DNS lookups.


  state (optional, str, present)
    Create or delete DNS servers configuration


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

    
    - name: Delete exisitng DNS settings
      purefb_dns:
        state: absent
        fa_url: 10.10.10.2
        api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
    
    - name: Set DNS settings
      purefb_dns:
        domain: purestorage.com
        nameservers:
          - 8.8.8.8
          - 8.8.4.4
        search:
          - purestorage.com
          - acme.com
        fa_url: 10.10.10.2
        api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


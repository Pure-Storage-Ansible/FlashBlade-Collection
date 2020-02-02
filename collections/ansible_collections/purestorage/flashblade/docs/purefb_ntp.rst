
purefb_ntp -- Configure Pure Storage FlashBlade NTP settings
============================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Set or erase NTP configuration for Pure Storage FlashBlades.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1



Parameters
----------

  ntp_servers (optional, list, None)
    A list of up to 4 alternate NTP servers. These may include IPv4, IPv6 or FQDNs. Invalid IP addresses will cause the module to fail. No validation is performed for FQDNs.

    If more than 4 servers are provided, only the first 4 unique nameservers will be used.

    if no servers are given a default of *0.pool.ntp.org* will be used.


  state (optional, str, present)
    Create or delete NTP servers configuration


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

    
    - name: Delete exisitng NTP server entries
      purefb_ntp:
        state: absent
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592
    
    - name: Set array NTP servers
      purefb_ntp:
        state: present
        ntp_servers:
          - "0.pool.ntp.org"
          - "1.pool.ntp.org"
          - "2.pool.ntp.org"
          - "3.pool.ntp.org"
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


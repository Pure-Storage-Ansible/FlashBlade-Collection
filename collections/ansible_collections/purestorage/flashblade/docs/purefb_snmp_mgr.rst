
purefb_snmp_mgr -- Configure FlashBlade SNMP Managers
=====================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Manage SNMP managers on a Pure Storage FlashBlade.

This module is not idempotent and will always modify an existing SNMP manager due to hidden parameters that cannot be compared to the play parameters.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1



Parameters
----------

  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  name (True, str, None)
    Name of SNMP Manager


  notification (optional, str, trap)
    Action to perform on event.


  state (optional, str, present)
    Create or delete SNMP manager


  community (optional, str, None)
    SNMP v2c only. Manager community ID. Between 1 and 32 characters long.


  privacy_protocol (optional, str, None)
    SNMP v3 only. Encryption protocol to use


  auth_protocol (optional, str, None)
    SNMP v3 only. Hash algorithm to use


  host (optional, str, None)
    IPv4 or IPv6 address or FQDN to send trap messages to.


  version (optional, str, None)
    Version of SNMP protocol to use for the manager.


  user (optional, str, None)
    SNMP v3 only. User ID recognized by the specified SNMP manager. Must be between 1 and 32 characters.


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  privacy_passphrase (optional, str, None)
    SNMPv3 only. Passphrase to encrypt SNMP messages. Must be between 8 and 63 non-space ASCII characters.


  auth_passphrase (optional, str, None)
    SNMPv3 only. Passphrase of 8 - 32 characters.





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Delete exisitng SNMP manager
      purefb_snmp_mgr:
        name: manager1
        state: absent
        fb_url: 10.10.10.2
        api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
    - name: Create v2c SNMP manager
      purefb_snmp_mgr:
        name: manager1
        community: public
        host: 10.21.22.23
        fb_url: 10.10.10.2
        api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
    - name: Create v3 SNMP manager
      purefb_snmp_mgr:
        name: manager2
        version: v3
        auth_protocol: MD5
        auth_passphrase: password
        host: 10.21.22.23
        fb_url: 10.10.10.2
        api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
    - name: Update existing SNMP manager
      purefb_snmp_mgr:
        name: manager1
        community: private
        fb_url: 10.10.10.2
        api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


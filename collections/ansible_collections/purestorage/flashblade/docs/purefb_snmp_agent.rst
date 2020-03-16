
purefb_snmp_agent -- Configure the FlashBlade SNMP Agent
========================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Configure the management SNMP Agent on a Pure Storage FlashBlade.

This module is not idempotent and will always modify the existing management SNMP agent due to hidden parameters that cannot be compared to the play parameters.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1



Parameters
----------

  auth_protocol (optional, str, None)
    SNMP v3 only. Hash algorithm to use


  version (optional, str, None)
    Version of SNMP protocol to use for the agent.


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  user (optional, str, None)
    SNMP v3 only. User ID recognized by the specified SNMP agent. Must be between 1 and 32 characters.


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  auth_passphrase (optional, str, None)
    SNMPv3 only. Passphrase of 8 - 32 characters.


  privacy_passphrase (optional, str, None)
    SNMPv3 only. Passphrase to encrypt SNMP messages. Must be between 8 and 63 non-space ASCII characters.


  community (optional, str, None)
    SNMP v2c only. Manager community ID. Between 1 and 32 characters long.


  privacy_protocol (optional, str, None)
    SNMP v3 only. Encryption protocol to use





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Update v2c SNMP agent
      purefb_snmp_agent:
        community: public
        fb_url: 10.10.10.2
        api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
    - name: Update v3 SNMP agent
      purefb_snmp_agent:
        version: v3
        auth_protocol: MD5
        auth_passphrase: password
        fb_url: 10.10.10.2
        api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


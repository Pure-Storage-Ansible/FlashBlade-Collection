
purefb_ds -- Configure FlashBlade Directory Service
===================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Create or erase directory services configurations. There is no facility to SSL certificates at this time. Use the FlashBlade GUI for this additional configuration work.

To modify an existing directory service configuration you must first delete an exisitng configuration and then recreate with new settings.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1
- netaddr
- pytz



Parameters
----------

  bind_user (optional, str, None)
    Sets the user name that can be used to bind to and query the directory.

    For Active Directory, enter the username - often referred to as sAMAccountName or User Logon Name - of the account that is used to perform directory lookups.

    For OpenLDAP, enter the full DN of the user.


  dstype (optional, str, None)
    The type of directory service to work on


  enable (optional, bool, False)
    Whether to enable or disable directory service support.


  join_ou (optional, str, None)
    The optional organizational unit (OU) where the machine account for the directory service will be created.


  nis_domain (optional, str, None)
    The NIS domain to search

    This cannot be used in conjunction with LDAP configurations.


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  uri (optional, list, None)
    A list of up to 30 URIs of the directory servers. Each URI must include the scheme ldap:// or ldaps:// (for LDAP over SSL), a hostname, and a domain name or IP address. For example, ldap://ad.company.com configures the directory service with the hostname "ad" in the domain "company.com" while specifying the unencrypted LDAP protocol.


  state (optional, str, present)
    Create or delete directory service configuration


  bind_password (optional, str, None)
    Sets the password of the bind_user user name account.


  base_dn (True, str, None)
    Sets the base of the Distinguished Name (DN) of the directory service groups. The base should consist of only Domain Components (DCs). The base_dn will populate with a default value when a URI is entered by parsing domain components from the URI. The base DN should specify DC= for each domain component and multiple DCs should be separated by commas.


  nis_servers (optional, list, None)
    A list of up to 30 IP addresses or FQDNs for NIS servers.

    This cannot be used in conjunction with LDAP configurations.


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Delete existing management directory service
      purefb_ds:
        dstype: management
        state: absent
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592
    
    - name: Create NFS directory service (disabled)
      purefb_ds:
        dstype: nfs
        uri: "ldaps://lab.purestorage.com"
        base_dn: "DC=lab,DC=purestorage,DC=com"
        bind_user: Administrator
        bind_password: password
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592
    
    - name: Enable existing SMB directory service
      purefb_ds:
        dstypr: smb
        enable: true
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592
    
    - name: Disable existing management directory service
      purefb_ds:
        dstype: management
        enable: false
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592
    
    - name: Create NFS directory service (enabled)
      purefb_ds:
        dstype: nfs
        enable: true
        uri: "ldaps://lab.purestorage.com"
        base_dn: "DC=lab,DC=purestorage,DC=com"
        bind_user: Administrator
        bind_password: password
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


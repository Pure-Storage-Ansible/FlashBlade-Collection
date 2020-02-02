
purefb_dsrole -- Configure FlashBlade  Management Directory Service Roles
=========================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Set or erase directory services role configurations.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1



Parameters
----------

  group_base (optional, str, None)
    Specifies where the configured group is located in the directory tree. This field consists of Organizational Units (OUs) that combine with the base DN attribute and the configured group CNs to complete the full Distinguished Name of the groups. The group base should specify OU= for each OU and multiple OUs should be separated by commas. The order of OUs is important and should get larger in scope from left to right.

    Each OU should not exceed 64 characters in length.


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  state (optional, str, present)
    Create or delete directory service role


  role (optional, str, None)
    The directory service role to work on


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  group (optional, str, None)
    Sets the common Name (CN) of the configured directory service group containing users for the FlashBlade. This name should be just the Common Name of the group without the CN= specifier.

    Common Names should not exceed 64 characters in length.





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Delete existing array_admin directory service role
      purefb_dsrole:
        role: array_admin
        state: absent
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592
    
    - name: Create array_admin directory service role
      purefb_dsrole:
        role: array_admin
        group_base: "OU=PureGroups,OU=SANManagers"
        group: pureadmins
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592
    
    - name: Update ops_admin directory service role
      purefb_dsrole:
        role: ops_admin
        group_base: "OU=PureGroups"
        group: opsgroup
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


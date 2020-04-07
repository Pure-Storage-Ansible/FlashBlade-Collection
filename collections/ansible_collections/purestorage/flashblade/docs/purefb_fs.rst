
purefb_fs -- Manage filesystemon Pure Storage FlashBlade`
=========================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

This module manages filesystems on Pure Storage FlashBlade.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1
- netaddr
- pytz



Parameters
----------

  size (False, str, 32G)
    Volume size in M, G, T or P units. See examples.


  smb (False, bool, False)
    Define whether to SMB protocol is enabled for the filesystem.


  nfs_rules (False, str, *(rw,no_root_squash))
    Define the NFS rules in operation.


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  http (False, bool, False)
    Define whether to HTTP/HTTPS protocol is enabled for the filesystem.


  name (True, str, None)
    Filesystem Name.


  nfsv4 (False, bool, True)
    Define whether to NFSv4.1 protocol is enabled for the filesystem.


  group_quota (False, str, None)
    Default quota in M, G, T or P units for a group under this file system.


  state (False, str, present)
    Create, delete or modifies a filesystem.


  snapshot (False, bool, False)
    Define whether a snapshot directory is enabled for the filesystem.


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  fastremove (False, bool, False)
    Define whether the fast remove directory is enabled for the filesystem.


  nfsv3 (False, bool, True)
    Define whether to NFSv3 protocol is enabled for the filesystem.


  hard_limit (False, bool, False)
    Define whether the capacity for a filesystem is a hard limit.

    CAUTION This will cause the filesystem to go Read-Only if the capacity has already exceeded the logical size of the filesystem.


  user_quota (False, str, None)
    Default quota in M, G, T or P units for a user under this file system.


  eradicate (False, bool, False)
    Define whether to eradicate the filesystem on delete or leave in trash.





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Create new filesystem named foo
      purefb_fs:
        name: foo
        size: 1T
        state: present
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Delete filesystem named foo
      purefb_fs:
        name: foo
        state: absent
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Recover filesystem named foo
      purefb_fs:
        name: foo
        state: present
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Eradicate filesystem named foo
      purefb_fs:
        name: foo
        state: absent
        eradicate: true
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Modify attributes of an existing filesystem named foo
      purefb_fs:
        name: foo
        size: 2T
        nfsv3 : false
        nfsv4 : true
        user_quota: 10K
        group_quota: 25M
        nfs_rules: '*(ro)'
        snapshot: true
        fastremove: true
        hard_limit: true
        smb: true
        state: present
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


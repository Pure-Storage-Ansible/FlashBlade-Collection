
purefb_fs_replica -- Manage filesystem replica links between Pure Storage FlashBlades
=====================================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

This module manages filesystem replica links between Pure Storage FlashBlades.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1
- netaddr
- pytz



Parameters
----------

  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  name (True, str, None)
    Local Filesystem Name.


  target_array (False, str, None)
    Remote array name to create replica on.


  state (False, str, present)
    Createx or modifies a filesystem.replica link


  target_fs (False, str, None)
    Name of target filesystem name

    If not supplied, will default to *name*.


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  policy (False, str, None)
    Name of filesystem snapshot policy to apply to the replica link.





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Create new filesystem replica from foo to bar on arrayB
      purefb_fs_replica:
          name: foo
        target_array: arrayB
        target_fs: bar
        policy: daily
        state: present
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Add new snapshot policy to exisitng filesystem repkica link
      purefb_fs_replica:
        name: foo
        policy: weekly
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Delete snapshot policy from filesystem replica foo
      purefb_fs_replica:
        name: foo
        policy: weekly
        state: absent
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


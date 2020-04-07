
purefb_snap -- Manage filesystem snapshots on Pure Storage FlashBlades
======================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Create or delete volumes and filesystem snapshots on Pure Storage FlashBlades.



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


  suffix (optional, str, None)
    Suffix of snapshot name.


  state (optional, str, present)
    Define whether the filesystem snapshot should exist or not.


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  eradicate (optional, bool, no)
    Define whether to eradicate the snapshot on delete or leave in trash.


  name (True, str, None)
    The name of the source filesystem.





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Create snapshot foo.ansible
      purefb_snap:
        name: foo
        suffix: ansible
        fb_url: 10.10.10.2
        fb_api_token: e31060a7-21fc-e277-6240-25983c6c4592
        state: present
    
    - name: Delete snapshot named foo.snap
      purefb_snap:
        name: foo
        suffix: snap
        fb_url: 10.10.10.2
        fb_api_token: e31060a7-21fc-e277-6240-25983c6c4592
        state: absent
    
    - name: Recover deleted snapshot foo.ansible
      purefb_snap:
        name: foo
        suffix: ansible
        fb_url: 10.10.10.2
        fb_api_token: e31060a7-21fc-e277-6240-25983c6c4592
        state: present
    
    - name: Eradicate snapshot named foo.snap
      purefb_snap:
        name: foo
        suffix: snap
        eradicate: true
        fb_url: 10.10.10.2
        fb_api_token: e31060a7-21fc-e277-6240-25983c6c4592
        state: absent




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


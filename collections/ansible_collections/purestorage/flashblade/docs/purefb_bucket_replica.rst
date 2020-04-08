
purefb_bucket_replica -- Manage bucket replica links between Pure Storage FlashBlades
=====================================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

This module manages bucket replica links between Pure Storage FlashBlades.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1
- netaddr
- pytz



Parameters
----------

  paused (optional, bool, False)
    State of the bucket replica link


  credential (False, str, None)
    Name of remote credential name to use.


  state (False, str, present)
    Creates or modifies a bucket replica link


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  name (True, str, None)
    Local Bucket Name.


  target_bucket (False, str, None)
    Name of target bucket name

    If not supplied, will default to *name*.


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  target (False, str, None)
    Remote array or target name to create replica on.





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Create new bucket replica from foo to bar on arrayB
      purefb_bucket_replica:
        name: foo
        target: arrayB
        target_bucket: bar
        credentials: cred_1
        state: present
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Pause exisitng bucket replica link
      purefb_bucket_replica:
        name: foo
        paused: true
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Delete bucket replica link foo
      purefb_fs_replica:
        name: foo
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



purefb_bucket -- Manage Object Store Buckets on a  Pure Storage FlashBlade.
===========================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

This module managess object store (s3) buckets on Pure Storage FlashBlade.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1



Parameters
----------

  account (True, str, None)
    Object Store Account for Bucket.


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  name (True, str, None)
    Bucket Name.


  state (False, str, present)
    Create, delete or modifies a bucket.


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  eradicate (False, bool, False)
    Define whether to eradicate the bucket on delete or leave in trash.





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Create new bucket named foo in account bar
      purefb_bucket:
        name: foo
        account: bar
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Delete bucket named foo in account bar
      purefb_bucket:
        name: foo
        account: bar
        state: absent
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Recover deleted bucket named foo in account bar
      purefb_bucket:
        name: foo
        account: bar
        state: present
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Eradicate bucket named foo in account bar
      purefb_bucket:
        name: foo
        account: bar
        state: absent
        eradicate: true
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>



purefb_s3user -- Create or delete FlashBlade Object Store account users
=======================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Create or delete object store account users on a Pure Stoage FlashBlade.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1
- netaddr
- pytz



Parameters
----------

  access_key (optional, bool, True)
    Create secret access key.

    Key can be exposed using the *debug* module


  account (optional, str, None)
    The name of object store account associated with user


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  name (optional, str, None)
    The name of object store user


  state (optional, str, present)
    Create or delete object store account user


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

    
    - name: Crrate object store user (with access ID and key) foo in account bar
      purefb_s3user:
        name: foo
        account: bar
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592
      register: result
    
    - debug:
        msg: "S3 User: {{ result['s3user_info'] }}"
    
    - name: Delete object store user foo in account bar
      purefb_s3user:
        name: foo
        account: bar
        state: absent
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


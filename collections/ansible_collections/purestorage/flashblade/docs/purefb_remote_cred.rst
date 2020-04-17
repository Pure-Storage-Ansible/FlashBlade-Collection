
purefb_remote_cred -- Create, modify and delete FlashBlade object store remote credentials
==========================================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Create, modify and delete object store remote credentials

You must have a correctly configured remote array or target

This module is **not** idempotent when updating existing remote credentials



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1
- netaddr
- pytz



Parameters
----------

  access_key (optional, str, None)
    Access Key ID of the S3 target


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  target (True, str, None)
    Define whether to initialize the S3 bucket


  secret (optional, str, None)
    Secret Access Key for the S3 or Azure target


  state (optional, str, present)
    Define state of remote credential


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  name (True, str, None)
    The name of the credential





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Create remote credential
      purefb_remote_cred:
        name: cred1
        access_key: "3794fb12c6204e19195f"
        secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        target: target1
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Delete remote credential
      purefb_remote_cred:
        name: cred1
        target: target1
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



purefb_bladename -- Configure Pure Storage FlashBlade name
==========================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Configure name of Pure Storage FlashBlades.

Ideal for Day 0 initial configuration.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1



Parameters
----------

  state (optional, str, present)
    Set the FlashBlade name


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  name (True, str, None)
    Name of the FlashBlade. Must conform to correct naming schema.


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

    
    - name: Set new FlashBlade name
      purefb_bladename:
        name: new-flashblade-name
        state: present
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


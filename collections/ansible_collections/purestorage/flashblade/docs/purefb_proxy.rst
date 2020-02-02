
purefb_proxy -- Configure FlashBlade phonehome HTTPs proxy settings
===================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Set or erase configuration for the HTTPS phonehome proxy settings.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1



Parameters
----------

  state (optional, str, present)
    Set or delete proxy configuration


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  host (optional, str, None)
    The proxy host name.


  port (optional, int, None)
    The proxy TCP/IP port number.





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Delete exisitng proxy settings
      purefb_proxy:
        state: absent
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592
    
    - name: Set proxy settings
      purefb_proxy:
        host: purestorage.com
        port: 8080
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


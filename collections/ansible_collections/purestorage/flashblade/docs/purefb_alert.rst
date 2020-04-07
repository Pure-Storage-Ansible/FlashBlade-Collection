
purefb_alert -- Configure Pure Storage FlashBlade alert email settings
======================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Configure alert email configuration for Pure Storage FlashArrays.

Add or delete an individual syslog server to the existing list of serves.



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


  severity (optional, str, info)
    The minimum severity that an alert must have in order for emails to be sent to the array's alert watchers


  address (True, str, None)
    Email address (valid format required)


  enabled (optional, bool, True)
    Set specified email address to be enabled or disabled


  state (optional, str, present)
    Create or delete alert email


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

    
    - name: Add new email recipient and enable, or enable existing email
      purefb_alert:
        address: "user@domain.com"
        enabled: true
        state: present
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592
    - name: Delete existing email recipient
      purefb_alert:
        state: absent
        address: "user@domain.com"
        fb_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Simon Dodsley (@sdodsley)


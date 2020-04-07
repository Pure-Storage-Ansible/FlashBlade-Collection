
purefb_inventory -- Collect information from Pure Storage FlashBlade
====================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Collect information from a Pure Storage FlashBlade running the Purity//FB operating system. By default, the module will collect basic information including hosts, host groups, protection groups and volume counts. Additional information can be collected based on the configured set of arguements.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1



Parameters
----------

  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


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

    
    - name: collect FlashBlade invenroty
      purefa_inventory:
        fa_url: 10.10.10.2
        api_token: e31060a7-21fc-e277-6240-25983c6c4592
    - name: show default information
      debug:
        msg: "{{ array_info['purefb_info'] }}"
    


Return Values
-------------

  purefb_inventory (always, complex, {'admins': {'pureuser': {'role': 'array_admin', 'type': 'local'}}, 'apps': {'offload': {'status': 'healthy', 'version': '5.2.1', 'description': 'Snapshot offload to NFS or Amazon S3'}}})
    Returns the inventory information for the FlashArray




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


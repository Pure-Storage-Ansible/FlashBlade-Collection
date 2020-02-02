
purefb_network -- Manage network interfaces in a Pure Storage FlashBlade
========================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

This module manages network interfaces on Pure Storage FlashBlade.

When creating a network interface a subnet must already exist with a network prefix that covers the IP address of the interface being created.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 2.7
- purity_fb >= 1.1



Parameters
----------

  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  name (True, str, None)
    Interface Name.


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  state (False, str, present)
    Create, delete or modifies a network interface.


  address (False, str, None)
    IP address of interface.


  services (False, str, data)
    Define which services are configured for the interfaces.


  itype (False, str, vip)
    Type of interface.





Notes
-----

.. note::
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Create new network interface named foo
      purefb_network:
        name: foo
        address: 10.21.200.23
        state: present
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Change IP address of network interface named foo
      purefb_network:
        name: foo
        state: present
        address: 10.21.200.123
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Delete network interface named foo
      purefb_network:
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

- P
- u
- r
- e
-  
- S
- t
- o
- r
- a
- g
- e
-  
- A
- n
- s
- i
- b
- l
- e
-  
- T
- e
- a
- m
-  
- (
- @
- s
- d
- o
- d
- s
- l
- e
- y
- )
-  
- <
- p
- u
- r
- e
- -
- a
- n
- s
- i
- b
- l
- e
- -
- t
- e
- a
- m
- @
- p
- u
- r
- e
- s
- t
- o
- r
- a
- g
- e
- .
- c
- o
- m
- >



purefb_subnet -- Manage network subnets in a Pure Storage FlashBlade
====================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

This module manages network subnets on Pure Storage FlashBlade.



Requirements
------------
The below requirements are needed on the host that executes this module.

- netaddr
- purity_fb >= 1.1
- python >= 2.7
- pytz



Parameters
----------

  state (False, str, present)
    Create, delete or modifies a subnet.


  gateway (False, str, None)
    IPv4 or IPv6 address of subnet gateway.


  name (True, str, None)
    Subnet Name.


  api_token (optional, str, None)
    FlashBlade API token for admin privileged user.


  fb_url (optional, str, None)
    FlashBlade management IP address or Hostname.


  vlan (False, int, 0)
    VLAN ID of the subnet.


  prefix (False, str, None)
    IPv4 or IPv6 address associated with the subnet.

    Supply the prefix length (CIDR) as well as the IP address.


  mtu (False, int, 1500)
    MTU size of the subnet. Range is 1280 to 9216.





Notes
-----

.. note::
   - Requires the netaddr Python package on the host.
   - This module requires the ``purity_fb`` Python library
   - You must set ``PUREFB_URL`` and ``PUREFB_API`` environment variables if *fb_url* and *api_token* arguments are not passed to the module directly




Examples
--------

.. code-block:: yaml+jinja

    
    - name: Create new network subnet named foo
      purefb_subnet:
        name: foo
        prefix: "10.21.200.3/24"
        gateway: 10.21.200.1
        mtu: 9000
        vlan: 2200
        state: present
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Change configuration of existing subnet foo
      purefb_network:
        name: foo
        state: present
        prefix: "10.21.100.3/24"
        gateway: 10.21.100.1
        mtu: 1500
        address: 10.21.200.123
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
    
    - name: Delete network subnet named foo
      purefb_subnet:
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


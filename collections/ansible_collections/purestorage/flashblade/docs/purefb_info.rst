
purefb_info -- Collect information from Pure Storage FlashBlade
===============================================================

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
- netaddr
- pytz



Parameters
----------

  gather_subset (False, list, minimum)
    When supplied, this argument will define the information to be collected. Possible values for this include all, minimum, config, performance, capacity, network, subnets, lags, filesystems, snapshots, buckets, replication, policies and arrays.


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

    
    - name: collect default set of info
      purefb_info:
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
      register: blade_info
    - name: show default information
      debug:
        msg: "{{ blade_info['purefb_info']['default'] }}"
    
    - name: collect configuration and capacity info
      purefb_info:
        gather_subset:
          - config
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
      register: blade_info
    - name: show config information
      debug:
        msg: "{{ blade_info['purefb_info']['config'] }}"
    
    - name: collect all info
      purefb_info:
        gather_subset:
          - all
        fb_url: 10.10.10.2
        api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
      register: blade_info
    - name: show all information
      debug:
        msg: "{{ blade_info['purefb_info'] }}"


Return Values
-------------

  purefb_info (always, complex, {'subnet': {'new-mgmt': {'prefix': '10.10.100.0/24', 'lag': 'uplink', 'services': ['data', 'management', 'support'], 'interfaces': [{'name': 'fm1.admin0'}, {'name': 'fm2.admin0'}, {'name': 'nfs1'}, {'name': 'vir0'}], 'vlan': 2200, 'gateway': '10.10.100.1', 'mtu': 1500}}, 'capacity': {'aggregate': {'data_reduction': 1.1179228, 'total_physical': 17519748439, 'unique': 17519748439, 'snapshots': 0, 'virtual': 19585726464}, 'object-store': {'data_reduction': 1.0263462, 'total_physical': 12771528731, 'unique': 12771528731, 'snapshots': 0, 'virtual': 6477716992}, 'file-system': {'data_reduction': 1.3642412, 'total_physical': 4748219708, 'unique': 4748219708, 'snapshots': 0, 'virtual': 6477716992}, 'total': 83359896948925}, 'network': {'nfs1': {'netmask': '255.255.255.0', 'address': '10.10.100.4', 'services': ['data'], 'vlan': 2200, 'type': 'vip', 'gateway': '10.10.100.1', 'mtu': 1500}, 'fm2.admin0': {'netmask': '255.255.255.0', 'address': '10.10.100.7', 'services': ['support'], 'vlan': 2200, 'type': 'vip', 'gateway': '10.10.100.1', 'mtu': 1500}, 'vir0': {'netmask': '255.255.255.0', 'address': '10.10.100.5', 'services': ['management'], 'vlan': 2200, 'type': 'vip', 'gateway': '10.10.100.1', 'mtu': 1500}, 'fm1.admin0': {'netmask': '255.255.255.0', 'address': '10.10.100.6', 'services': ['support'], 'vlan': 2200, 'type': 'vip', 'gateway': '10.10.100.1', 'mtu': 1500}}, 'default': {'object_store_users': 1, 'total_capacity': 83359896948925, 'buckets': 7, 'object_store_accounts': 1, 'snapshots': 1, 'filesystems': 2, 'flashblade_name': 'demo-fb-1', 'purity_version': '2.2.0', 'blades': 15}, 'lag': {'uplink': {'status': 'healthy', 'lag_speed': 0, 'ports': [{'name': 'CH1.FM1.ETH1.1'}, {'name': 'CH1.FM1.ETH1.2'}], 'port_speed': 40000000000}}, 'snapshots': {'z.188': {'destroyed': False, 'source': 'z', 'source_destroyed': False, 'suffix': '188'}}, 'filesystems': {'k8s-pvc-d24b1357-579e-11e8-811f-ecf4bbc88f54': {'destroyed': False, 'provisioned': 21474836480, 'nfs_rules': '10.21.255.0/24(rw,no_root_squash)', 'fast_remove': False, 'hard_limit': True, 'snapshot_enabled': False}, 'z': {'destroyed': False, 'provisioned': 1073741824, 'fast_remove': False, 'hard_limit': False, 'snapshot_enabled': False}}, 'performance': {'aggregate': {'write_bytes_per_sec': 0, 'writes_per_sec': 0, 'bytes_per_read': 0, 'usec_per_write_op': 0, 'read_bytes_per_sec': 0, 'bytes_per_op': 0, 'reads_per_sec': 0, 'usec_per_other_op': 0, 'usec_per_read_op': 0, 'bytes_per_write': 0}, 's3': {'write_bytes_per_sec': 0, 'writes_per_sec': 0, 'bytes_per_read': 0, 'usec_per_write_op': 0, 'read_bytes_per_sec': 0, 'bytes_per_op': 0, 'reads_per_sec': 0, 'usec_per_other_op': 0, 'usec_per_read_op': 0, 'bytes_per_write': 0}, 'nfs': {'write_bytes_per_sec': 0, 'writes_per_sec': 0, 'bytes_per_read': 0, 'usec_per_write_op': 0, 'read_bytes_per_sec': 0, 'bytes_per_op': 0, 'reads_per_sec': 0, 'usec_per_other_op': 0, 'usec_per_read_op': 0, 'bytes_per_write': 0}, 'http': {'write_bytes_per_sec': 0, 'writes_per_sec': 0, 'bytes_per_read': 0, 'usec_per_write_op': 0, 'read_bytes_per_sec': 0, 'bytes_per_op': 0, 'reads_per_sec': 0, 'usec_per_other_op': 0, 'usec_per_read_op': 0, 'bytes_per_write': 0}}, 'config': {'smb_directory_service': {'bind_user': None, 'name': 'smb', 'bind_password': None, 'base_dn': None, 'services': ['smb'], 'enabled': False, 'uris': []}, 'alert_watchers': {'enabled': True, 'name': 'notify@acmestorage.com'}, 'ntp': ['0.ntp.pool.org'], 'smtp': {'name': 'demo-fb-1', 'relay_host': None, 'sender_domain': 'acmestorage.com'}, 'array_management': {'bind_user': None, 'name': 'management', 'bind_password': None, 'base_dn': None, 'services': ['management'], 'enabled': False, 'uris': []}, 'nfs_directory_service': {'bind_user': None, 'name': 'nfs', 'bind_password': None, 'base_dn': None, 'services': ['nfs'], 'enabled': False, 'uris': []}, 'dns': {'nameservers': ['8.8.8.8'], 'search': ['demo.acmestorage.com'], 'domain': 'demo.acmestorage.com', 'name': 'demo-fb-1'}, 'ssl_certs': {'issued_to': 'Acme Storage', 'status': 'self-signed', 'private_key': None, 'intermediate_certificate': None, 'passphrase': None, 'common_name': 'Acme Storage', 'valid_from': '1508433967000', 'name': 'global', 'certificate': '-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----', 'locality': None, 'country': 'US', 'issued_by': 'Acme Storage', 'valid_to': '2458833967000', 'state': None, 'key_size': 4096, 'organizational_unit': 'Acme Storage', 'organization': 'Acme Storage', 'email': None}, 'directory_service_roles': {'ops_admin': {'group_base': None, 'group': None}, 'readonly': {'group_base': None, 'group': None}, 'array_admin': {'group_base': None, 'group': None}, 'storage_admin': {'group_base': None, 'group': None}}}})
    Returns the information collected from the FlashBlade




Status
------




- This  is not guaranteed to have a backwards compatible interface. *[preview]*


- This  is maintained by community.



Authors
~~~~~~~

- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>


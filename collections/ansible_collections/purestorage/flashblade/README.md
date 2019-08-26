# Pure Storage FlashBlade Collection

The Pure Storage FlashBlade collection consists of the latest versions of the FlashBlade modules.

## Modules

- purefb_bucket - manage S3 buckets on a FlashBlade
- purefb_ds - manage Directory Services settings on a FlashBlade
- purefb_dsrole - manage Directory Service Roles on a FlashBlade
- purefb_fs - manage filesystems on a FlashBlade
- purefb_info - get information about the configuration of a FlashBlade
- purefb_network - manage the network settings for a FlashBlade
- purefb_ra - manage the Remote Assist connections on a FlashBlade
- purefb_s3acc - manage the object store accounts on a FlashBlade
- purefb_s3user - manage the object atore users on a FlashBlade
- purefb_smtp - manage SMTP settings on a FlashBlade
- purefb_snap - manage filesystem snapshots on a FlashBlade
- purefb_subnet - manage network subnets on a FlashBlade

## Requirements

- Ansible 2.9 or later
- Pure Storage FlashBlade system running Purity 2.1.2  or later
- purity_fb Python SDK

## Instructions

Instll the Pure Storage FlashBlade collection on your Ansible management host.

- Using ansible-galaxy (Ansible 2.9 or later):
`ansible-galaxy install purestorage.flashblade`

## Example Playbook
```yaml
- hosts: localhost
  gather_facts: true
  collection:
    - puestorage.flashblade
  tasks:
    - name: Get FlashBlade information
      purefb_info:
    
```

## License

[BSD-2-Clause](https://directory.fsf.org/wiki?title=License:FreeBSD)

## Author

This collection was created in 2019 by [Simon Dodsley](@sdodsley) for, and on behalf of, the [Pure Storage Ansible Team](pure-ansible-team@purestorage.com)

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

Install the Pure Storage FlashBlade collection on your Ansible management host.

- Using ansible-galaxy (Ansible 2.9 or later):
```
<<<<<<< HEAD
ansible-galaxy collection install purestorage.flashblade -p ~/.ansible/collections
=======
ansible-galaxy install purestorage.flashblade
>>>>>>> db4fddc85b63b47c09a0d207147a9da9170c19d0
```

## Example Playbook
```yaml
- hosts: localhost
  gather_facts: true
  collections:
    - puestorage.flashblade
  tasks:
    - name: Get FlashBlade information
      purefb_info:
        fb_url: 10.0.0.12
        api_token: "T-9f276a18-50ab-446e-8a0c-666a3529a1b6"

    - name: Create test filesystem
      purefb_fs:
        name: test_filesystem
        fb_url : 10.21.200.12
        api_token: "T-9f276a18-50ab-446e-8a0c-666a3529a1b6"
        size: 1T
        nfs: True
        nfsv4: True
        user_quota: 10k
        group_quota: 10T
        hard_limit: true
        nfs_rules: '10.10.28.78/32(rw,no_root_squash)'
        snapshot: True

    - name: Create test snapshot
      purefb_snap:
        name: test_filesystem
        state: present
        suffix: snap-name
```

## License

[BSD-2-Clause](https://directory.fsf.org/wiki?title=License:FreeBSD)

## Author

This collection was created in 2019 by [Simon Dodsley](@sdodsley) for, and on behalf of, the [Pure Storage Ansible Team](pure-ansible-team@purestorage.com)

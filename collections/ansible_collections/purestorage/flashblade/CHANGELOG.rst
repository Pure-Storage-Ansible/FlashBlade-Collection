====================================
Purestorage.Flashblade Release Notes
====================================

.. contents:: Topics


v1.4.0
======

Minor Changes
-------------

- purefb_banner - Module to manage the GUI and SSH login message
- purefb_certgrp - Module to manage FlashBlade Certificate Groups
- purefb_certs - Module to create and delete SSL certificates
- purefb_connect - Support idempotency when exisitng connection is incoming
- purefb_fs - Add new options for filesystem control (https://github.com/Pure-Storage-Ansible/FlashBlade-Collection/pull/81)
- purefb_fs - Default filesystem size on creation changes from 32G to ``unlimited``
- purefb_fs - Fix error in deletion and eradication of filesystem
- purefb_fs_replica - Remove condition to attach/detach policies on unhealthy replica-link
- purefb_info - Add support to list filesystem policies
- purefb_lifecycle - Module to manage FlashBlade Bucket Lifecycle Rules
- purefb_s3user - Add support for imported user access keys
- purefb_syslog - Module to manage syslog server configuration

Bugfixes
--------

- purefa_policy - Resolve multiple issues related to incorrect use of timezones
- purefb_connect - Ensure changing encryption status on array connection is performed correctly
- purefb_connect - Fix breaking change created in purity_fb SDK 1.9.2 for deletion of array connections
- purefb_connect - Hide target array API token
- purefb_ds - Ensure updating directory service configurations completes correctly
- purefb_info - Fix issue getting array info when encrypted connection exists

New Modules
-----------

- purestorage.flashblade.purefb_banner - Configure Pure Storage FlashBlade GUI and SSH MOTD message
- purestorage.flashblade.purefb_certgrp - Manage FlashBlade Certifcate Groups
- purestorage.flashblade.purefb_certs - Manage FlashBlade SSL Certifcates
- purestorage.flashblade.purefb_lifecycle - Manage FlashBlade object lifecycles
- purestorage.flashblade.purefb_syslog - Configure Pure Storage FlashBlade syslog settings

v1.3.0
======

Release Summary
---------------

| Release Date: 2020-08-08
| This changlelog describes all changes made to the modules and plugins included in this collection since Ansible 2.9.0


Major Changes
-------------

- purefb_alert - manage alert email settings on a FlashBlade
- purefb_bladename - manage FlashBlade name
- purefb_bucket_replica - manage bucket replica links on a FlashBlade
- purefb_connect - manage connections between FlashBlades
- purefb_dns - manage DNS settings on a FlashBlade
- purefb_fs_replica - manage filesystem replica links on a FlashBlade
- purefb_inventory - get information about the hardware inventory of a FlashBlade
- purefb_ntp - manage the NTP settings for a FlashBlade
- purefb_phonehome - manage the phone home settings for a FlashBlade
- purefb_policy - manage the filesystem snapshot policies for a FlashBlade
- purefb_proxy - manage the phone home HTTP proxy settings for a FlashBlade
- purefb_remote_cred - manage the Object Store Remote Credentials on a FlashBlade
- purefb_snmp_agent - modify the FlashBlade SNMP Agent
- purefb_snmp_mgr - manage SNMP Managers on a FlashBlade
- purefb_target - manage remote S3-capable targets for a FlashBlade
- purefb_user - manage local ``pureuser`` account password on a FlashBlade

Minor Changes
-------------

- purefb_bucket - Versioning support added
- purefb_info - new options added for information collection
- purefb_network - Add replication service type
- purefb_s3user - Limit ``access_key`` recreation to 3 times
- purefb_s3user - return dict changed from ``ansible_facts`` to ``s3user_info``

Bugfixes
--------

- purefb_bucket - Add warning message if ``state`` is ``absent`` without ``eradicate:``
- purefb_fs - Add graceful exist when ``state`` is ``absent`` and filesystem not eradicated
- purefb_fs - Add warning message if ``state`` is ``absent`` without ``eradicate``

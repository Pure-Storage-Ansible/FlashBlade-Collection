# Copyright: (c) 2026, Pure Storage Ansible Team <pure-ansible-team@purestorage.com>
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for purefb_info module."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import sys
from unittest.mock import Mock, patch, MagicMock

# Mock external dependencies before importing module
sys.modules["pypureclient"] = MagicMock()
sys.modules["pypureclient.flashblade"] = MagicMock()
sys.modules["urllib3"] = MagicMock()
sys.modules["distro"] = MagicMock()

from plugins.modules.purefb_info import (
    main,
    generate_default_dict,
    generate_perf_dict,
    generate_config_dict,
)


class TestPurefbInfo:
    """Test cases for purefb_info module"""

    @patch("plugins.modules.purefb_info.generate_default_dict")
    @patch("plugins.modules.purefb_info.get_system")
    @patch("plugins.modules.purefb_info.AnsibleModule")
    def test_main_minimum_subset(
        self, mock_ansible_module, mock_get_system, mock_generate_default
    ):
        """Test main with minimum subset (default)"""
        # Setup mocks
        mock_module = Mock()
        mock_module.params = {"gather_subset": ["minimum"]}
        mock_module.check_mode = False
        mock_ansible_module.return_value = mock_module

        mock_blade = Mock()
        mock_version = Mock()
        mock_version.version = "2.0.0"
        mock_blade.get_versions.return_value.items = [mock_version]
        mock_get_system.return_value = mock_blade

        mock_default_info = {"array_name": "test-array"}
        mock_generate_default.return_value = mock_default_info

        # Call main
        main()

        # Verify
        mock_generate_default.assert_called_once_with(mock_blade)
        mock_module.exit_json.assert_called_once()
        call_args = mock_module.exit_json.call_args[1]
        assert call_args["changed"] is False
        assert "purefb_info" in call_args
        assert "default" in call_args["purefb_info"]
        assert call_args["purefb_info"]["default"] == mock_default_info

    @patch("plugins.modules.purefb_info.generate_default_dict")
    @patch("plugins.modules.purefb_info.get_system")
    @patch("plugins.modules.purefb_info.AnsibleModule")
    def test_main_default_subset_when_none(
        self, mock_ansible_module, mock_get_system, mock_generate_default
    ):
        """Test main defaults to minimum when gather_subset is None"""
        # Setup mocks
        mock_module = Mock()
        mock_module.params = {"gather_subset": None}
        mock_module.check_mode = False
        mock_ansible_module.return_value = mock_module

        mock_blade = Mock()
        mock_version = Mock()
        mock_version.version = "2.0.0"
        mock_blade.get_versions.return_value.items = [mock_version]
        mock_get_system.return_value = mock_blade

        mock_default_info = {"array_name": "test-array"}
        mock_generate_default.return_value = mock_default_info

        # Call main
        main()

        # Verify - should default to minimum
        assert mock_module.params["gather_subset"] == ["minimum"]
        mock_generate_default.assert_called_once_with(mock_blade)
        mock_module.exit_json.assert_called_once()

    @patch("plugins.modules.purefb_info.get_system")
    @patch("plugins.modules.purefb_info.AnsibleModule")
    def test_main_invalid_subset(self, mock_ansible_module, mock_get_system):
        """Test main with invalid gather_subset"""
        # Setup mocks
        mock_module = Mock()
        mock_module.params = {"gather_subset": ["invalid_subset"]}
        mock_module.check_mode = False
        mock_ansible_module.return_value = mock_module

        mock_blade = Mock()
        mock_version = Mock()
        mock_version.version = "2.0.0"
        mock_blade.get_versions.return_value.items = [mock_version]
        mock_get_system.return_value = mock_blade

        # Call main
        main()

        # Verify - should fail with invalid subset message
        mock_module.fail_json.assert_called_once()
        call_args = mock_module.fail_json.call_args[1]
        assert "gather_subset must be one or more of" in call_args["msg"]
        assert "invalid_subset" in call_args["msg"]

    @patch("plugins.modules.purefb_info.generate_perf_dict")
    @patch("plugins.modules.purefb_info.generate_default_dict")
    @patch("plugins.modules.purefb_info.get_system")
    @patch("plugins.modules.purefb_info.AnsibleModule")
    def test_main_performance_subset(
        self,
        mock_ansible_module,
        mock_get_system,
        mock_generate_default,
        mock_generate_perf,
    ):
        """Test main with performance subset"""
        # Setup mocks
        mock_module = Mock()
        mock_module.params = {"gather_subset": ["performance"]}
        mock_module.check_mode = False
        mock_ansible_module.return_value = mock_module

        mock_blade = Mock()
        mock_version = Mock()
        mock_version.version = "2.0.0"
        mock_blade.get_versions.return_value.items = [mock_version]
        mock_get_system.return_value = mock_blade

        mock_perf_info = {"read_bandwidth": 1000}
        mock_generate_perf.return_value = mock_perf_info

        # Call main
        main()

        # Verify
        mock_generate_perf.assert_called_once_with(mock_blade)
        mock_module.exit_json.assert_called_once()
        call_args = mock_module.exit_json.call_args[1]
        assert "performance" in call_args["purefb_info"]
        assert call_args["purefb_info"]["performance"] == mock_perf_info

    @patch("plugins.modules.purefb_info.generate_config_dict")
    @patch("plugins.modules.purefb_info.generate_capacity_dict")
    @patch("plugins.modules.purefb_info.generate_network_dict")
    @patch("plugins.modules.purefb_info.generate_default_dict")
    @patch("plugins.modules.purefb_info.get_system")
    @patch("plugins.modules.purefb_info.AnsibleModule")
    def test_main_multiple_subsets(
        self,
        mock_ansible_module,
        mock_get_system,
        mock_generate_default,
        mock_generate_network,
        mock_generate_capacity,
        mock_generate_config,
    ):
        """Test main with multiple subsets"""
        # Setup mocks
        mock_module = Mock()
        mock_module.params = {"gather_subset": ["config", "capacity", "network"]}
        mock_module.check_mode = False
        mock_ansible_module.return_value = mock_module

        mock_blade = Mock()
        mock_version = Mock()
        mock_version.version = "2.0.0"
        mock_blade.get_versions.return_value.items = [mock_version]
        mock_get_system.return_value = mock_blade

        mock_config_info = {"dns": {}}
        mock_capacity_info = {"total": 1000}
        mock_network_info = {"eth0": {}}
        mock_generate_config.return_value = mock_config_info
        mock_generate_capacity.return_value = mock_capacity_info
        mock_generate_network.return_value = mock_network_info

        # Call main
        main()

        # Verify all three generators were called
        mock_generate_config.assert_called_once_with(mock_blade)
        mock_generate_capacity.assert_called_once_with(mock_blade)
        mock_generate_network.assert_called_once_with(mock_blade)
        mock_module.exit_json.assert_called_once()
        call_args = mock_module.exit_json.call_args[1]
        assert "config" in call_args["purefb_info"]
        assert "capacity" in call_args["purefb_info"]
        assert "network" in call_args["purefb_info"]

    @patch("plugins.modules.purefb_info.generate_perf_dict")
    @patch("plugins.modules.purefb_info.generate_config_dict")
    @patch("plugins.modules.purefb_info.generate_capacity_dict")
    @patch("plugins.modules.purefb_info.generate_network_dict")
    @patch("plugins.modules.purefb_info.generate_subnet_dict")
    @patch("plugins.modules.purefb_info.generate_lag_dict")
    @patch("plugins.modules.purefb_info.generate_fs_dict")
    @patch("plugins.modules.purefb_info.generate_admin_dict")
    @patch("plugins.modules.purefb_info.generate_snap_dict")
    @patch("plugins.modules.purefb_info.generate_bucket_dict")
    @patch("plugins.modules.purefb_info.generate_policies_dict")
    @patch("plugins.modules.purefb_info.generate_array_conn_dict")
    @patch("plugins.modules.purefb_info.generate_file_repl_dict")
    @patch("plugins.modules.purefb_info.generate_bucket_repl_dict")
    @patch("plugins.modules.purefb_info.generate_snap_transfer_dict")
    @patch("plugins.modules.purefb_info.generate_remote_creds_dict")
    @patch("plugins.modules.purefb_info.generate_targets_dict")
    @patch("plugins.modules.purefb_info.generate_object_store_accounts_dict")
    @patch("plugins.modules.purefb_info.generate_ad_dict")
    @patch("plugins.modules.purefb_info.generate_kerb_dict")
    @patch("plugins.modules.purefb_info.generate_object_store_access_policies_dict")
    @patch("plugins.modules.purefb_info.generate_nfs_export_policies_dict")
    @patch("plugins.modules.purefb_info.generate_default_dict")
    @patch("plugins.modules.purefb_info.get_system")
    @patch("plugins.modules.purefb_info.AnsibleModule")
    def test_main_all_subset(
        self,
        mock_ansible_module,
        mock_get_system,
        mock_generate_default,
        mock_generate_nfs_export,
        mock_generate_access_policies,
        mock_generate_kerb,
        mock_generate_ad,
        mock_generate_accounts,
        mock_generate_targets,
        mock_generate_remote_creds,
        mock_generate_snap_transfer,
        mock_generate_bucket_repl,
        mock_generate_file_repl,
        mock_generate_array_conn,
        mock_generate_policies,
        mock_generate_bucket,
        mock_generate_snap,
        mock_generate_admin,
        mock_generate_fs,
        mock_generate_lag,
        mock_generate_subnet,
        mock_generate_network,
        mock_generate_capacity,
        mock_generate_config,
        mock_generate_perf,
    ):
        """Test main with 'all' subset"""
        # Setup mocks
        mock_module = Mock()
        mock_module.params = {"gather_subset": ["all"]}
        mock_module.check_mode = False
        mock_ansible_module.return_value = mock_module

        mock_blade = Mock()
        mock_version = Mock()
        mock_version.version = "2.0.0"
        mock_blade.get_versions.return_value.items = [mock_version]
        mock_get_system.return_value = mock_blade

        # Set return values for all generators
        mock_generate_default.return_value = {}
        mock_generate_perf.return_value = {}
        mock_generate_config.return_value = {}
        mock_generate_capacity.return_value = {}
        mock_generate_network.return_value = {}
        mock_generate_subnet.return_value = {}
        mock_generate_lag.return_value = {}
        mock_generate_fs.return_value = {}
        mock_generate_admin.return_value = {}
        mock_generate_snap.return_value = {}
        mock_generate_bucket.return_value = {}
        mock_generate_policies.return_value = {}
        mock_generate_array_conn.return_value = {}
        mock_generate_file_repl.return_value = {}
        mock_generate_bucket_repl.return_value = {}
        mock_generate_snap_transfer.return_value = {}
        mock_generate_remote_creds.return_value = {}
        mock_generate_targets.return_value = {}
        mock_generate_accounts.return_value = {}
        mock_generate_ad.return_value = {}
        mock_generate_kerb.return_value = {}
        mock_generate_access_policies.return_value = {}
        mock_generate_nfs_export.return_value = {}

        # Call main
        main()

        # Verify all generators were called
        mock_generate_default.assert_called_once()
        mock_generate_perf.assert_called_once()
        mock_generate_config.assert_called_once()
        mock_generate_capacity.assert_called_once()
        mock_generate_network.assert_called_once()
        mock_generate_subnet.assert_called_once()
        mock_generate_lag.assert_called_once()
        mock_generate_fs.assert_called_once()
        mock_generate_admin.assert_called_once()
        mock_generate_snap.assert_called_once()
        mock_generate_bucket.assert_called_once()
        mock_generate_policies.assert_called()  # Called multiple times
        mock_generate_array_conn.assert_called_once()
        mock_module.exit_json.assert_called_once()
        call_args = mock_module.exit_json.call_args[1]
        assert call_args["changed"] is False
        assert "purefb_info" in call_args

    def test_generate_default_dict(self):
        """Test generate_default_dict function"""
        # Setup mock blade
        mock_blade = Mock()

        # Mock API version
        mock_version = Mock()
        mock_version.version = "2.0.0"
        mock_blade.get_versions.return_value.items = [mock_version]

        # Mock array info
        mock_array = Mock()
        mock_array.name = "test-array"
        mock_array.id = "12345"
        mock_array.os = "Purity//FB"
        mock_array.version = "3.0.0"
        mock_blade.get_arrays.return_value.items = [mock_array]

        # Mock counts
        mock_blade.get_buckets.return_value.total_item_count = 5
        mock_blade.get_file_systems.return_value.total_item_count = 10
        mock_blade.get_file_system_snapshots.return_value.total_item_count = 20

        # Call function
        result = generate_default_dict(mock_blade)

        # Verify
        assert "flashblade_name" in result
        assert result["flashblade_name"] == "test-array"
        assert "purity_version" in result
        assert result["purity_version"] == "3.0.0"
        assert "bucket_count" in result
        assert result["bucket_count"] == 5
        assert "filesystem_count" in result
        assert result["filesystem_count"] == 10
        assert "snapshot_count" in result
        assert result["snapshot_count"] == 20

    def test_generate_perf_dict(self):
        """Test generate_perf_dict function"""
        # Setup mock blade
        mock_blade = Mock()

        # Mock performance data
        mock_total_perf = Mock()
        mock_total_perf.bytes_per_op = 4096
        mock_total_perf.bytes_per_read = 8192
        mock_total_perf.bytes_per_write = 4096
        mock_total_perf.read_bytes_per_sec = 1000000
        mock_total_perf.write_bytes_per_sec = 500000

        mock_http_perf = Mock()
        mock_http_perf.read_bytes_per_sec = 100000
        mock_http_perf.write_bytes_per_sec = 50000

        mock_s3_perf = Mock()
        mock_s3_perf.read_bytes_per_sec = 200000
        mock_s3_perf.write_bytes_per_sec = 100000

        mock_nfs_perf = Mock()
        mock_nfs_perf.read_bytes_per_sec = 300000
        mock_nfs_perf.write_bytes_per_sec = 150000

        mock_smb_perf = Mock()
        mock_smb_perf.read_bytes_per_sec = 400000
        mock_smb_perf.write_bytes_per_sec = 200000

        # Setup return values for different protocol queries
        def get_perf_side_effect(protocol=None):
            mock_result = Mock()
            if protocol == "http":
                mock_result.items = [mock_http_perf]
            elif protocol == "s3":
                mock_result.items = [mock_s3_perf]
            elif protocol == "nfs":
                mock_result.items = [mock_nfs_perf]
            elif protocol == "smb":
                mock_result.items = [mock_smb_perf]
            else:
                mock_result.items = [mock_total_perf]
            return mock_result

        mock_blade.get_arrays_performance.side_effect = get_perf_side_effect

        # Call function
        result = generate_perf_dict(mock_blade)

        # Verify
        assert "total" in result
        assert "http" in result
        assert "s3" in result
        assert "nfs" in result
        assert result["total"]["read_bytes_per_sec"] == 1000000
        assert result["http"]["read_bytes_per_sec"] == 100000
        assert result["s3"]["read_bytes_per_sec"] == 200000
        assert result["nfs"]["read_bytes_per_sec"] == 300000

    def test_generate_config_dict(self):
        """Test generate_config_dict function"""
        # Setup mock blade
        mock_blade = Mock()

        # Mock API version
        mock_version = Mock()
        mock_version.version = "2.0.0"
        mock_blade.get_versions.return_value.items = [mock_version]

        # Mock DNS
        mock_dns = Mock()
        mock_dns.domain = "example.com"
        mock_dns.nameservers = ["8.8.8.8", "8.8.4.4"]
        mock_blade.get_dns.return_value.items = [mock_dns]

        # Mock NTP
        mock_blade.get_ntp_servers.return_value.items = []

        # Mock SMTP
        mock_blade.get_smtp_servers.return_value.items = []

        # Mock SSL certs
        mock_blade.get_certificates.return_value.items = []

        # Mock SNMP managers
        mock_blade.get_snmp_managers.return_value.items = []

        # Mock directory services
        mock_blade.get_directory_services.return_value.items = []

        # Mock alerts
        mock_blade.get_alerts.return_value.items = []

        # Mock array connections
        mock_blade.get_array_connections.return_value.items = []

        # Call function
        result = generate_config_dict(mock_blade)

        # Verify
        assert "dns" in result
        assert result["dns"]["domain"] == "example.com"
        assert result["dns"]["nameservers"] == ["8.8.8.8", "8.8.4.4"]



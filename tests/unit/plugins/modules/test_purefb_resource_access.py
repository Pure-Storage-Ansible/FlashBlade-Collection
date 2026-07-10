# Copyright: (c) 2026, Pure Storage Ansible Team <pure-ansible-team@everpuredata.com>
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for purefb_realm module."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import sys
import multiprocessing
import ctypes
from unittest.mock import Mock, patch, MagicMock

# Mock multiprocessing context for Windows
if sys.platform == "win32":
    original_get_context = multiprocessing.get_context

    def mock_get_context(method=None):
        if method == "fork":
            return original_get_context("spawn")
        return original_get_context(method)

    multiprocessing.get_context = mock_get_context

    # Mock ctypes LoadLibrary to prevent Windows errors
    original_load_library = ctypes.cdll.LoadLibrary

    def mock_load_library(name):
        if name is None or not isinstance(name, str):
            return MagicMock()
        try:
            return original_load_library(name)
        except (OSError, TypeError):
            return MagicMock()

    ctypes.cdll.LoadLibrary = mock_load_library

# Mock external dependencies before importing module
sys.modules["pypureclient"] = MagicMock()
sys.modules["pypureclient.flashblade"] = MagicMock()
sys.modules["urllib3"] = MagicMock()
sys.modules["distro"] = MagicMock()
# Mock Unix-specific modules for Windows compatibility
sys.modules["grp"] = MagicMock()
sys.modules["fcntl"] = MagicMock()
sys.modules["pwd"] = MagicMock()
sys.modules["syslog"] = MagicMock()
# Mock termios with required constants
mock_termios = MagicMock()
mock_termios.TCSAFLUSH = 2
sys.modules["termios"] = mock_termios
sys.modules["tty"] = MagicMock()

# Mock ansible_collections module structure
sys.modules["ansible_collections"] = MagicMock()
sys.modules["ansible_collections.everpure"] = MagicMock()
sys.modules["ansible_collections.everpure.flashblade"] = MagicMock()
sys.modules["ansible_collections.everpure.flashblade.plugins"] = MagicMock()
sys.modules[
    "ansible_collections.everpure.flashblade.plugins.module_utils"
] = MagicMock()
sys.modules[
    "ansible_collections.everpure.flashblade.plugins.module_utils.purefb"
] = MagicMock()
sys.modules[
    "ansible_collections.everpure.flashblade.plugins.module_utils.common"
] = MagicMock()
sys.modules[
    "ansible_collections.everpure.flashblade.plugins.module_utils.version"
] = MagicMock()

from plugins.modules.purefb_resource_access import (
    main,
    get_resource_access,
)


class TestPurefbResourceAccess:
    """Test cases for purefb_resource_access module"""

    @patch("plugins.modules.purefb_resource_access.get_resource_access")
    @patch("plugins.modules.purefb_resource_access.LooseVersion")
    @patch("plugins.modules.purefb_resource_access.get_system")
    @patch("plugins.modules.purefb_resource_access.AnsibleModule")
    @patch("plugins.modules.purefb_resource_access.HAS_PURESTORAGE", True)
    def test_main_create_resource_access(
        self,
        mock_ansible_module,
        mock_get_system,
        mock_loose_version,
        mock_get_resource_access,
    ):
        """Test creating a resource access"""
        # Setup mock module
        mock_module = Mock()
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.params = {
            "resource_type": "dns",
            "resource_name": "management",
            "scope_type": "realms",
            "scope_name": "test-realm",
            "state": "present",
        }
        mock_module.check_mode = False
        mock_ansible_module.return_value = mock_module

        # Mock blade
        mock_blade = Mock()
        mock_blade.get_versions.return_value.items = ["2.19"]
        mock_get_system.return_value = mock_blade

        # Mock API version check
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        # Resource Access doesn't exist
        mock_get_resource_access.return_value = None

        # Mock successful resource access
        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_blade.post_resource_accesses_batch.return_value = mock_post_response

        try:
            main()
        except SystemExit:
            pass

        # Filter search
        filter_string = (
            "resource.resource_type='"
            + "dns"
            + "' and scope.name='"
            + "test-realm"
            + "' and scope.resource_type='"
            + "realms"
            + "'"
        )

        # Verify post_resource_accesses_batch was called
        mock_blade.post_resource_accesses_batch.assert_called_once_with(
            filter=filter_string
        )

        # Verify exit_json wa called with changed=True
        mock_module.exit_json.assert_called_once()
        call_args = mock_module.exit_json.call_args[1]
        assert call_args["changed"] is True

    @patch("plugins.modules.purefb_resource_access.get_resource_access")
    @patch("plugins.modules.purefb_resource_access.LooseVersion")
    @patch("plugins.modules.purefb_resource_access.get_system")
    @patch("plugins.modules.purefb_resource_access.AnsibleModule")
    @patch("plugins.modules.purefb_resource_access.HAS_PURESTORAGE", True)
    def test_main_delete_resource_access(
        self,
        mock_ansible_module,
        mock_get_system,
        mock_loose_version,
        mock_get_resource_access,
    ):
        """Test deleting a resource access"""
        # Setup mock module
        mock_module = Mock()
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.params = {
            "resource_type": "dns",
            "resource_name": "management",
            "scope_type": "realms",
            "scope_name": "test-realm",
            "state": "absent",
        }
        mock_module.check_mode = False
        mock_ansible_module.return_value = mock_module

        # Mock blade
        mock_blade = Mock()
        mock_blade.get_versions.return_value.items = ["2.19"]
        mock_get_system.return_value = mock_blade

        # Mock API version check
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        # Resource Access exist
        mock_get_resource_access.return_value = True

        # Mock successful resource access deletion
        mock_delete_response = Mock()
        mock_delete_response.status_code = 200
        mock_blade.delete_resource_accesses.return_value = mock_delete_response

        # Call main
        try:
            main()
        except SystemExit:
            pass

        # Verify delete_resource_accesses was called
        mock_blade.delete_resource_accesses.assert_called_once()

        # Verify exit_json wa called with changed=True
        mock_module.exit_json.assert_called_once()
        call_args = mock_module.exit_json.call_args[1]
        assert call_args["changed"] is True

    def test_get_resource_access(self):
        """Test get_resource_access function"""
        # Setup mock module
        mock_module = Mock()
        mock_module.params = {
            "resource_type": "dns",
            "resource_name": "management",
            "scope_type": "realms",
            "scope_name": "test-realm",
        }

        # Setup mock blade
        mock_blade = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_blade.get_realms.return_value = mock_response

        result = get_resource_access(mock_module, mock_blade)

        # Filter search
        filter_string = (
            "resource.resource_type='"
            + "dns"
            + "' and scope.name='"
            + "test-realm"
            + "' and scope.resource_type='"
            + "realms"
            + "'"
        )

        assert result is True
        mock_blade.get_resource_accesses.assert_called_once_with(filter=filter_string)

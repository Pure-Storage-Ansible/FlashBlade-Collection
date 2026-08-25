# Copyright: (c) 2026, Pure Storage Ansible Team <pure-ansible-team@everpuredata.com>
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for purefb_local_user module."""

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
sys.modules["ansible_collections.everpure.flashblade.plugins.module_utils"] = (
    MagicMock()
)
sys.modules["ansible_collections.everpure.flashblade.plugins.module_utils.purefb"] = (
    MagicMock()
)
sys.modules["ansible_collections.everpure.flashblade.plugins.module_utils.common"] = (
    MagicMock()
)
sys.modules["ansible_collections.everpure.flashblade.plugins.module_utils.version"] = (
    MagicMock()
)

from plugins.modules.purefb_local_user import (
    main,
    _get_user,
    _get_current_groups,
    _reconcile_memberships,
)


def _base_params(**overrides):
    params = {
        "name": "alice",
        "state": "present",
        "local_directory_service": "myserver_local",
        "new_name": None,
        "uid": None,
        "email": None,
        "enabled": True,
        "password": "s3cret!",
        "force_password_reset": False,
        "primary_group": None,
        "groups": None,
        "context": "",
    }
    params.update(overrides)
    return params


class TestPurefbLocalUser:
    """Test cases for purefb_local_user module"""

    # ---------------- helper-function unit tests ----------------

    def test_get_user_returns_first_item(self):
        """_get_user returns the first hit"""
        module = Mock()
        module.params = {"name": "alice", "context": ""}

        existing = Mock()
        existing.name = "alice"
        response = Mock()
        response.status_code = 200
        response.items = [existing]

        blade = Mock()
        blade.get_directory_services_local_users.return_value = response

        assert _get_user(module, blade, "myserver_local") is existing
        blade.get_directory_services_local_users.assert_called_once_with(
            names=["alice"],
            filter="local_directory_service.name='myserver_local'",
        )

    def test_get_user_returns_none_when_empty(self):
        """_get_user returns None when items is empty"""
        module = Mock()
        module.params = {"name": "alice", "context": ""}

        response = Mock()
        response.status_code = 200
        response.items = []
        blade = Mock()
        blade.get_directory_services_local_users.return_value = response

        assert _get_user(module, blade, "myserver_local") is None

    def test_get_current_groups_extracts_names(self):
        """_get_current_groups returns the set of the user's current group names"""
        module = Mock()
        module.params = {"name": "alice", "context": ""}
        module.fail_json = Mock(side_effect=SystemExit)

        edge_a = Mock()
        edge_a.group = Mock()
        edge_a.group.name = "developers"
        edge_b = Mock()
        edge_b.group = Mock()
        edge_b.group.name = "infra"

        response = Mock()
        response.status_code = 200
        response.items = [edge_a, edge_b]
        blade = Mock()
        blade.get_directory_services_local_users_members.return_value = response

        result = _get_current_groups(module, blade, "myserver_local")
        assert result == {"developers", "infra"}

    # ---------------- _reconcile_memberships tests ----------------

    def test_reconcile_adds_missing(self):
        """_reconcile_memberships POSTs groups the user isn't in yet"""
        module = Mock()
        module.params = {
            "name": "alice",
            "groups": ["developers", "infra"],
            "context": "",
        }
        module.check_mode = False
        module.fail_json = Mock(side_effect=SystemExit)

        current_response = Mock()
        current_response.status_code = 200
        current_response.items = []
        post_response = Mock()
        post_response.status_code = 200

        blade = Mock()
        blade.get_directory_services_local_users_members.return_value = current_response
        blade.post_directory_services_local_users_members.return_value = post_response

        changed = _reconcile_memberships(module, blade, "myserver_local", "alice")
        assert changed is True
        blade.post_directory_services_local_users_members.assert_called_once()
        blade.delete_directory_services_local_users_members.assert_not_called()

    def test_reconcile_removes_extras(self):
        """_reconcile_memberships DELETEs groups the user should no longer be in"""
        module = Mock()
        module.params = {
            "name": "alice",
            "groups": ["developers"],
            "context": "",
        }
        module.check_mode = False
        module.fail_json = Mock(side_effect=SystemExit)

        keep = Mock()
        keep.group = Mock()
        keep.group.name = "developers"
        drop = Mock()
        drop.group = Mock()
        drop.group.name = "infra"

        current_response = Mock()
        current_response.status_code = 200
        current_response.items = [keep, drop]
        delete_response = Mock()
        delete_response.status_code = 200

        blade = Mock()
        blade.get_directory_services_local_users_members.return_value = current_response
        blade.delete_directory_services_local_users_members.return_value = (
            delete_response
        )

        changed = _reconcile_memberships(module, blade, "myserver_local", "alice")
        assert changed is True
        blade.delete_directory_services_local_users_members.assert_called_once_with(
            member_names=["alice"],
            group_names=["infra"],
            local_directory_service_names=["myserver_local"],
        )
        blade.post_directory_services_local_users_members.assert_not_called()

    def test_reconcile_excludes_primary_group(self):
        """_reconcile_memberships never touches the primary-group edge"""
        module = Mock()
        module.params = {
            "name": "alice",
            "groups": ["developers"],
            "context": "",
        }
        module.check_mode = False
        module.fail_json = Mock(side_effect=SystemExit)

        primary_edge = Mock()
        primary_edge.group = Mock()
        primary_edge.group.name = "alice"  # primary
        dev_edge = Mock()
        dev_edge.group = Mock()
        dev_edge.group.name = "developers"

        current_response = Mock()
        current_response.status_code = 200
        current_response.items = [primary_edge, dev_edge]

        blade = Mock()
        blade.get_directory_services_local_users_members.return_value = current_response

        changed = _reconcile_memberships(
            module, blade, "myserver_local", desired_primary_group="alice"
        )
        assert changed is False
        blade.post_directory_services_local_users_members.assert_not_called()
        blade.delete_directory_services_local_users_members.assert_not_called()

    def test_reconcile_check_mode_skips_writes(self):
        """_reconcile_memberships reports changed but skips writes in check mode"""
        module = Mock()
        module.params = {
            "name": "alice",
            "groups": ["developers"],
            "context": "",
        }
        module.check_mode = True
        module.fail_json = Mock(side_effect=SystemExit)

        current_response = Mock()
        current_response.status_code = 200
        current_response.items = []

        blade = Mock()
        blade.get_directory_services_local_users_members.return_value = current_response

        changed = _reconcile_memberships(module, blade, "myserver_local", "alice")
        assert changed is True
        blade.post_directory_services_local_users_members.assert_not_called()
        blade.delete_directory_services_local_users_members.assert_not_called()

    # ---------------- main() flows ----------------

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.ReferenceWritable")
    @patch("plugins.modules.purefb_local_user.LocalUserPost")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_creates_user(
        self,
        mock_ansible_module,
        mock_get_system,
        mock_user_post,
        mock_reference_writable,
        mock_loose_version,
    ):
        """Test creating a new local user with primary_group and uid"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(
            uid=5001,
            email="alice@example.com",
            primary_group="alice",
        )
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        blade.get_directory_services_local_users.return_value = get_response

        created = Mock()
        created.name = "alice"
        created.uid = 5001
        created.sid = "S-1-5-21-2"
        created.enabled = True
        created.primary_group = Mock()
        created.primary_group.name = "alice"

        post_response = Mock()
        post_response.status_code = 200
        post_response.items = [created]
        blade.post_directory_services_local_users.return_value = post_response

        try:
            main()
        except SystemExit:
            pass

        blade.post_directory_services_local_users.assert_called_once()
        call_kwargs = blade.post_directory_services_local_users.call_args[1]
        assert call_kwargs["names"] == ["alice"]
        assert call_kwargs["local_directory_service_names"] == ["myserver_local"]
        mock_user_post.assert_called_once()
        mock_reference_writable.assert_any_call(name="alice")
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_create_fails_without_password_when_enabled(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test create fails when enabled=true and no password is provided"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(password=None, enabled=True)
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        blade.get_directory_services_local_users.return_value = get_response

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        assert "password" in module.fail_json.call_args[1]["msg"]
        blade.post_directory_services_local_users.assert_not_called()

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_create_check_mode_skips_post(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test create reports changed but skips POST in check mode"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(primary_group="alice")
        module.check_mode = True
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        blade.get_directory_services_local_users.return_value = get_response

        try:
            main()
        except SystemExit:
            pass

        blade.post_directory_services_local_users.assert_not_called()
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_create_fails_on_api_error(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test create surfaces API error via fail_json"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(primary_group="alice")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        blade.get_directory_services_local_users.return_value = get_response

        post_response = Mock()
        post_response.status_code = 400
        post_response.errors = []
        blade.post_directory_services_local_users.return_value = post_response

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        assert "Failed to create local user" in module.fail_json.call_args[1]["msg"]

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.LocalUserPatch")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_updates_email(
        self, mock_ansible_module, mock_get_system, mock_user_patch, mock_loose_version
    ):
        """Test updating email on an existing user"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(
            email="new@example.com", password=None, primary_group="alice"
        )
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "alice"
        existing.built_in = False
        existing.email = "old@example.com"
        existing.enabled = True
        existing.uid = 5001
        existing.primary_group = Mock()
        existing.primary_group.name = "alice"

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_users.return_value = get_response

        patch_response = Mock()
        patch_response.status_code = 200
        blade.patch_directory_services_local_users.return_value = patch_response

        try:
            main()
        except SystemExit:
            pass

        blade.patch_directory_services_local_users.assert_called_once()
        mock_user_patch.assert_called_once_with(email="new@example.com")
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_update_idempotent_when_no_changes(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test update is a no-op when nothing changed"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(
            uid=5001,
            email="alice@example.com",
            password=None,
        )
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "alice"
        existing.built_in = False
        existing.email = "alice@example.com"
        existing.enabled = True
        existing.uid = 5001
        existing.primary_group = None

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_users.return_value = get_response

        try:
            main()
        except SystemExit:
            pass

        blade.patch_directory_services_local_users.assert_not_called()
        assert module.exit_json.call_args[1]["changed"] is False

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.LocalUserPatch")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_renames_user(
        self, mock_ansible_module, mock_get_system, mock_user_patch, mock_loose_version
    ):
        """Test renaming an existing user via new_name"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(new_name="alice2", password=None)
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "alice"
        existing.built_in = False
        existing.email = None
        existing.enabled = True
        existing.uid = 5001
        existing.primary_group = None

        # First call from _get_user, second from the rename-clash lookup
        first_response = Mock()
        first_response.status_code = 200
        first_response.items = [existing]
        clash_response = Mock()
        clash_response.status_code = 200
        clash_response.items = []
        blade.get_directory_services_local_users.side_effect = [
            first_response,
            clash_response,
        ]

        patch_response = Mock()
        patch_response.status_code = 200
        blade.patch_directory_services_local_users.return_value = patch_response

        try:
            main()
        except SystemExit:
            pass

        mock_user_patch.assert_called_once_with(name="alice2")
        blade.patch_directory_services_local_users.assert_called_once()
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_rename_fails_when_target_exists(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test rename fails cleanly when the target name already exists"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(new_name="alice2", password=None)
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "alice"
        existing.built_in = False
        existing.email = None
        existing.enabled = True
        existing.uid = 5001
        existing.primary_group = None

        clash = Mock()
        clash.name = "alice2"
        first_response = Mock()
        first_response.status_code = 200
        first_response.items = [existing]
        clash_response = Mock()
        clash_response.status_code = 200
        clash_response.items = [clash]
        blade.get_directory_services_local_users.side_effect = [
            first_response,
            clash_response,
        ]

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        assert "target name already exists" in module.fail_json.call_args[1]["msg"]
        blade.patch_directory_services_local_users.assert_not_called()

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_refuses_to_rename_builtin(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test rename is refused on built-in users"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(
            name="Administrator", new_name="root", password=None
        )
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "Administrator"
        existing.built_in = True
        existing.email = None
        existing.enabled = True
        existing.uid = 500
        existing.primary_group = None

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_users.return_value = get_response

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        assert "built-in" in module.fail_json.call_args[1]["msg"]
        blade.patch_directory_services_local_users.assert_not_called()

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.LocalUserPatch")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_disables_user(
        self, mock_ansible_module, mock_get_system, mock_user_patch, mock_loose_version
    ):
        """Test disabling an existing user"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(enabled=False, password=None)
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "alice"
        existing.built_in = False
        existing.email = None
        existing.enabled = True
        existing.uid = 5001
        existing.primary_group = None

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_users.return_value = get_response

        patch_response = Mock()
        patch_response.status_code = 200
        blade.patch_directory_services_local_users.return_value = patch_response

        try:
            main()
        except SystemExit:
            pass

        blade.patch_directory_services_local_users.assert_called_once()
        mock_user_patch.assert_called_once_with(enabled=False)
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_reenable_requires_password(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test re-enabling a disabled user requires a password"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(enabled=True, password=None)
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "alice"
        existing.built_in = False
        existing.email = None
        existing.enabled = False
        existing.uid = 5001
        existing.primary_group = None

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_users.return_value = get_response

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        assert "password" in module.fail_json.call_args[1]["msg"]
        blade.patch_directory_services_local_users.assert_not_called()

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.LocalUserPatch")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_force_password_reset_patches_password(
        self, mock_ansible_module, mock_get_system, mock_user_patch, mock_loose_version
    ):
        """Test force_password_reset=true includes the password in the PATCH body"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(force_password_reset=True, password="brandnew!")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "alice"
        existing.built_in = False
        existing.email = None
        existing.enabled = True
        existing.uid = 5001
        existing.primary_group = None

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_users.return_value = get_response

        patch_response = Mock()
        patch_response.status_code = 200
        blade.patch_directory_services_local_users.return_value = patch_response

        try:
            main()
        except SystemExit:
            pass

        blade.patch_directory_services_local_users.assert_called_once()
        mock_user_patch.assert_called_once_with(password="brandnew!")
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_force_password_reset_requires_password(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test force_password_reset=true without a password fails cleanly"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(force_password_reset=True, password=None)
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "alice"
        existing.built_in = False
        existing.email = None
        existing.enabled = True
        existing.uid = 5001
        existing.primary_group = None

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_users.return_value = get_response

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        assert "force_password_reset" in module.fail_json.call_args[1]["msg"]
        blade.patch_directory_services_local_users.assert_not_called()

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_deletes_user(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test deleting an existing user"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(state="absent", password=None)
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "alice"
        existing.built_in = False

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_users.return_value = get_response

        delete_response = Mock()
        delete_response.status_code = 200
        blade.delete_directory_services_local_users.return_value = delete_response

        try:
            main()
        except SystemExit:
            pass

        blade.delete_directory_services_local_users.assert_called_once_with(
            names=["alice"],
            local_directory_service_names=["myserver_local"],
        )
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_delete_check_mode_skips_call(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test delete reports changed but skips DELETE in check mode"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(state="absent", password=None)
        module.check_mode = True
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "alice"
        existing.built_in = False

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_users.return_value = get_response

        try:
            main()
        except SystemExit:
            pass

        blade.delete_directory_services_local_users.assert_not_called()
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_refuses_to_delete_builtin(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test delete is refused on built-in users"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(
            state="absent", name="Administrator", password=None
        )
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "Administrator"
        existing.built_in = True

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_users.return_value = get_response

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        assert "built-in" in module.fail_json.call_args[1]["msg"]
        blade.delete_directory_services_local_users.assert_not_called()

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_delete_nonexistent_is_noop(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test state=absent on a nonexistent user reports changed=False"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(state="absent", name="ghost", password=None)
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        blade.get_directory_services_local_users.return_value = get_response

        try:
            main()
        except SystemExit:
            pass

        blade.delete_directory_services_local_users.assert_not_called()
        assert module.exit_json.call_args[1]["changed"] is False

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.LocalUserPost")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_create_with_groups_reconciles(
        self, mock_ansible_module, mock_get_system, mock_user_post, mock_loose_version
    ):
        """Test create-with-groups POSTs the user then reconciles memberships"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(
            primary_group="alice",
            groups=["developers", "infra"],
        )
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        blade.get_directory_services_local_users.return_value = get_response

        created = Mock()
        created.name = "alice"
        created.uid = 5001
        created.sid = "S-1"
        created.enabled = True
        created.primary_group = Mock()
        created.primary_group.name = "alice"

        post_response = Mock()
        post_response.status_code = 200
        post_response.items = [created]
        blade.post_directory_services_local_users.return_value = post_response

        members_current = Mock()
        members_current.status_code = 200
        members_current.items = []
        blade.get_directory_services_local_users_members.return_value = members_current

        post_members = Mock()
        post_members.status_code = 200
        blade.post_directory_services_local_users_members.return_value = post_members

        try:
            main()
        except SystemExit:
            pass

        blade.post_directory_services_local_users.assert_called_once()
        blade.post_directory_services_local_users_members.assert_called_once()
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", True)
    def test_main_fails_on_unsupported_api_version(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test failure when the array API version is older than MIN_REQUIRED_API_VERSION"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=True)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(primary_group="alice")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.17", "2.18", "2.19"]
        mock_get_system.return_value = blade

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        assert "REST version not supported" in module.fail_json.call_args[1]["msg"]

    @patch("plugins.modules.purefb_local_user.LooseVersion")
    @patch("plugins.modules.purefb_local_user.get_system")
    @patch("plugins.modules.purefb_local_user.AnsibleModule")
    @patch("plugins.modules.purefb_local_user.HAS_PYPURECLIENT", False)
    def test_main_fails_without_sdk(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test failure when py-pure-client SDK is not installed"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params()
        module.check_mode = False
        mock_ansible_module.return_value = module

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        assert "py-pure-client" in module.fail_json.call_args[1]["msg"]

# Copyright: (c) 2026, Pure Storage Ansible Team <pure-ansible-team@everpuredata.com>
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for purefb_local_group module."""

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

from plugins.modules.purefb_local_group import (
    main,
    _get_group,
    _get_current_user_members,
    _reconcile_user_members,
)


def _base_params(**overrides):
    params = {
        "name": "developers",
        "state": "present",
        "local_directory_service": "myserver_local",
        "new_name": None,
        "gid": None,
        "email": None,
        "local_users": None,
        "force": False,
        "context": "",
    }
    params.update(overrides)
    return params


class TestPurefbLocalGroup:
    """Test cases for purefb_local_group module"""

    # ---------------- helper-function unit tests ----------------

    def test_get_group_returns_first_item(self):
        """_get_group returns the first hit"""
        module = Mock()
        module.params = {"name": "developers", "context": ""}

        existing = Mock()
        existing.name = "developers"
        response = Mock()
        response.status_code = 200
        response.items = [existing]

        blade = Mock()
        blade.get_directory_services_local_groups.return_value = response

        assert _get_group(module, blade, "myserver_local") is existing
        blade.get_directory_services_local_groups.assert_called_once_with(
            names=["developers"],
            filter="local_directory_service.name='myserver_local'",
        )

    def test_get_group_returns_none_when_empty(self):
        """_get_group returns None when items is empty"""
        module = Mock()
        module.params = {"name": "developers", "context": ""}

        response = Mock()
        response.status_code = 200
        response.items = []
        blade = Mock()
        blade.get_directory_services_local_groups.return_value = response

        assert _get_group(module, blade, "myserver_local") is None

    def test_get_current_user_members_extracts_names(self):
        """_get_current_user_members returns the set of user-member names"""
        module = Mock()
        module.params = {"name": "developers", "context": ""}
        module.fail_json = Mock(side_effect=SystemExit)

        edge_a = Mock()
        edge_a.member = Mock()
        edge_a.member.name = "alice"
        edge_b = Mock()
        edge_b.member = Mock()
        edge_b.member.name = "bob"

        response = Mock()
        response.status_code = 200
        response.items = [edge_a, edge_b]
        blade = Mock()
        blade.get_directory_services_local_groups_members.return_value = response

        result = _get_current_user_members(
            module, blade, "myserver_local", group_name="developers"
        )
        assert result == {"alice", "bob"}
        blade.get_directory_services_local_groups_members.assert_called_once_with(
            group_names=["developers"],
            filter="local_directory_service.name='myserver_local'",
            member_types=["User"],
        )

    # ---------------- _reconcile_user_members tests ----------------

    def test_reconcile_adds_missing_members(self):
        """_reconcile_user_members POSTs users not yet in the group"""
        module = Mock()
        module.params = {
            "name": "developers",
            "local_users": ["alice", "bob"],
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
        blade.get_directory_services_local_groups_members.return_value = (
            current_response
        )
        blade.post_directory_services_local_groups_members.return_value = post_response

        changed = _reconcile_user_members(module, blade, "myserver_local", "developers")
        assert changed is True
        blade.post_directory_services_local_groups_members.assert_called_once()
        blade.delete_directory_services_local_groups_members.assert_not_called()

    def test_reconcile_removes_extras(self):
        """_reconcile_user_members DELETEs users no longer in the desired list"""
        module = Mock()
        module.params = {
            "name": "developers",
            "local_users": ["alice"],
            "context": "",
        }
        module.check_mode = False
        module.fail_json = Mock(side_effect=SystemExit)

        alice = Mock()
        alice.member = Mock()
        alice.member.name = "alice"
        bob = Mock()
        bob.member = Mock()
        bob.member.name = "bob"

        current_response = Mock()
        current_response.status_code = 200
        current_response.items = [alice, bob]
        delete_response = Mock()
        delete_response.status_code = 200

        blade = Mock()
        blade.get_directory_services_local_groups_members.return_value = (
            current_response
        )
        blade.delete_directory_services_local_groups_members.return_value = (
            delete_response
        )

        changed = _reconcile_user_members(module, blade, "myserver_local", "developers")
        assert changed is True
        blade.delete_directory_services_local_groups_members.assert_called_once()
        blade.post_directory_services_local_groups_members.assert_not_called()

    def test_reconcile_idempotent_when_match(self):
        """_reconcile_user_members is a no-op when current == desired"""
        module = Mock()
        module.params = {
            "name": "developers",
            "local_users": ["alice"],
            "context": "",
        }
        module.check_mode = False
        module.fail_json = Mock(side_effect=SystemExit)

        alice = Mock()
        alice.member = Mock()
        alice.member.name = "alice"
        current_response = Mock()
        current_response.status_code = 200
        current_response.items = [alice]

        blade = Mock()
        blade.get_directory_services_local_groups_members.return_value = (
            current_response
        )

        changed = _reconcile_user_members(module, blade, "myserver_local", "developers")
        assert changed is False
        blade.post_directory_services_local_groups_members.assert_not_called()
        blade.delete_directory_services_local_groups_members.assert_not_called()

    def test_reconcile_check_mode_skips_writes(self):
        """_reconcile_user_members reports changed but skips writes in check mode"""
        module = Mock()
        module.params = {
            "name": "developers",
            "local_users": ["alice"],
            "context": "",
        }
        module.check_mode = True
        module.fail_json = Mock(side_effect=SystemExit)

        current_response = Mock()
        current_response.status_code = 200
        current_response.items = []

        blade = Mock()
        blade.get_directory_services_local_groups_members.return_value = (
            current_response
        )

        changed = _reconcile_user_members(module, blade, "myserver_local", "developers")
        assert changed is True
        blade.post_directory_services_local_groups_members.assert_not_called()
        blade.delete_directory_services_local_groups_members.assert_not_called()

    # ---------------- main() flows ----------------

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.LocalGroupPost")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_creates_group(
        self, mock_ansible_module, mock_get_system, mock_group_post, mock_loose_version
    ):
        """Test creating a new local group with gid and email"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(gid=6001, email="devs@example.com")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        # Group doesn't exist
        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        blade.get_directory_services_local_groups.return_value = get_response

        created = Mock()
        created.name = "developers"
        created.gid = 6001
        created.sid = "S-1-5-21-1"
        created.built_in = False

        post_response = Mock()
        post_response.status_code = 200
        post_response.items = [created]
        blade.post_directory_services_local_groups.return_value = post_response

        try:
            main()
        except SystemExit:
            pass

        blade.post_directory_services_local_groups.assert_called_once()
        call_kwargs = blade.post_directory_services_local_groups.call_args[1]
        assert call_kwargs["names"] == ["developers"]
        assert call_kwargs["local_directory_service_names"] == ["myserver_local"]
        mock_group_post.assert_called_once_with(email="devs@example.com", gid=6001)
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_create_check_mode_skips_post(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test create reports changed but skips POST in check mode"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params()
        module.check_mode = True
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        blade.get_directory_services_local_groups.return_value = get_response

        try:
            main()
        except SystemExit:
            pass

        blade.post_directory_services_local_groups.assert_not_called()
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_create_fails_on_api_error(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test create surfaces API error via fail_json"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params()
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        blade.get_directory_services_local_groups.return_value = get_response

        post_response = Mock()
        post_response.status_code = 400
        post_response.errors = []
        blade.post_directory_services_local_groups.return_value = post_response

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        assert "Failed to create local group" in module.fail_json.call_args[1]["msg"]

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.LocalGroupPatch")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_updates_email_and_gid(
        self, mock_ansible_module, mock_get_system, mock_group_patch, mock_loose_version
    ):
        """Test updating an existing group's email and gid"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(gid=7001, email="new@example.com")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "developers"
        existing.built_in = False
        existing.gid = 6001
        existing.email = "old@example.com"

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_groups.return_value = get_response

        patch_response = Mock()
        patch_response.status_code = 200
        blade.patch_directory_services_local_groups.return_value = patch_response

        try:
            main()
        except SystemExit:
            pass

        blade.patch_directory_services_local_groups.assert_called_once()
        mock_group_patch.assert_called_once_with(email="new@example.com", gid=7001)
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_update_idempotent_when_no_changes(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test update is a no-op when nothing changed"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(gid=6001, email="devs@example.com")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "developers"
        existing.built_in = False
        existing.gid = 6001
        existing.email = "devs@example.com"

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_groups.return_value = get_response

        try:
            main()
        except SystemExit:
            pass

        blade.patch_directory_services_local_groups.assert_not_called()
        assert module.exit_json.call_args[1]["changed"] is False

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.LocalGroupPatch")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_renames_group(
        self, mock_ansible_module, mock_get_system, mock_group_patch, mock_loose_version
    ):
        """Test renaming an existing group via new_name"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(new_name="devs")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "developers"
        existing.built_in = False
        existing.gid = 6001
        existing.email = None

        # First call is _get_group (existing found); second is the rename-clash lookup
        clash_response = Mock()
        clash_response.status_code = 200
        clash_response.items = []
        first_response = Mock()
        first_response.status_code = 200
        first_response.items = [existing]
        blade.get_directory_services_local_groups.side_effect = [
            first_response,
            clash_response,
        ]

        patch_response = Mock()
        patch_response.status_code = 200
        blade.patch_directory_services_local_groups.return_value = patch_response

        try:
            main()
        except SystemExit:
            pass

        mock_group_patch.assert_called_once_with(name="devs")
        blade.patch_directory_services_local_groups.assert_called_once()
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_rename_fails_when_target_exists(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test rename fails cleanly when the target name already exists"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(new_name="devs")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "developers"
        existing.built_in = False
        existing.gid = 6001
        existing.email = None

        clash = Mock()
        clash.name = "devs"
        clash_response = Mock()
        clash_response.status_code = 200
        clash_response.items = [clash]
        first_response = Mock()
        first_response.status_code = 200
        first_response.items = [existing]
        blade.get_directory_services_local_groups.side_effect = [
            first_response,
            clash_response,
        ]

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        msg = module.fail_json.call_args[1]["msg"]
        assert "target name already exists" in msg
        blade.patch_directory_services_local_groups.assert_not_called()

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_refuses_to_rename_builtin(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test rename is refused on built-in groups"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(name="Domain Users", new_name="dev-users")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "Domain Users"
        existing.built_in = True
        existing.gid = 100
        existing.email = None

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_groups.return_value = get_response

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        assert "built-in" in module.fail_json.call_args[1]["msg"]
        blade.patch_directory_services_local_groups.assert_not_called()

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_deletes_empty_group(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test deleting a group that has no members"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(state="absent")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "developers"
        existing.built_in = False

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_groups.return_value = get_response

        members_response = Mock()
        members_response.status_code = 200
        members_response.items = []
        blade.get_directory_services_local_groups_members.return_value = (
            members_response
        )

        delete_response = Mock()
        delete_response.status_code = 200
        blade.delete_directory_services_local_groups.return_value = delete_response

        try:
            main()
        except SystemExit:
            pass

        blade.delete_directory_services_local_groups.assert_called_once_with(
            names=["developers"],
            local_directory_service_names=["myserver_local"],
        )
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_delete_refuses_when_members_and_no_force(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test delete refuses when the group has members and force=false"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(state="absent")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "developers"
        existing.built_in = False

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_groups.return_value = get_response

        edge = Mock()
        edge.member = Mock()
        edge.member.name = "alice"
        edge.member.resource_type = "local-users"
        members_response = Mock()
        members_response.status_code = 200
        members_response.items = [edge]
        blade.get_directory_services_local_groups_members.return_value = (
            members_response
        )

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        assert "force: true" in module.fail_json.call_args[1]["msg"]
        blade.delete_directory_services_local_groups.assert_not_called()

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_delete_force_clears_members_then_deletes(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test delete with force=true clears members first, then deletes the group"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(state="absent", force=True)
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "developers"
        existing.built_in = False

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_groups.return_value = get_response

        edge = Mock()
        edge.member = Mock()
        edge.member.name = "alice"
        edge.member.resource_type = "local-users"
        members_response = Mock()
        members_response.status_code = 200
        members_response.items = [edge]
        blade.get_directory_services_local_groups_members.return_value = (
            members_response
        )

        ok = Mock()
        ok.status_code = 200
        blade.delete_directory_services_local_groups_members.return_value = ok
        blade.delete_directory_services_local_groups.return_value = ok

        try:
            main()
        except SystemExit:
            pass

        blade.delete_directory_services_local_groups_members.assert_called_once()
        blade.delete_directory_services_local_groups.assert_called_once()
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_refuses_to_delete_builtin(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test delete is refused on built-in groups"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(state="absent", name="Domain Users")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "Domain Users"
        existing.built_in = True

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_groups.return_value = get_response

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        assert "built-in" in module.fail_json.call_args[1]["msg"]
        blade.delete_directory_services_local_groups.assert_not_called()

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_delete_nonexistent_is_noop(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test state=absent on a nonexistent group reports changed=False"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(state="absent", name="ghost")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        blade.get_directory_services_local_groups.return_value = get_response

        try:
            main()
        except SystemExit:
            pass

        blade.delete_directory_services_local_groups.assert_not_called()
        assert module.exit_json.call_args[1]["changed"] is False

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.LocalGroupPost")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_create_with_local_users_reconciles(
        self, mock_ansible_module, mock_get_system, mock_group_post, mock_loose_version
    ):
        """Test create-with-members POSTs the group then reconciles members"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(local_users=["alice", "bob"])
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        blade.get_directory_services_local_groups.return_value = get_response

        created = Mock()
        created.name = "developers"
        created.gid = 6001
        created.sid = "S-1"
        created.built_in = False

        post_response = Mock()
        post_response.status_code = 200
        post_response.items = [created]
        blade.post_directory_services_local_groups.return_value = post_response

        members_current = Mock()
        members_current.status_code = 200
        members_current.items = []
        blade.get_directory_services_local_groups_members.return_value = members_current

        post_members = Mock()
        post_members.status_code = 200
        blade.post_directory_services_local_groups_members.return_value = post_members

        try:
            main()
        except SystemExit:
            pass

        blade.post_directory_services_local_groups.assert_called_once()
        blade.post_directory_services_local_groups_members.assert_called_once()
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", True)
    def test_main_fails_on_unsupported_api_version(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test failure when the array API version is older than MIN_REQUIRED_API_VERSION"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=True)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params()
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

    @patch("plugins.modules.purefb_local_group.LooseVersion")
    @patch("plugins.modules.purefb_local_group.get_system")
    @patch("plugins.modules.purefb_local_group.AnsibleModule")
    @patch("plugins.modules.purefb_local_group.HAS_PYPURECLIENT", False)
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

# Copyright: (c) 2026, Pure Storage Ansible Team <pure-ansible-team@everpuredata.com>
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for purefb_mgmt_role module."""

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

from plugins.modules.purefb_mgmt_role import (
    main,
    _ctx,
    _normalize_resource,
    _normalize_actions,
    _validate_role_name,
    _get_role,
    _get_permissions,
    _role_referenced_by_rule,
    _delete_role,
    _create_role,
    _reconcile_permissions,
    _current_attached_policy_names,
    _subject_exists,
    _handle_role,
    _handle_attach,
    RESOURCE_PREFIX,
)


def _base_params(**overrides):
    """Return a full params dict with sane defaults, patched by overrides."""
    params = {
        "object": "role",
        "state": "present",
        "name": "backup-operator",
        "description": None,
        "permissions": None,
        "admin": None,
        "ds_role": None,
        "policies": None,
        "context": "",
    }
    params.update(overrides)
    return params


class TestPurefbMgmtRole:
    """Tests for purefb_mgmt_role module."""

    # ================ pure-function helpers ================

    # ---------------- _ctx ----------------

    def test_ctx_empty_when_context_unset(self):
        """Test _ctx returns {} when context is empty string"""
        mock_module = Mock()
        mock_module.params = {"context": ""}
        assert _ctx(mock_module, "2.19") == {}

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_ctx_returns_context_names_when_supported(self, mock_loose_version):
        """Test _ctx returns context_names when API supports it"""
        mock_loose_version.return_value.__le__ = Mock(return_value=True)
        mock_module = Mock()
        mock_module.params = {"context": "fleet1"}
        assert _ctx(mock_module, "2.19") == {"context_names": ["fleet1"]}

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_ctx_drops_context_when_api_too_old(self, mock_loose_version):
        """Test _ctx returns {} when API is too old, even if context is set"""
        mock_loose_version.return_value.__le__ = Mock(return_value=False)
        mock_module = Mock()
        mock_module.params = {"context": "fleet1"}
        assert _ctx(mock_module, "2.16") == {}

    # ---------------- _normalize_resource ----------------

    def test_normalize_resource_prefixes_short_name(self):
        """Test _normalize_resource prefixes a short resource name"""
        assert _normalize_resource("file-system-snapshots") == (
            RESOURCE_PREFIX + "file-system-snapshots"
        )

    def test_normalize_resource_leaves_fully_qualified_alone(self):
        """Test _normalize_resource does not double-prefix a FQ resource"""
        fq = RESOURCE_PREFIX + "file-systems"
        assert _normalize_resource(fq) == fq

    # ---------------- _normalize_actions ----------------

    def test_normalize_actions_sorts_lowercases(self):
        """Test _normalize_actions returns a sorted list of lowercased verbs"""
        mock_module = Mock()
        mock_module.fail_json = Mock(side_effect=SystemExit)
        out = _normalize_actions(mock_module, ["POST", "GET", "delete"])
        assert out == ["delete", "get", "post"]
        mock_module.fail_json.assert_not_called()

    def test_normalize_actions_rejects_duplicates(self):
        """Test _normalize_actions calls fail_json when the same verb appears twice"""
        mock_module = Mock()
        mock_module.fail_json = Mock(side_effect=SystemExit)
        try:
            _normalize_actions(mock_module, ["get", "GET"])
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "Duplicate action" in mock_module.fail_json.call_args[1]["msg"]

    def test_normalize_actions_rejects_all_with_specific(self):
        """Test _normalize_actions calls fail_json when 'all' is mixed with specific verbs"""
        mock_module = Mock()
        mock_module.fail_json = Mock(side_effect=SystemExit)
        try:
            _normalize_actions(mock_module, ["all", "get"])
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "'all' cannot be combined" in mock_module.fail_json.call_args[1]["msg"]

    def test_normalize_actions_rejects_invalid_verb(self):
        """Test _normalize_actions calls fail_json on an unrecognized verb"""
        mock_module = Mock()
        mock_module.fail_json = Mock(side_effect=SystemExit)
        try:
            _normalize_actions(mock_module, ["get", "options"])
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "Invalid action(s)" in mock_module.fail_json.call_args[1]["msg"]

    def test_normalize_actions_accepts_all_alone(self):
        """Test _normalize_actions accepts the sentinel 'all' on its own"""
        mock_module = Mock()
        mock_module.fail_json = Mock(side_effect=SystemExit)
        out = _normalize_actions(mock_module, ["all"])
        assert out == ["all"]
        mock_module.fail_json.assert_not_called()

    # ---------------- _validate_role_name ----------------

    def test_validate_role_name_accepts_valid(self):
        """Test _validate_role_name is a no-op on a valid name"""
        mock_module = Mock()
        mock_module.fail_json = Mock(side_effect=SystemExit)
        _validate_role_name(mock_module, "backup-operator")
        mock_module.fail_json.assert_not_called()

    def test_validate_role_name_rejects_too_long(self):
        """Test _validate_role_name fails on a >63-character name"""
        mock_module = Mock()
        mock_module.fail_json = Mock(side_effect=SystemExit)
        try:
            _validate_role_name(mock_module, "x" * 64)
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "63 characters" in mock_module.fail_json.call_args[1]["msg"]

    def test_validate_role_name_rejects_leading_underscore(self):
        """Test _validate_role_name fails on a name starting with '_'"""
        mock_module = Mock()
        mock_module.fail_json = Mock(side_effect=SystemExit)
        try:
            _validate_role_name(mock_module, "_reserved")
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "reserved" in mock_module.fail_json.call_args[1]["msg"]

    # ---------------- _get_role ----------------

    def test_get_role_returns_first_item(self):
        """Test _get_role returns the first role when present"""
        mock_module = Mock()
        mock_module.params = _base_params()

        existing = Mock()
        mock_blade = Mock()
        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        mock_blade.get_management_access_policies_roles.return_value = get_response

        assert _get_role(mock_module, mock_blade, {}) is existing
        mock_blade.get_management_access_policies_roles.assert_called_once_with(
            names=["backup-operator"]
        )

    def test_get_role_returns_none_when_empty(self):
        """Test _get_role returns None when items list is empty"""
        mock_module = Mock()
        mock_module.params = _base_params()

        mock_blade = Mock()
        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        mock_blade.get_management_access_policies_roles.return_value = get_response

        assert _get_role(mock_module, mock_blade, {}) is None

    def test_get_role_returns_none_on_error(self):
        """Test _get_role returns None on non-200 status"""
        mock_module = Mock()
        mock_module.params = _base_params()

        mock_blade = Mock()
        get_response = Mock()
        get_response.status_code = 400
        get_response.items = []
        mock_blade.get_management_access_policies_roles.return_value = get_response

        assert _get_role(mock_module, mock_blade, {}) is None

    # ---------------- _get_permissions ----------------

    def test_get_permissions_returns_items(self):
        """Test _get_permissions returns permission list on 200"""
        mock_module = Mock()
        mock_module.params = _base_params()

        perm = Mock()
        mock_blade = Mock()
        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [perm]
        mock_blade.get_management_access_policies_roles_permissions.return_value = (
            get_response
        )

        assert _get_permissions(mock_module, mock_blade, {}) == [perm]
        mock_blade.get_management_access_policies_roles_permissions.assert_called_once_with(
            role_names=["backup-operator"]
        )

    def test_get_permissions_fails_on_error(self):
        """Test _get_permissions calls fail_json on non-200"""
        mock_module = Mock()
        mock_module.params = _base_params()
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        get_response = Mock()
        get_response.status_code = 400
        get_response.items = []
        mock_blade.get_management_access_policies_roles_permissions.return_value = (
            get_response
        )

        try:
            _get_permissions(mock_module, mock_blade, {})
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()
        assert (
            "Failed to list permissions for role"
            in mock_module.fail_json.call_args[1]["msg"]
        )

    # ---------------- _role_referenced_by_rule ----------------

    def test_role_referenced_by_rule_true_when_match(self):
        """Test _role_referenced_by_rule returns True when a rule's role.name matches"""
        mock_blade = Mock()
        rule = Mock()
        rule.role = Mock()
        rule.role.name = "backup-operator"
        res = Mock()
        res.status_code = 200
        res.items = [rule]
        mock_blade.get_management_access_policies_rules.return_value = res

        assert _role_referenced_by_rule(mock_blade, "backup-operator", {}) is True

    def test_role_referenced_by_rule_false_when_no_match(self):
        """Test _role_referenced_by_rule returns False when no rule references the role"""
        mock_blade = Mock()
        rule = Mock()
        rule.role = Mock()
        rule.role.name = "some-other-role"
        res = Mock()
        res.status_code = 200
        res.items = [rule]
        mock_blade.get_management_access_policies_rules.return_value = res

        assert _role_referenced_by_rule(mock_blade, "backup-operator", {}) is False

    def test_role_referenced_by_rule_false_on_error(self):
        """Test _role_referenced_by_rule returns False on non-200 status"""
        mock_blade = Mock()
        res = Mock()
        res.status_code = 400
        res.items = []
        mock_blade.get_management_access_policies_rules.return_value = res

        assert _role_referenced_by_rule(mock_blade, "backup-operator", {}) is False

    # ================ _delete_role ================

    def test_delete_role_refuses_builtin(self):
        """Test _delete_role fails when the role is pure_defined"""
        mock_module = Mock()
        mock_module.params = _base_params()
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.exit_json = Mock(side_effect=SystemExit)

        existing = Mock()
        existing.pure_defined = True

        mock_blade = Mock()

        try:
            _delete_role(mock_module, mock_blade, {}, existing)
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()
        assert (
            "Built-in role backup-operator cannot be deleted"
            in mock_module.fail_json.call_args[1]["msg"]
        )
        mock_blade.delete_management_access_policies_roles.assert_not_called()

    def test_delete_role_refuses_when_referenced_by_rule(self):
        """Test _delete_role fails when a policy rule still references the role"""
        mock_module = Mock()
        mock_module.params = _base_params()
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.exit_json = Mock(side_effect=SystemExit)

        existing = Mock()
        existing.pure_defined = False

        rule = Mock()
        rule.role = Mock()
        rule.role.name = "backup-operator"
        rules_res = Mock()
        rules_res.status_code = 200
        rules_res.items = [rule]

        mock_blade = Mock()
        mock_blade.get_management_access_policies_rules.return_value = rules_res

        try:
            _delete_role(mock_module, mock_blade, {}, existing)
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()
        msg = mock_module.fail_json.call_args[1]["msg"]
        assert "is referenced by one or more policy rules" in msg
        assert "purefb_mgmt_policy" in msg
        mock_blade.delete_management_access_policies_roles.assert_not_called()

    def test_delete_role_success(self):
        """Test _delete_role DELETEs when not built-in and not referenced"""
        mock_module = Mock()
        mock_module.params = _base_params()
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.exit_json = Mock(side_effect=SystemExit)

        existing = Mock()
        existing.pure_defined = False

        rules_res = Mock()
        rules_res.status_code = 200
        rules_res.items = []

        mock_blade = Mock()
        mock_blade.get_management_access_policies_rules.return_value = rules_res
        delete_res = Mock()
        delete_res.status_code = 200
        mock_blade.delete_management_access_policies_roles.return_value = delete_res

        try:
            _delete_role(mock_module, mock_blade, {}, existing)
        except SystemExit:
            pass

        mock_blade.delete_management_access_policies_roles.assert_called_once_with(
            names=["backup-operator"]
        )
        assert mock_module.exit_json.call_args[1]["changed"] is True

    def test_delete_role_check_mode_skips_delete(self):
        """Test _delete_role reports changed but skips DELETE in check mode"""
        mock_module = Mock()
        mock_module.params = _base_params()
        mock_module.check_mode = True
        mock_module.exit_json = Mock(side_effect=SystemExit)

        existing = Mock()
        existing.pure_defined = False

        rules_res = Mock()
        rules_res.status_code = 200
        rules_res.items = []

        mock_blade = Mock()
        mock_blade.get_management_access_policies_rules.return_value = rules_res

        try:
            _delete_role(mock_module, mock_blade, {}, existing)
        except SystemExit:
            pass

        mock_blade.delete_management_access_policies_roles.assert_not_called()
        assert mock_module.exit_json.call_args[1]["changed"] is True

    # ================ _create_role ================

    @patch("plugins.modules.purefb_mgmt_role.ManagementAccessPolicyRolePost")
    def test_create_role_without_description(self, mock_post_cls):
        """Test _create_role omits description from POST body when not provided"""
        mock_module = Mock()
        mock_module.params = _base_params(description=None)
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.exit_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        post_res = Mock()
        post_res.status_code = 200
        mock_blade.post_management_access_policies_roles.return_value = post_res

        try:
            _create_role(mock_module, mock_blade, {})
        except SystemExit:
            pass

        mock_post_cls.assert_called_once_with()
        mock_blade.post_management_access_policies_roles.assert_called_once()
        assert mock_module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_mgmt_role.ManagementAccessPolicyRolePost")
    def test_create_role_with_description(self, mock_post_cls):
        """Test _create_role passes description when the caller provides one"""
        mock_module = Mock()
        mock_module.params = _base_params(description="Does snapshot restore")
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.exit_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        post_res = Mock()
        post_res.status_code = 200
        mock_blade.post_management_access_policies_roles.return_value = post_res

        try:
            _create_role(mock_module, mock_blade, {})
        except SystemExit:
            pass

        mock_post_cls.assert_called_once_with(description="Does snapshot restore")

    def test_create_role_check_mode_skips_post(self):
        """Test _create_role reports changed but skips POST in check mode"""
        mock_module = Mock()
        mock_module.params = _base_params()
        mock_module.check_mode = True
        mock_module.exit_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        try:
            _create_role(mock_module, mock_blade, {})
        except SystemExit:
            pass

        mock_blade.post_management_access_policies_roles.assert_not_called()
        assert mock_module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_mgmt_role.ManagementAccessPolicyRolePermissionPost")
    @patch("plugins.modules.purefb_mgmt_role.ManagementAccessPolicyRolePost")
    def test_create_role_posts_permissions(self, mock_post_cls, mock_perm_post_cls):
        """Test _create_role POSTs one permission per entry after the role is created"""
        mock_module = Mock()
        mock_module.params = _base_params(
            permissions=[
                {
                    "resource": "file-system-snapshots",
                    "actions": ["get", "post"],
                },
                {
                    "resource": "file-systems",
                    "actions": ["get"],
                },
            ]
        )
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.exit_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        ok = Mock()
        ok.status_code = 200
        mock_blade.post_management_access_policies_roles.return_value = ok
        mock_blade.post_management_access_policies_roles_permissions.return_value = ok

        try:
            _create_role(mock_module, mock_blade, {})
        except SystemExit:
            pass

        assert (
            mock_blade.post_management_access_policies_roles_permissions.call_count == 2
        )
        assert mock_perm_post_cls.call_count == 2
        # The resource passed to the SDK must be fully-qualified.
        for call in mock_perm_post_cls.call_args_list:
            assert call[1]["resource"].startswith(RESOURCE_PREFIX)
        assert mock_module.exit_json.call_args[1]["changed"] is True

    def test_create_role_validates_permissions_before_post(self):
        """Test _create_role rejects invalid permissions before creating the role"""
        mock_module = Mock()
        mock_module.params = _base_params(
            permissions=[
                {"resource": "file-systems", "actions": ["all", "get"]},
            ]
        )
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.exit_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        try:
            _create_role(mock_module, mock_blade, {})
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()
        # A rejected create must be side-effect free on the array.
        mock_blade.post_management_access_policies_roles.assert_not_called()
        mock_blade.post_management_access_policies_roles_permissions.assert_not_called()

    @patch("plugins.modules.purefb_mgmt_role.ManagementAccessPolicyRolePost")
    def test_create_role_failure_calls_fail_json(self, mock_post_cls):
        """Test _create_role surfaces backend errors via fail_json"""
        mock_module = Mock()
        mock_module.params = _base_params()
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.exit_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        post_res = Mock()
        post_res.status_code = 400
        post_res.errors = []
        mock_blade.post_management_access_policies_roles.return_value = post_res

        try:
            _create_role(mock_module, mock_blade, {})
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()
        assert "Failed to create role" in mock_module.fail_json.call_args[1]["msg"]

    # ================ _reconcile_permissions ================

    def test_reconcile_none_returns_false(self):
        """Test _reconcile_permissions returns False (untouched) when permissions is None"""
        mock_module = Mock()
        mock_module.params = _base_params(permissions=None)
        mock_module.check_mode = False

        mock_blade = Mock()
        assert _reconcile_permissions(mock_module, mock_blade, {}) is False
        mock_blade.get_management_access_policies_roles_permissions.assert_not_called()

    def test_reconcile_rejects_duplicate_resource(self):
        """Test _reconcile_permissions fails when the input has duplicate resources"""
        mock_module = Mock()
        mock_module.params = _base_params(
            permissions=[
                {"resource": "file-systems", "actions": ["get"]},
                {"resource": "file-systems", "actions": ["get"]},
            ]
        )
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        try:
            _reconcile_permissions(mock_module, mock_blade, {})
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()
        assert "Duplicate resource" in mock_module.fail_json.call_args[1]["msg"]

    @patch("plugins.modules.purefb_mgmt_role.ManagementAccessPolicyRolePermissionPost")
    def test_reconcile_adds_missing_permission(self, mock_perm_post_cls):
        """Test _reconcile_permissions POSTs permissions that are absent on the blade"""
        mock_module = Mock()
        mock_module.params = _base_params(
            permissions=[{"resource": "file-systems", "actions": ["get"]}]
        )
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        get_res = Mock()
        get_res.status_code = 200
        get_res.items = []
        mock_blade.get_management_access_policies_roles_permissions.return_value = (
            get_res
        )

        post_res = Mock()
        post_res.status_code = 200
        mock_blade.post_management_access_policies_roles_permissions.return_value = (
            post_res
        )

        changed = _reconcile_permissions(mock_module, mock_blade, {})

        assert changed is True
        mock_blade.post_management_access_policies_roles_permissions.assert_called_once()
        mock_blade.delete_management_access_policies_roles_permissions.assert_not_called()
        mock_blade.patch_management_access_policies_roles_permissions.assert_not_called()

    def test_reconcile_removes_orphan_permission(self):
        """Test _reconcile_permissions DELETEs permissions not in desired"""
        mock_module = Mock()
        mock_module.params = _base_params(
            permissions=[
                {"resource": "file-systems", "actions": ["get"]},
            ]
        )
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)

        keep = Mock()
        keep.name = "perm-keep"
        keep.resource = RESOURCE_PREFIX + "file-systems"
        keep.actions = ["get"]

        drop = Mock()
        drop.name = "perm-drop"
        drop.resource = RESOURCE_PREFIX + "orphan-resource"
        drop.actions = ["get"]

        mock_blade = Mock()
        get_res = Mock()
        get_res.status_code = 200
        get_res.items = [keep, drop]
        mock_blade.get_management_access_policies_roles_permissions.return_value = (
            get_res
        )

        del_res = Mock()
        del_res.status_code = 200
        mock_blade.delete_management_access_policies_roles_permissions.return_value = (
            del_res
        )

        changed = _reconcile_permissions(mock_module, mock_blade, {})

        assert changed is True
        mock_blade.delete_management_access_policies_roles_permissions.assert_called_once()
        call_kwargs = (
            mock_blade.delete_management_access_policies_roles_permissions.call_args[1]
        )
        assert call_kwargs["names"] == ["perm-drop"]
        # Permission names are globally unique; the delete endpoint takes
        # no role_names parameter (SDK rejects it).
        assert "role_names" not in call_kwargs

    @patch("plugins.modules.purefb_mgmt_role.ManagementAccessPolicyRolePermissionPatch")
    def test_reconcile_patches_changed_actions(self, mock_patch_cls):
        """Test _reconcile_permissions PATCHes when actions differ on the same resource"""
        mock_module = Mock()
        mock_module.params = _base_params(
            permissions=[
                {"resource": "file-systems", "actions": ["get", "post"]},
            ]
        )
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)

        current = Mock()
        current.name = "perm-fs"
        current.resource = RESOURCE_PREFIX + "file-systems"
        current.actions = ["get"]

        mock_blade = Mock()
        get_res = Mock()
        get_res.status_code = 200
        get_res.items = [current]
        mock_blade.get_management_access_policies_roles_permissions.return_value = (
            get_res
        )

        patch_res = Mock()
        patch_res.status_code = 200
        mock_blade.patch_management_access_policies_roles_permissions.return_value = (
            patch_res
        )

        changed = _reconcile_permissions(mock_module, mock_blade, {})

        assert changed is True
        mock_blade.patch_management_access_policies_roles_permissions.assert_called_once()
        assert mock_patch_cls.call_args[1]["actions"] == ["get", "post"]

    def test_reconcile_idempotent_when_match(self):
        """Test _reconcile_permissions is a no-op when actions and resources match"""
        mock_module = Mock()
        mock_module.params = _base_params(
            permissions=[{"resource": "file-systems", "actions": ["get"]}]
        )
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)

        current = Mock()
        current.name = "perm-fs"
        current.resource = RESOURCE_PREFIX + "file-systems"
        current.actions = ["get"]

        mock_blade = Mock()
        get_res = Mock()
        get_res.status_code = 200
        get_res.items = [current]
        mock_blade.get_management_access_policies_roles_permissions.return_value = (
            get_res
        )

        changed = _reconcile_permissions(mock_module, mock_blade, {})

        assert changed is False
        mock_blade.post_management_access_policies_roles_permissions.assert_not_called()
        mock_blade.delete_management_access_policies_roles_permissions.assert_not_called()
        mock_blade.patch_management_access_policies_roles_permissions.assert_not_called()

    def test_reconcile_short_and_fq_resource_are_equivalent(self):
        """Test _reconcile_permissions treats short and fully-qualified resource names as identical"""
        mock_module = Mock()
        mock_module.params = _base_params(
            # Short form on input
            permissions=[{"resource": "file-systems", "actions": ["get"]}]
        )
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)

        # Fully-qualified on the blade
        current = Mock()
        current.name = "perm-fs"
        current.resource = RESOURCE_PREFIX + "file-systems"
        current.actions = ["get"]

        mock_blade = Mock()
        get_res = Mock()
        get_res.status_code = 200
        get_res.items = [current]
        mock_blade.get_management_access_policies_roles_permissions.return_value = (
            get_res
        )

        changed = _reconcile_permissions(mock_module, mock_blade, {})
        assert changed is False

    def test_reconcile_check_mode_skips_writes(self):
        """Test _reconcile_permissions reports changed but skips writes in check mode"""
        mock_module = Mock()
        mock_module.params = _base_params(
            permissions=[{"resource": "file-systems", "actions": ["get"]}]
        )
        mock_module.check_mode = True
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        get_res = Mock()
        get_res.status_code = 200
        get_res.items = []
        mock_blade.get_management_access_policies_roles_permissions.return_value = (
            get_res
        )

        changed = _reconcile_permissions(mock_module, mock_blade, {})

        assert changed is True
        mock_blade.post_management_access_policies_roles_permissions.assert_not_called()

    def test_reconcile_empty_desired_removes_all(self):
        """Test _reconcile_permissions with permissions=[] removes every current permission"""
        mock_module = Mock()
        mock_module.params = _base_params(permissions=[])
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)

        current = Mock()
        current.name = "perm-fs"
        current.resource = RESOURCE_PREFIX + "file-systems"
        current.actions = ["get"]

        mock_blade = Mock()
        get_res = Mock()
        get_res.status_code = 200
        get_res.items = [current]
        mock_blade.get_management_access_policies_roles_permissions.return_value = (
            get_res
        )

        del_res = Mock()
        del_res.status_code = 200
        mock_blade.delete_management_access_policies_roles_permissions.return_value = (
            del_res
        )

        changed = _reconcile_permissions(mock_module, mock_blade, {})
        assert changed is True
        mock_blade.delete_management_access_policies_roles_permissions.assert_called_once()

    # ===== attachment helpers: _current_attached_policy_names / _subject_exists =====

    def test_current_attached_admin_returns_policy_names(self):
        """Test _current_attached_policy_names collects attached policy names for admin kind"""
        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach", admin="pureuser", policies=["p1"]
        )
        mock_module.fail_json = Mock(side_effect=SystemExit)

        m1 = Mock()
        m1.policy = Mock()
        m1.policy.name = "p1"
        m2 = Mock()
        m2.policy = Mock()
        m2.policy.name = "p2"

        mock_blade = Mock()
        res = Mock()
        res.status_code = 200
        res.items = [m1, m2]
        mock_blade.get_management_access_policies_admins.return_value = res

        out = _current_attached_policy_names(mock_module, mock_blade, "admin", {})
        assert out == {"p1", "p2"}
        mock_blade.get_management_access_policies_admins.assert_called_once_with(
            member_names=["pureuser"]
        )

    def test_current_attached_ds_returns_policy_names(self):
        """Test _current_attached_policy_names uses the DS endpoint for ds_role kind"""
        mock_module = Mock()
        mock_module.params = _base_params(
            object="ds_attach", ds_role="tenant-a-admins", policies=["p1"]
        )
        mock_module.fail_json = Mock(side_effect=SystemExit)

        m1 = Mock()
        m1.policy = Mock()
        m1.policy.name = "p1"

        mock_blade = Mock()
        res = Mock()
        res.status_code = 200
        res.items = [m1]
        mock_blade.get_management_access_policies_directory_services_roles.return_value = (
            res
        )

        out = _current_attached_policy_names(mock_module, mock_blade, "ds_role", {})
        assert out == {"p1"}
        mock_blade.get_management_access_policies_directory_services_roles.assert_called_once_with(
            member_names=["tenant-a-admins"]
        )

    def test_current_attached_fails_on_error(self):
        """Test _current_attached_policy_names fails on non-200 status"""
        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach", admin="pureuser", policies=["p1"]
        )
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        res = Mock()
        res.status_code = 400
        res.items = []
        mock_blade.get_management_access_policies_admins.return_value = res

        try:
            _current_attached_policy_names(mock_module, mock_blade, "admin", {})
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()

    def test_subject_exists_true_for_admin(self):
        """Test _subject_exists returns True when the admin exists"""
        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach", admin="pureuser", policies=["p1"]
        )

        mock_blade = Mock()
        res = Mock()
        res.status_code = 200
        res.items = [Mock()]
        mock_blade.get_admins.return_value = res

        assert _subject_exists(mock_module, mock_blade, "admin", {}) is True
        mock_blade.get_admins.assert_called_once_with(names=["pureuser"])
        mock_blade.get_directory_services_roles.assert_not_called()

    def test_subject_exists_true_for_ds_role(self):
        """Test _subject_exists returns True when the DS role mapping exists"""
        mock_module = Mock()
        mock_module.params = _base_params(
            object="ds_attach", ds_role="tenant-a-admins", policies=["p1"]
        )

        mock_blade = Mock()
        res = Mock()
        res.status_code = 200
        res.items = [Mock()]
        mock_blade.get_directory_services_roles.return_value = res

        assert _subject_exists(mock_module, mock_blade, "ds_role", {}) is True
        mock_blade.get_directory_services_roles.assert_called_once_with(
            names=["tenant-a-admins"]
        )
        mock_blade.get_admins.assert_not_called()

    def test_subject_exists_false_when_missing(self):
        """Test _subject_exists returns False when the admin is not found"""
        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach", admin="ghost", policies=["p1"]
        )

        mock_blade = Mock()
        res = Mock()
        res.status_code = 200
        res.items = []
        mock_blade.get_admins.return_value = res

        assert _subject_exists(mock_module, mock_blade, "admin", {}) is False

    def test_subject_exists_false_on_error(self):
        """Test _subject_exists returns False when the lookup errors"""
        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach", admin="ghost", policies=["p1"]
        )

        mock_blade = Mock()
        res = Mock()
        res.status_code = 400
        res.items = []
        mock_blade.get_admins.return_value = res

        assert _subject_exists(mock_module, mock_blade, "admin", {}) is False

    # ================ _handle_role dispatcher ================

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_role_fails_when_api_too_old(self, mock_loose_version):
        """Test _handle_role fails when the API is too old for custom roles"""
        # role gate: LooseVersion(MIN_ROLE_API_VERSION) > LooseVersion(api_version) → True
        mock_loose_version.return_value.__gt__ = Mock(return_value=True)

        mock_module = Mock()
        mock_module.params = _base_params()
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        try:
            _handle_role(mock_module, mock_blade, "2.19", {})
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()
        msg = mock_module.fail_json.call_args[1]["msg"]
        assert "does not support custom roles and permissions" in msg
        assert "2.26+" in msg

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_role_absent_noop_when_missing(self, mock_loose_version):
        """Test _handle_role state=absent is a no-op when the role doesn't exist"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(state="absent")
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        get_res = Mock()
        get_res.status_code = 200
        get_res.items = []
        mock_blade.get_management_access_policies_roles.return_value = get_res

        try:
            _handle_role(mock_module, mock_blade, "2.26", {})
        except SystemExit:
            pass

        assert mock_module.exit_json.call_args[1]["changed"] is False

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_role_reconciles_permissions_on_existing(self, mock_loose_version):
        """Test _handle_role reconciles permissions when the role already exists"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(permissions=None)
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        existing = Mock()

        mock_blade = Mock()
        get_res = Mock()
        get_res.status_code = 200
        get_res.items = [existing]
        mock_blade.get_management_access_policies_roles.return_value = get_res

        try:
            _handle_role(mock_module, mock_blade, "2.26", {})
        except SystemExit:
            pass

        # permissions=None → no reconcile activity, changed=False
        assert mock_module.exit_json.call_args[1]["changed"] is False

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_role_refuses_builtin_permissions_rewrite(self, mock_loose_version):
        """Test _handle_role fails fast when permissions target a built-in role"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(name="viewer", permissions=[])
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        existing = Mock()
        existing.pure_defined = True

        mock_blade = Mock()
        get_res = Mock()
        get_res.status_code = 200
        get_res.items = [existing]
        mock_blade.get_management_access_policies_roles.return_value = get_res

        try:
            _handle_role(mock_module, mock_blade, "2.26", {})
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()
        assert (
            "Built-in role viewer cannot be modified"
            in mock_module.fail_json.call_args[1]["msg"]
        )
        # The guard must fire before any reconcile read or write.
        mock_blade.get_management_access_policies_roles_permissions.assert_not_called()

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_role_builtin_existence_check_is_noop(self, mock_loose_version):
        """Test _handle_role without permissions is a changed=False no-op on a built-in role"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(name="viewer", permissions=None)
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        existing = Mock()
        existing.pure_defined = True

        mock_blade = Mock()
        get_res = Mock()
        get_res.status_code = 200
        get_res.items = [existing]
        mock_blade.get_management_access_policies_roles.return_value = get_res

        try:
            _handle_role(mock_module, mock_blade, "2.26", {})
        except SystemExit:
            pass

        mock_module.fail_json.assert_not_called()
        assert mock_module.exit_json.call_args[1]["changed"] is False

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_role_builtin_guard_ignores_custom_roles(self, mock_loose_version):
        """Test the built-in guard lets permissions reconcile proceed on a custom role"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(name="backup-operator", permissions=[])
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        existing = Mock()
        existing.pure_defined = False

        perm = Mock()
        perm.name = "backup-operator.1"
        perm.resource = RESOURCE_PREFIX + "file-systems"
        perm.actions = ["get"]

        mock_blade = Mock()
        get_role_res = Mock()
        get_role_res.status_code = 200
        get_role_res.items = [existing]
        mock_blade.get_management_access_policies_roles.return_value = get_role_res

        get_perm_res = Mock()
        get_perm_res.status_code = 200
        get_perm_res.items = [perm]
        mock_blade.get_management_access_policies_roles_permissions.return_value = (
            get_perm_res
        )

        del_res = Mock()
        del_res.status_code = 200
        mock_blade.delete_management_access_policies_roles_permissions.return_value = (
            del_res
        )

        try:
            _handle_role(mock_module, mock_blade, "2.26", {})
        except SystemExit:
            pass

        mock_module.fail_json.assert_not_called()
        mock_blade.delete_management_access_policies_roles_permissions.assert_called_once()
        assert mock_module.exit_json.call_args[1]["changed"] is True

    # ================ _handle_attach ================

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_fails_when_api_too_old(self, mock_loose_version):
        """Test _handle_attach fails when the API is older than the attach version"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=True)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach", admin="pureuser", policies=["p1"]
        )
        mock_module.check_mode = False
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        try:
            _handle_attach(mock_module, mock_blade, "2.18", {}, "admin")
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()
        msg = mock_module.fail_json.call_args[1]["msg"]
        assert "does not support management access policy attachment" in msg
        assert "2.19+" in msg

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_present_fails_when_subject_missing(self, mock_loose_version):
        """Test _handle_attach state=present fails when the admin does not exist"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="present",
            admin="ghost",
            policies=["p1"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = []
        mock_blade.get_admins.return_value = admins_res

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()
        assert "admin ghost does not exist" in mock_module.fail_json.call_args[1]["msg"]

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_absent_noop_when_subject_missing(self, mock_loose_version):
        """Test _handle_attach state=absent is an idempotent no-op on a missing admin"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="absent",
            admin="ghost",
            policies=["p1"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = []
        mock_blade.get_admins.return_value = admins_res

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        mock_module.fail_json.assert_not_called()
        assert mock_module.exit_json.call_args[1]["changed"] is False
        # Nothing can be attached to a missing subject — no policy calls.
        mock_blade.get_management_access_policies_admins.assert_not_called()
        mock_blade.delete_management_access_policies_admins.assert_not_called()

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_present_case_variant_is_noop(self, mock_loose_version):
        """Test _handle_attach state=present matches attached policies case-insensitively"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="present",
            admin="pureuser",
            policies=["TENANT-A-OPS"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = [Mock()]
        mock_blade.get_admins.return_value = admins_res

        existing = Mock()
        existing.policy = Mock()
        existing.policy.name = "Tenant-A-Ops"
        current_res = Mock()
        current_res.status_code = 200
        current_res.items = [existing]
        mock_blade.get_management_access_policies_admins.return_value = current_res

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        mock_blade.post_management_access_policies_admins.assert_not_called()
        mock_blade.delete_management_access_policies_admins.assert_not_called()
        assert mock_module.exit_json.call_args[1]["changed"] is False

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_absent_case_variant_detaches_canonical(
        self, mock_loose_version
    ):
        """Test _handle_attach state=absent detaches a case variant using the array's spelling"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="absent",
            admin="pureuser",
            policies=["TENANT-A-OPS"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = [Mock()]
        mock_blade.get_admins.return_value = admins_res

        existing = Mock()
        existing.policy = Mock()
        existing.policy.name = "Tenant-A-Ops"
        current_res = Mock()
        current_res.status_code = 200
        current_res.items = [existing]
        mock_blade.get_management_access_policies_admins.return_value = current_res

        ok = Mock()
        ok.status_code = 200
        mock_blade.delete_management_access_policies_admins.return_value = ok

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        mock_blade.delete_management_access_policies_admins.assert_called_once_with(
            member_names=["pureuser"], policy_names=["Tenant-A-Ops"]
        )
        assert mock_module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_dedupes_case_variant_requests(self, mock_loose_version):
        """Test _handle_attach collapses case-variant duplicates in the policies list"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="present",
            admin="pureuser",
            policies=["p1", "P1"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = [Mock()]
        mock_blade.get_admins.return_value = admins_res

        current_res = Mock()
        current_res.status_code = 200
        current_res.items = []
        mock_blade.get_management_access_policies_admins.return_value = current_res

        ok = Mock()
        ok.status_code = 200
        mock_blade.post_management_access_policies_admins.return_value = ok

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        # One POST with a single spelling (first occurrence wins).
        mock_blade.post_management_access_policies_admins.assert_called_once_with(
            member_names=["pureuser"], policy_names=["p1"]
        )
        assert mock_module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_present_fails_when_ds_role_missing(self, mock_loose_version):
        """Test _handle_attach state=present fails when the DS role mapping does not exist"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="ds_attach",
            state="present",
            ds_role="ghost-mapping",
            policies=["p1"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        ds_res = Mock()
        ds_res.status_code = 200
        ds_res.items = []
        mock_blade.get_directory_services_roles.return_value = ds_res

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "ds_role")
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()
        assert (
            "ds_role ghost-mapping does not exist"
            in mock_module.fail_json.call_args[1]["msg"]
        )

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_absent_noop_when_ds_role_missing(self, mock_loose_version):
        """Test _handle_attach state=absent is an idempotent no-op on a missing DS role"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="ds_attach",
            state="absent",
            ds_role="ghost-mapping",
            policies=["p1"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()
        ds_res = Mock()
        ds_res.status_code = 200
        ds_res.items = []
        mock_blade.get_directory_services_roles.return_value = ds_res

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "ds_role")
        except SystemExit:
            pass

        mock_module.fail_json.assert_not_called()
        assert mock_module.exit_json.call_args[1]["changed"] is False
        mock_blade.get_management_access_policies_directory_services_roles.assert_not_called()
        mock_blade.delete_management_access_policies_directory_services_roles.assert_not_called()

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_check_mode_case_variant_is_noop(self, mock_loose_version):
        """Test check_mode reports changed=False when the request is already satisfied case-insensitively"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="present",
            admin="pureuser",
            policies=["TENANT-A-OPS"],
        )
        mock_module.check_mode = True
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = [Mock()]
        mock_blade.get_admins.return_value = admins_res

        existing = Mock()
        existing.policy = Mock()
        existing.policy.name = "Tenant-A-Ops"
        current_res = Mock()
        current_res.status_code = 200
        current_res.items = [existing]
        mock_blade.get_management_access_policies_admins.return_value = current_res

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        # The empty-diff exit must win over the check_mode changed=True exit.
        assert mock_module.exit_json.call_args[1]["changed"] is False
        mock_blade.post_management_access_policies_admins.assert_not_called()

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_mixed_list_posts_only_new_with_user_spelling(
        self, mock_loose_version
    ):
        """Test a case-variant match is excluded from the POST while a new policy keeps the user's spelling"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="present",
            admin="pureuser",
            policies=["TENANT-A-OPS", "New-Pol"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = [Mock()]
        mock_blade.get_admins.return_value = admins_res

        existing = Mock()
        existing.policy = Mock()
        existing.policy.name = "Tenant-A-Ops"
        current_res = Mock()
        current_res.status_code = 200
        current_res.items = [existing]
        mock_blade.get_management_access_policies_admins.return_value = current_res

        ok = Mock()
        ok.status_code = 200
        mock_blade.post_management_access_policies_admins.return_value = ok

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        # Only the genuinely new policy, in the user's spelling — neither the
        # matched variant nor any lowercased key may leak into the POST.
        mock_blade.post_management_access_policies_admins.assert_called_once_with(
            member_names=["pureuser"], policy_names=["New-Pol"]
        )
        assert mock_module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_ds_absent_detaches_canonical(self, mock_loose_version):
        """Test ds_attach state=absent detaches via the DS endpoint using the array's spelling"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="ds_attach",
            state="absent",
            ds_role="tenant-a-admins",
            policies=["TENANT-A-OPS"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        ds_res = Mock()
        ds_res.status_code = 200
        ds_res.items = [Mock()]
        mock_blade.get_directory_services_roles.return_value = ds_res

        existing = Mock()
        existing.policy = Mock()
        existing.policy.name = "Tenant-A-Ops"
        current_res = Mock()
        current_res.status_code = 200
        current_res.items = [existing]
        mock_blade.get_management_access_policies_directory_services_roles.return_value = (
            current_res
        )

        ok = Mock()
        ok.status_code = 200
        mock_blade.delete_management_access_policies_directory_services_roles.return_value = (
            ok
        )

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "ds_role")
        except SystemExit:
            pass

        mock_blade.delete_management_access_policies_directory_services_roles.assert_called_once_with(
            member_names=["tenant-a-admins"], policy_names=["Tenant-A-Ops"]
        )
        mock_blade.post_management_access_policies_directory_services_roles.assert_not_called()
        assert mock_module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_post_failure_calls_fail_json(self, mock_loose_version):
        """Test a non-200 attach POST surfaces as 'Failed to attach policies'"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="present",
            admin="pureuser",
            policies=["p1"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = [Mock()]
        mock_blade.get_admins.return_value = admins_res

        current_res = Mock()
        current_res.status_code = 200
        current_res.items = []
        mock_blade.get_management_access_policies_admins.return_value = current_res

        bad = Mock()
        bad.status_code = 400
        bad.errors = []
        mock_blade.post_management_access_policies_admins.return_value = bad

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()
        msg = mock_module.fail_json.call_args[1]["msg"]
        assert "Failed to attach policies" in msg
        assert "['p1']" in msg
        assert "admin pureuser" in msg

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_delete_failure_calls_fail_json(self, mock_loose_version):
        """Test a non-200 detach DELETE surfaces as 'Failed to detach policies'"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="absent",
            admin="pureuser",
            policies=["p1"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = [Mock()]
        mock_blade.get_admins.return_value = admins_res

        existing = Mock()
        existing.policy = Mock()
        existing.policy.name = "p1"
        current_res = Mock()
        current_res.status_code = 200
        current_res.items = [existing]
        mock_blade.get_management_access_policies_admins.return_value = current_res

        bad = Mock()
        bad.status_code = 400
        bad.errors = []
        mock_blade.delete_management_access_policies_admins.return_value = bad

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()
        msg = mock_module.fail_json.call_args[1]["msg"]
        assert "Failed to detach policies" in msg
        assert "['p1']" in msg
        assert "admin pureuser" in msg

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_attaches_new_policy(self, mock_loose_version):
        """Test _handle_attach POSTs the diff of desired-vs-current when state=present"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="present",
            admin="pureuser",
            policies=["p1", "p2"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = [Mock()]
        mock_blade.get_admins.return_value = admins_res

        # p1 already attached; p2 not attached → we should only add p2
        existing = Mock()
        existing.policy = Mock()
        existing.policy.name = "p1"
        current_res = Mock()
        current_res.status_code = 200
        current_res.items = [existing]
        mock_blade.get_management_access_policies_admins.return_value = current_res

        ok = Mock()
        ok.status_code = 200
        mock_blade.post_management_access_policies_admins.return_value = ok

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        mock_blade.post_management_access_policies_admins.assert_called_once_with(
            member_names=["pureuser"], policy_names=["p2"]
        )
        mock_blade.delete_management_access_policies_admins.assert_not_called()
        assert mock_module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_present_noop_when_all_attached(self, mock_loose_version):
        """Test _handle_attach state=present is a no-op when everything requested is already attached"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="present",
            admin="pureuser",
            policies=["p1"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = [Mock()]
        mock_blade.get_admins.return_value = admins_res

        existing = Mock()
        existing.policy = Mock()
        existing.policy.name = "p1"
        current_res = Mock()
        current_res.status_code = 200
        current_res.items = [existing]
        mock_blade.get_management_access_policies_admins.return_value = current_res

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        mock_blade.post_management_access_policies_admins.assert_not_called()
        mock_blade.delete_management_access_policies_admins.assert_not_called()
        assert mock_module.exit_json.call_args[1]["changed"] is False

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_absent_detaches_intersection(self, mock_loose_version):
        """Test _handle_attach state=absent DELETEs only the intersection of requested and current"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="absent",
            admin="pureuser",
            policies=["p1", "p3"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = [Mock()]
        mock_blade.get_admins.return_value = admins_res

        # Current: p1 and p2. Requested detach: p1 and p3.
        # Only p1 should be detached.
        e1 = Mock()
        e1.policy = Mock()
        e1.policy.name = "p1"
        e2 = Mock()
        e2.policy = Mock()
        e2.policy.name = "p2"
        current_res = Mock()
        current_res.status_code = 200
        current_res.items = [e1, e2]
        mock_blade.get_management_access_policies_admins.return_value = current_res

        ok = Mock()
        ok.status_code = 200
        mock_blade.delete_management_access_policies_admins.return_value = ok

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        mock_blade.delete_management_access_policies_admins.assert_called_once_with(
            member_names=["pureuser"], policy_names=["p1"]
        )
        mock_blade.post_management_access_policies_admins.assert_not_called()
        assert mock_module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_absent_noop_when_not_attached(self, mock_loose_version):
        """Test _handle_attach state=absent is a no-op when nothing requested is currently attached"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="absent",
            admin="pureuser",
            policies=["p1"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = [Mock()]
        mock_blade.get_admins.return_value = admins_res

        current_res = Mock()
        current_res.status_code = 200
        current_res.items = []
        mock_blade.get_management_access_policies_admins.return_value = current_res

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        mock_blade.post_management_access_policies_admins.assert_not_called()
        mock_blade.delete_management_access_policies_admins.assert_not_called()
        assert mock_module.exit_json.call_args[1]["changed"] is False

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_ds_role_uses_ds_endpoint(self, mock_loose_version):
        """Test _handle_attach on ds_role kind hits the DS-role endpoints"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="ds_attach",
            state="present",
            ds_role="tenant-a-admins",
            policies=["p1"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        ds_res = Mock()
        ds_res.status_code = 200
        ds_res.items = [Mock()]
        mock_blade.get_directory_services_roles.return_value = ds_res

        current_res = Mock()
        current_res.status_code = 200
        current_res.items = []
        mock_blade.get_management_access_policies_directory_services_roles.return_value = (
            current_res
        )

        ok = Mock()
        ok.status_code = 200
        mock_blade.post_management_access_policies_directory_services_roles.return_value = (
            ok
        )

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "ds_role")
        except SystemExit:
            pass

        mock_blade.post_management_access_policies_directory_services_roles.assert_called_once_with(
            member_names=["tenant-a-admins"], policy_names=["p1"]
        )
        mock_blade.post_management_access_policies_admins.assert_not_called()

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_check_mode_skips_writes(self, mock_loose_version):
        """Test _handle_attach reports changed but skips writes in check mode"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="present",
            admin="pureuser",
            policies=["p1"],
        )
        mock_module.check_mode = True
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = [Mock()]
        mock_blade.get_admins.return_value = admins_res

        current_res = Mock()
        current_res.status_code = 200
        current_res.items = []
        mock_blade.get_management_access_policies_admins.return_value = current_res

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        mock_blade.post_management_access_policies_admins.assert_not_called()
        assert mock_module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    def test_handle_attach_deduplicates_policies(self, mock_loose_version):
        """Test _handle_attach silently deduplicates a repeated policy name"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.params = _base_params(
            object="admin_attach",
            state="present",
            admin="pureuser",
            policies=["p1", "p1"],
        )
        mock_module.check_mode = False
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)

        mock_blade = Mock()

        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = [Mock()]
        mock_blade.get_admins.return_value = admins_res

        current_res = Mock()
        current_res.status_code = 200
        current_res.items = []
        mock_blade.get_management_access_policies_admins.return_value = current_res

        ok = Mock()
        ok.status_code = 200
        mock_blade.post_management_access_policies_admins.return_value = ok

        try:
            _handle_attach(mock_module, mock_blade, "2.26", {}, "admin")
        except SystemExit:
            pass

        mock_blade.post_management_access_policies_admins.assert_called_once_with(
            member_names=["pureuser"], policy_names=["p1"]
        )

    # ================ end-to-end main() ================

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    @patch("plugins.modules.purefb_mgmt_role.ManagementAccessPolicyRolePost")
    @patch("plugins.modules.purefb_mgmt_role.get_system")
    @patch("plugins.modules.purefb_mgmt_role.AnsibleModule")
    @patch("plugins.modules.purefb_mgmt_role.HAS_PYPURECLIENT", True)
    def test_main_creates_role(
        self,
        mock_ansible_module,
        mock_get_system,
        mock_post_cls,
        mock_loose_version,
    ):
        """Test main creates a new custom role"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.params = _base_params()
        mock_module.check_mode = False
        mock_ansible_module.return_value = mock_module

        mock_blade = Mock()
        mock_blade.get_versions.return_value.items = ["2.26"]
        mock_get_system.return_value = mock_blade

        # Role doesn't exist
        get_res = Mock()
        get_res.status_code = 200
        get_res.items = []
        mock_blade.get_management_access_policies_roles.return_value = get_res

        # Create succeeds
        post_res = Mock()
        post_res.status_code = 200
        mock_blade.post_management_access_policies_roles.return_value = post_res

        try:
            main()
        except SystemExit:
            pass

        mock_blade.post_management_access_policies_roles.assert_called_once()
        assert mock_module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    @patch("plugins.modules.purefb_mgmt_role.get_system")
    @patch("plugins.modules.purefb_mgmt_role.AnsibleModule")
    @patch("plugins.modules.purefb_mgmt_role.HAS_PYPURECLIENT", True)
    def test_main_absent_role_when_missing_is_noop(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test main is a no-op when state=absent and the role doesn't exist"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.params = _base_params(state="absent")
        mock_module.check_mode = False
        mock_ansible_module.return_value = mock_module

        mock_blade = Mock()
        mock_blade.get_versions.return_value.items = ["2.26"]
        mock_get_system.return_value = mock_blade

        get_res = Mock()
        get_res.status_code = 200
        get_res.items = []
        mock_blade.get_management_access_policies_roles.return_value = get_res

        try:
            main()
        except SystemExit:
            pass

        mock_blade.delete_management_access_policies_roles.assert_not_called()
        assert mock_module.exit_json.call_args[1]["changed"] is False

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    @patch("plugins.modules.purefb_mgmt_role.get_system")
    @patch("plugins.modules.purefb_mgmt_role.AnsibleModule")
    @patch("plugins.modules.purefb_mgmt_role.HAS_PYPURECLIENT", True)
    def test_main_deletes_existing_role(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test main deletes an existing custom role when nothing references it"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.params = _base_params(state="absent")
        mock_module.check_mode = False
        mock_ansible_module.return_value = mock_module

        mock_blade = Mock()
        mock_blade.get_versions.return_value.items = ["2.26"]
        mock_get_system.return_value = mock_blade

        existing = Mock()
        existing.pure_defined = False
        get_res = Mock()
        get_res.status_code = 200
        get_res.items = [existing]
        mock_blade.get_management_access_policies_roles.return_value = get_res

        rules_res = Mock()
        rules_res.status_code = 200
        rules_res.items = []
        mock_blade.get_management_access_policies_rules.return_value = rules_res

        delete_res = Mock()
        delete_res.status_code = 200
        mock_blade.delete_management_access_policies_roles.return_value = delete_res

        try:
            main()
        except SystemExit:
            pass

        mock_blade.delete_management_access_policies_roles.assert_called_once_with(
            names=["backup-operator"]
        )
        assert mock_module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    @patch("plugins.modules.purefb_mgmt_role.get_system")
    @patch("plugins.modules.purefb_mgmt_role.AnsibleModule")
    @patch("plugins.modules.purefb_mgmt_role.HAS_PYPURECLIENT", True)
    def test_main_admin_attach_uses_admin_endpoint(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test main dispatches object=admin_attach to the admin endpoints"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.params = _base_params(
            object="admin_attach",
            state="present",
            name=None,
            admin="pureuser",
            policies=["tenant-a-ops"],
        )
        mock_module.check_mode = False
        mock_ansible_module.return_value = mock_module

        mock_blade = Mock()
        mock_blade.get_versions.return_value.items = ["2.26"]
        mock_get_system.return_value = mock_blade

        admins_res = Mock()
        admins_res.status_code = 200
        admins_res.items = [Mock()]
        mock_blade.get_admins.return_value = admins_res

        current_res = Mock()
        current_res.status_code = 200
        current_res.items = []
        mock_blade.get_management_access_policies_admins.return_value = current_res

        ok = Mock()
        ok.status_code = 200
        mock_blade.post_management_access_policies_admins.return_value = ok

        try:
            main()
        except SystemExit:
            pass

        mock_blade.post_management_access_policies_admins.assert_called_once_with(
            member_names=["pureuser"], policy_names=["tenant-a-ops"]
        )
        assert mock_module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_mgmt_role.LooseVersion")
    @patch("plugins.modules.purefb_mgmt_role.get_system")
    @patch("plugins.modules.purefb_mgmt_role.AnsibleModule")
    @patch("plugins.modules.purefb_mgmt_role.HAS_PYPURECLIENT", True)
    def test_main_ds_attach_uses_ds_endpoint(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test main dispatches object=ds_attach to the directory-service endpoints"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)

        mock_module = Mock()
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.params = _base_params(
            object="ds_attach",
            state="present",
            name=None,
            ds_role="tenant-a-admins",
            policies=["tenant-a-ops"],
        )
        mock_module.check_mode = False
        mock_ansible_module.return_value = mock_module

        mock_blade = Mock()
        mock_blade.get_versions.return_value.items = ["2.26"]
        mock_get_system.return_value = mock_blade

        ds_res = Mock()
        ds_res.status_code = 200
        ds_res.items = [Mock()]
        mock_blade.get_directory_services_roles.return_value = ds_res

        current_res = Mock()
        current_res.status_code = 200
        current_res.items = []
        mock_blade.get_management_access_policies_directory_services_roles.return_value = (
            current_res
        )

        ok = Mock()
        ok.status_code = 200
        mock_blade.post_management_access_policies_directory_services_roles.return_value = (
            ok
        )

        try:
            main()
        except SystemExit:
            pass

        mock_blade.post_management_access_policies_directory_services_roles.assert_called_once_with(
            member_names=["tenant-a-admins"], policy_names=["tenant-a-ops"]
        )
        assert mock_module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_mgmt_role.get_system")
    @patch("plugins.modules.purefb_mgmt_role.AnsibleModule")
    @patch("plugins.modules.purefb_mgmt_role.HAS_PYPURECLIENT", False)
    def test_main_fails_when_sdk_missing(self, mock_ansible_module, mock_get_system):
        """Test main fails clearly when py-pure-client is not installed"""
        mock_module = Mock()
        mock_module.fail_json = Mock(side_effect=SystemExit)
        mock_module.exit_json = Mock(side_effect=SystemExit)
        mock_module.params = _base_params()
        mock_module.check_mode = False
        mock_ansible_module.return_value = mock_module

        try:
            main()
        except SystemExit:
            pass

        mock_module.fail_json.assert_called_once()
        assert (
            "py-pure-client sdk is required"
            in mock_module.fail_json.call_args[1]["msg"]
        )

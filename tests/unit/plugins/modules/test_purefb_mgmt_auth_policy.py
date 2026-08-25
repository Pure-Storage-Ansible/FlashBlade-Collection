# Copyright: (c) 2026, Pure Storage Ansible Team <pure-ansible-team@everpuredata.com>
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for purefb_mgmt_auth_policy module."""

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

from plugins.modules.purefb_mgmt_auth_policy import (
    main,
    _ctx,
    _validate_methods,
    _validate_members,
    _get_policy,
    _get_members,
    _get_member_current_policy,
    _desired_ssh_config,
    _current_ssh_config,
    _build_ssh_config,
    reconcile_members,
    create_policy,
    update_policy,
    delete_policy,
)


def _base_params(**overrides):
    """Return a full params dict with sane defaults, patched by overrides."""
    params = {
        "name": "ssh-mfa",
        "state": "present",
        "enabled": None,
        "ssh_allowed_methods": None,
        "ssh_required_methods": None,
        "members": None,
        "replace_existing": False,
        "context": "",
    }
    params.update(overrides)
    return params


def _mock_module(**overrides):
    """Mock AnsibleModule with SystemExit-raising exit/fail hooks."""
    module = Mock()
    module.params = _base_params(**overrides)
    module.check_mode = False
    module.fail_json = Mock(side_effect=SystemExit)
    module.exit_json = Mock(side_effect=SystemExit)
    module.warn = Mock()
    return module


def _mock_policy(enabled=True, allowed=None, required=None):
    """Mock policy object as returned by the get endpoint (inactive mode
    reads back as an empty list, mirroring the array)."""
    policy = Mock()
    policy.name = "ssh-mfa"
    policy.enabled = enabled
    policy.ssh = Mock()
    policy.ssh.allowed_methods = allowed if allowed is not None else []
    policy.ssh.required_methods = required if required is not None else []
    return policy


def _member_item(policy_name, resource_type, member_name):
    item = Mock()
    item.policy = Mock()
    item.policy.name = policy_name
    item.member = Mock()
    item.member.resource_type = resource_type
    item.member.name = member_name
    return item


def _ok_response(items=None):
    response = Mock()
    response.status_code = 200
    response.items = items if items is not None else []
    return response


def _members_side_effect(policy_members, member_policy_map):
    """Route the shared members GET: policy_names filter returns the
    policy's members; member_names filter answers conflict lookups."""

    def _side_effect(**kwargs):
        if "policy_names" in kwargs:
            return _ok_response(list(policy_members))
        name = kwargs["member_names"][0]
        rtype = kwargs["member_types"][0]
        attached_to = member_policy_map.get(name)
        if attached_to is None:
            return _ok_response([])
        return _ok_response([_member_item(attached_to, rtype, name)])

    return _side_effect


def _members_exist(mock_blade, arrays=("fb1",)):
    """Stub the existence lookups: every admin exists, plus the given arrays."""
    mock_blade.get_admins.return_value = _ok_response([Mock()])
    items = []
    for name in arrays:
        array = Mock()
        array.name = name
        items.append(array)
    mock_blade.get_arrays.return_value = _ok_response(items)


class TestPurefbMgmtAuthPolicy:
    """Test cases for purefb_mgmt_auth_policy module"""

    # ==== _ctx ====

    def test_ctx_empty_when_context_unset(self):
        """Test _ctx returns {} when context is empty string"""
        mock_module = Mock()
        mock_module.params = {"context": ""}
        assert _ctx(mock_module, "2.22") == {}

    @patch("plugins.modules.purefb_mgmt_auth_policy.LooseVersion")
    def test_ctx_returns_context_names_when_supported(self, mock_loose_version):
        """Test _ctx returns context_names dict when API supports it"""
        mock_loose_version.return_value.__le__ = Mock(return_value=True)
        mock_module = Mock()
        mock_module.params = {"context": "fleet1"}
        assert _ctx(mock_module, "2.22") == {"context_names": ["fleet1"]}

    @patch("plugins.modules.purefb_mgmt_auth_policy.LooseVersion")
    def test_ctx_silently_drops_context_when_api_too_old(self, mock_loose_version):
        """Test _ctx returns {} when API is too old, even if context is set"""
        mock_loose_version.return_value.__le__ = Mock(return_value=False)
        mock_module = Mock()
        mock_module.params = {"context": "fleet1"}
        assert _ctx(mock_module, "2.16") == {}

    # ==== method validation ====
    # Choice enforcement ('default' only in allowed) and the allowed/required
    # mutual exclusion live in the argument spec, so helpers only cover the
    # rules the spec cannot express.

    def test_validate_methods_noop_when_omitted(self):
        """Test _validate_methods passes when neither method list is supplied"""
        mock_module = _mock_module()
        _validate_methods(mock_module)
        mock_module.fail_json.assert_not_called()

    def test_validate_methods_rejects_empty_list(self):
        """Test _validate_methods rejects an explicit empty method list"""
        mock_module = _mock_module(ssh_allowed_methods=[])
        try:
            _validate_methods(mock_module)
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "at least one method" in mock_module.fail_json.call_args[1]["msg"]

    def test_validate_methods_rejects_duplicates(self):
        """Test _validate_methods rejects a duplicated method"""
        mock_module = _mock_module(ssh_required_methods=["password", "password"])
        try:
            _validate_methods(mock_module)
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "Duplicate method" in mock_module.fail_json.call_args[1]["msg"]

    def test_validate_methods_accepts_valid_list(self):
        """Test _validate_methods passes a valid required list"""
        mock_module = _mock_module(ssh_required_methods=["password", "key"])
        _validate_methods(mock_module)
        mock_module.fail_json.assert_not_called()

    # ==== member validation ====

    def test_validate_members_noop_when_omitted(self):
        """Test _validate_members passes when members is omitted"""
        mock_module = _mock_module()
        _validate_members(mock_module)
        mock_module.fail_json.assert_not_called()

    def test_validate_members_rejects_duplicates(self):
        """Test _validate_members rejects duplicate (name, type) entries"""
        mock_module = _mock_module(
            members=[
                {"name": "alice", "type": "admin"},
                {"name": "alice", "type": "admin"},
            ]
        )
        try:
            _validate_members(mock_module)
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "Duplicate member" in mock_module.fail_json.call_args[1]["msg"]

    def test_validate_members_rejects_multiple_arrays(self):
        """Test _validate_members rejects more than one array member"""
        mock_module = _mock_module(
            members=[
                {"name": "fb1", "type": "array"},
                {"name": "fb2", "type": "array"},
            ]
        )
        try:
            _validate_members(mock_module)
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "at most one array" in mock_module.fail_json.call_args[1]["msg"]

    def test_validate_members_rejects_protected_admins(self):
        """Test _validate_members rejects exempt users, case-insensitively"""
        for name in ("ir", "Pureeng"):
            mock_module = _mock_module(members=[{"name": name, "type": "admin"}])
            try:
                _validate_members(mock_module)
            except SystemExit:
                pass
            mock_module.fail_json.assert_called_once()
            assert "exempt" in mock_module.fail_json.call_args[1]["msg"]

    def test_validate_members_accepts_valid_list(self):
        """Test _validate_members passes admins plus one array"""
        mock_module = _mock_module(
            members=[
                {"name": "alice", "type": "admin"},
                {"name": "fb1", "type": "array"},
            ]
        )
        _validate_members(mock_module)
        mock_module.fail_json.assert_not_called()

    # ==== ssh config helpers ====

    def test_desired_ssh_config_allowed_mode(self):
        """Test _desired_ssh_config maps the allowed list"""
        mock_module = _mock_module(ssh_allowed_methods=["password", "key"])
        assert _desired_ssh_config(mock_module) == ("allowed", {"password", "key"})

    def test_desired_ssh_config_required_mode(self):
        """Test _desired_ssh_config maps the required list"""
        mock_module = _mock_module(ssh_required_methods=["key"])
        assert _desired_ssh_config(mock_module) == ("required", {"key"})

    def test_desired_ssh_config_none_when_omitted(self):
        """Test _desired_ssh_config returns None when neither list is set"""
        mock_module = _mock_module()
        assert _desired_ssh_config(mock_module) is None

    def test_current_ssh_config_reads_modes(self):
        """Test _current_ssh_config picks the non-empty mode"""
        assert _current_ssh_config(_mock_policy(required=["key", "password"])) == (
            "required",
            {"key", "password"},
        )
        assert _current_ssh_config(_mock_policy(allowed=["default"])) == (
            "allowed",
            {"default"},
        )

    @patch(
        "plugins.modules.purefb_mgmt_auth_policy.ManagementAuthenticationPolicyConfig"
    )
    def test_build_ssh_config_clears_opposite_mode(self, mock_config_cls):
        """Test _build_ssh_config always sends the opposite list as []"""
        _build_ssh_config("allowed", {"key", "password"})
        assert mock_config_cls.call_args[1] == {
            "allowed_methods": ["key", "password"],
            "required_methods": [],
        }
        _build_ssh_config("required", {"password"})
        assert mock_config_cls.call_args[1] == {
            "allowed_methods": [],
            "required_methods": ["password"],
        }

    # ==== read helpers ====

    def test_get_policy_found(self):
        """Test _get_policy returns the policy object"""
        mock_module = _mock_module()
        policy = _mock_policy()
        mock_blade = Mock()
        mock_blade.get_management_authentication_policies.return_value = _ok_response(
            [policy]
        )
        assert _get_policy(mock_module, mock_blade, {}) is policy

    @patch("plugins.modules.purefb_mgmt_auth_policy.get_error_message")
    def test_get_policy_not_found(self, mock_gem):
        """Test _get_policy returns None only for the not-found 400"""
        mock_gem.return_value = "Management authentication policy does not exist."
        mock_module = _mock_module()
        error = Mock()
        error.status_code = 400
        mock_blade = Mock()
        mock_blade.get_management_authentication_policies.return_value = error
        assert _get_policy(mock_module, mock_blade, {}) is None
        mock_module.fail_json.assert_not_called()

    @patch("plugins.modules.purefb_mgmt_auth_policy.get_error_message")
    def test_get_policy_transient_error_fails(self, mock_gem):
        """Test _get_policy fails loudly on errors other than not-found,
        instead of letting state=absent report ok on a transient error"""
        mock_gem.return_value = "Internal server error"
        mock_module = _mock_module()
        error = Mock()
        error.status_code = 500
        mock_blade = Mock()
        mock_blade.get_management_authentication_policies.return_value = error
        try:
            _get_policy(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        msg = mock_module.fail_json.call_args[1]["msg"]
        assert "Failed to read policy" in msg
        assert "Internal server error" in msg

    def test_get_members_maps_resource_types(self):
        """Test _get_members maps API resource types to module member types"""
        mock_module = _mock_module()
        mock_blade = Mock()
        mock_blade.get_management_authentication_policies_members.return_value = (
            _ok_response(
                [
                    _member_item("ssh-mfa", "admins", "alice"),
                    _member_item("ssh-mfa", "arrays", "fb1"),
                ]
            )
        )
        assert _get_members(mock_module, mock_blade, {}) == {
            ("admin", "alice"),
            ("array", "fb1"),
        }

    def test_get_members_error_fails(self):
        """Test _get_members fails the task when the list call errors"""
        mock_module = _mock_module()
        error = Mock()
        error.status_code = 400
        error.errors = []
        mock_blade = Mock()
        mock_blade.get_management_authentication_policies_members.return_value = error
        try:
            _get_members(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()

    def test_get_member_current_policy(self):
        """Test _get_member_current_policy returns the attached policy or None"""
        mock_module = _mock_module()
        mock_blade = Mock()
        mock_blade.get_management_authentication_policies_members.return_value = (
            _ok_response([_member_item("other-policy", "admins", "alice")])
        )
        assert (
            _get_member_current_policy(mock_module, mock_blade, "admin", "alice", {})
            == "other-policy"
        )
        mock_blade.get_management_authentication_policies_members.return_value = (
            _ok_response([])
        )
        assert (
            _get_member_current_policy(mock_module, mock_blade, "admin", "bob", {})
            is None
        )

    def test_get_member_current_policy_lookup_error_fails(self):
        """Test a failed conflict lookup fails loudly instead of reading as
        'no conflict'"""
        mock_module = _mock_module()
        mock_blade = Mock()
        error = Mock()
        error.status_code = 400
        error.errors = []
        mock_blade.get_management_authentication_policies_members.return_value = error
        try:
            _get_member_current_policy(mock_module, mock_blade, "admin", "alice", {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert (
            "Failed to look up current policy"
            in mock_module.fail_json.call_args[1]["msg"]
        )

    # ==== reconcile_members ====

    def test_reconcile_members_noop_when_omitted(self):
        """Test reconcile_members does nothing when members is omitted"""
        mock_module = _mock_module()
        mock_blade = Mock()
        assert reconcile_members(mock_module, mock_blade, {}) is False
        mock_blade.get_management_authentication_policies_members.assert_not_called()

    def test_reconcile_members_converged(self):
        """Test reconcile_members reports no change when membership matches"""
        mock_module = _mock_module(members=[{"name": "alice", "type": "admin"}])
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect(
                [_member_item("ssh-mfa", "admins", "alice")], {"alice": "ssh-mfa"}
            )
        )
        assert reconcile_members(mock_module, mock_blade, {}) is False
        mock_blade.post_management_authentication_policies_members.assert_not_called()
        mock_blade.delete_management_authentication_policies_members.assert_not_called()

    def test_reconcile_members_attaches_missing_member(self):
        """Test reconcile_members POSTs a missing member with mapped type"""
        mock_module = _mock_module(members=[{"name": "fb1", "type": "array"}])
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {})
        )
        mock_blade.post_management_authentication_policies_members.return_value = (
            _ok_response()
        )
        assert reconcile_members(mock_module, mock_blade, {}) is True
        call = mock_blade.post_management_authentication_policies_members.call_args[1]
        assert call["policy_names"] == ["ssh-mfa"]
        assert call["member_names"] == ["fb1"]
        assert call["member_types"] == ["arrays"]

    def test_reconcile_members_empty_list_detaches_all(self):
        """Test members: [] detaches every current member"""
        mock_module = _mock_module(members=[])
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect(
                [
                    _member_item("ssh-mfa", "admins", "alice"),
                    _member_item("ssh-mfa", "arrays", "fb1"),
                ],
                {},
            )
        )
        mock_blade.delete_management_authentication_policies_members.return_value = (
            _ok_response()
        )
        assert reconcile_members(mock_module, mock_blade, {}) is True
        assert (
            mock_blade.delete_management_authentication_policies_members.call_count == 2
        )

    def test_reconcile_members_never_detaches_protected_admins(self):
        """Test exempt users are not detached even when absent from the list"""
        mock_module = _mock_module(members=[])
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([_member_item("ssh-mfa", "admins", "ir")], {})
        )
        assert reconcile_members(mock_module, mock_blade, {}) is False
        mock_blade.delete_management_authentication_policies_members.assert_not_called()

    def test_reconcile_members_conflict_fails_by_default(self):
        """Test attaching a member owned by another policy fails with its name"""
        mock_module = _mock_module(members=[{"name": "alice", "type": "admin"}])
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {"alice": "other-policy"})
        )
        try:
            reconcile_members(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        msg = mock_module.fail_json.call_args[1]["msg"]
        assert "other-policy" in msg
        assert "replace_existing" in msg
        mock_blade.post_management_authentication_policies_members.assert_not_called()

    def test_reconcile_members_replace_existing_moves_member(self):
        """Test replace_existing detaches from the old policy, then attaches"""
        mock_module = _mock_module(
            members=[{"name": "alice", "type": "admin"}], replace_existing=True
        )
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {"alice": "other-policy"})
        )
        mock_blade.delete_management_authentication_policies_members.return_value = (
            _ok_response()
        )
        mock_blade.post_management_authentication_policies_members.return_value = (
            _ok_response()
        )
        assert reconcile_members(mock_module, mock_blade, {}) is True
        detach = mock_blade.delete_management_authentication_policies_members.call_args[
            1
        ]
        assert detach["policy_names"] == ["other-policy"]
        assert detach["member_names"] == ["alice"]
        mock_blade.post_management_authentication_policies_members.assert_called_once()
        # A successful move is silent; the orphan note appears only in the
        # failure message when the attach half fails.
        mock_module.warn.assert_not_called()

    def test_reconcile_members_move_failure_orphans_only_one_member(self):
        """Test per-member pairing: a failed move stops before touching the
        next mover and names the orphaned member"""
        mock_module = _mock_module(
            members=[
                {"name": "alice", "type": "admin"},
                {"name": "bob", "type": "admin"},
            ],
            replace_existing=True,
        )
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {"alice": "other-policy", "bob": "other-policy"})
        )
        mock_blade.delete_management_authentication_policies_members.return_value = (
            _ok_response()
        )
        error = Mock()
        error.status_code = 400
        error.errors = []
        mock_blade.post_management_authentication_policies_members.return_value = error
        try:
            reconcile_members(mock_module, mock_blade, {})
        except SystemExit:
            pass
        # alice (sorted first) was detached and her attach failed; bob's
        # move must not have started.
        assert (
            mock_blade.delete_management_authentication_policies_members.call_count == 1
        )
        msg = mock_module.fail_json.call_args[1]["msg"]
        assert "alice" in msg
        assert "attached to no policy" in msg

    def test_reconcile_members_check_mode_reports_without_writes(self):
        """Test check mode reports a pending change without POST/DELETE"""
        mock_module = _mock_module(members=[{"name": "alice", "type": "admin"}])
        mock_module.check_mode = True
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {})
        )
        assert reconcile_members(mock_module, mock_blade, {}) is True
        mock_blade.post_management_authentication_policies_members.assert_not_called()
        mock_blade.delete_management_authentication_policies_members.assert_not_called()

    def test_reconcile_members_check_mode_still_fails_on_conflict(self):
        """Test check mode fails on a conflict exactly like a real run"""
        mock_module = _mock_module(members=[{"name": "alice", "type": "admin"}])
        mock_module.check_mode = True
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {"alice": "other-policy"})
        )
        try:
            reconcile_members(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()

    def test_reconcile_members_attach_error_fails(self):
        """Test a failed attach surfaces the API error"""
        mock_module = _mock_module(members=[{"name": "alice", "type": "admin"}])
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {})
        )
        error = Mock()
        error.status_code = 400
        error.errors = []
        mock_blade.post_management_authentication_policies_members.return_value = error
        try:
            reconcile_members(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "Failed to attach" in mock_module.fail_json.call_args[1]["msg"]

    def test_reconcile_members_fails_on_nonexistent_admin(self):
        """Test a mistyped admin name fails before any write, even in check mode"""
        mock_module = _mock_module(members=[{"name": "ghost", "type": "admin"}])
        mock_module.check_mode = True
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {})
        )
        error = Mock()
        error.status_code = 400
        mock_blade.get_admins.return_value = error
        try:
            reconcile_members(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "does not exist" in mock_module.fail_json.call_args[1]["msg"]
        mock_blade.post_management_authentication_policies_members.assert_not_called()

    def test_reconcile_members_fails_on_unknown_array(self):
        """Test an array member name that is not this array fails"""
        mock_module = _mock_module(members=[{"name": "fb2", "type": "array"}])
        mock_blade = Mock()
        _members_exist(mock_blade, arrays=("fb1",))
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {})
        )
        try:
            reconcile_members(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "does not exist" in mock_module.fail_json.call_args[1]["msg"]

    # ==== create_policy ====

    def test_create_policy_requires_a_method_mode(self):
        """Test create fails when neither method list is supplied"""
        mock_module = _mock_module()
        mock_blade = Mock()
        try:
            create_policy(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert (
            "ssh_allowed_methods or ssh_required_methods"
            in mock_module.fail_json.call_args[1]["msg"]
        )
        mock_blade.post_management_authentication_policies.assert_not_called()

    @patch("plugins.modules.purefb_mgmt_auth_policy.ManagementAuthenticationPolicyPost")
    def test_create_policy_defaults_enabled_true(self, mock_post_cls):
        """Test create defaults enabled to true and POSTs the policy"""
        mock_module = _mock_module(ssh_allowed_methods=["password"])
        mock_blade = Mock()
        mock_blade.post_management_authentication_policies.return_value = _ok_response()
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {})
        )
        try:
            create_policy(mock_module, mock_blade, {})
        except SystemExit:
            pass
        assert mock_post_cls.call_args[1]["enabled"] is True
        mock_blade.post_management_authentication_policies.assert_called_once()
        mock_module.exit_json.assert_called_once_with(changed=True)

    def test_create_policy_check_mode_skips_post(self):
        """Test create in check mode reports changed without POSTing"""
        mock_module = _mock_module(ssh_required_methods=["password", "key"])
        mock_module.check_mode = True
        mock_blade = Mock()
        try:
            create_policy(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_blade.post_management_authentication_policies.assert_not_called()
        mock_module.exit_json.assert_called_once_with(changed=True)

    def test_create_policy_attaches_members(self):
        """Test create reconciles members after the POST"""
        mock_module = _mock_module(
            ssh_allowed_methods=["key"],
            members=[{"name": "alice", "type": "admin"}],
        )
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.post_management_authentication_policies.return_value = _ok_response()
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {})
        )
        mock_blade.post_management_authentication_policies_members.return_value = (
            _ok_response()
        )
        try:
            create_policy(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_blade.post_management_authentication_policies_members.assert_called_once()
        mock_module.exit_json.assert_called_once_with(changed=True)

    def test_create_policy_preflights_conflict_before_post(self):
        """Test a member conflict fails create before the policy POST"""
        mock_module = _mock_module(
            ssh_allowed_methods=["key"],
            members=[{"name": "alice", "type": "admin"}],
        )
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {"alice": "other-policy"})
        )
        try:
            create_policy(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "other-policy" in mock_module.fail_json.call_args[1]["msg"]
        mock_blade.post_management_authentication_policies.assert_not_called()

    def test_create_policy_check_mode_fails_on_conflict(self):
        """Test check-mode create fails on a member conflict like a real run"""
        mock_module = _mock_module(
            ssh_allowed_methods=["key"],
            members=[{"name": "alice", "type": "admin"}],
        )
        mock_module.check_mode = True
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {"alice": "other-policy"})
        )
        try:
            create_policy(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "replace_existing" in mock_module.fail_json.call_args[1]["msg"]
        mock_blade.post_management_authentication_policies.assert_not_called()

    def test_create_policy_check_mode_fails_on_nonexistent_member(self):
        """Test check-mode create catches a nonexistent member before the POST"""
        mock_module = _mock_module(
            ssh_allowed_methods=["key"],
            members=[{"name": "ghost", "type": "admin"}],
        )
        mock_module.check_mode = True
        mock_blade = Mock()
        error = Mock()
        error.status_code = 400
        mock_blade.get_admins.return_value = error
        try:
            create_policy(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "does not exist" in mock_module.fail_json.call_args[1]["msg"]
        mock_blade.post_management_authentication_policies.assert_not_called()

    def test_create_policy_replace_existing_moves_member(self):
        """Test create with replace_existing moves a conflicted member"""
        mock_module = _mock_module(
            ssh_allowed_methods=["key"],
            members=[{"name": "alice", "type": "admin"}],
            replace_existing=True,
        )
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {"alice": "other-policy"})
        )
        mock_blade.post_management_authentication_policies.return_value = _ok_response()
        mock_blade.delete_management_authentication_policies_members.return_value = (
            _ok_response()
        )
        mock_blade.post_management_authentication_policies_members.return_value = (
            _ok_response()
        )
        try:
            create_policy(mock_module, mock_blade, {})
        except SystemExit:
            pass
        detach = mock_blade.delete_management_authentication_policies_members.call_args[
            1
        ]
        assert detach["policy_names"] == ["other-policy"]
        mock_blade.post_management_authentication_policies_members.assert_called_once()
        mock_module.exit_json.assert_called_once_with(changed=True)

    def test_create_policy_api_error_fails(self):
        """Test create surfaces an API failure"""
        mock_module = _mock_module(ssh_allowed_methods=["password"])
        mock_blade = Mock()
        error = Mock()
        error.status_code = 400
        error.errors = []
        mock_blade.post_management_authentication_policies.return_value = error
        try:
            create_policy(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "Failed to create policy" in mock_module.fail_json.call_args[1]["msg"]

    # ==== update_policy ====

    def test_update_policy_no_changes(self):
        """Test update exits changed=False when nothing differs"""
        mock_module = _mock_module(ssh_allowed_methods=["password", "key"])
        mock_blade = Mock()
        existing = _mock_policy(allowed=["key", "password"])
        try:
            update_policy(mock_module, mock_blade, {}, existing)
        except SystemExit:
            pass
        mock_blade.patch_management_authentication_policies.assert_not_called()
        mock_module.exit_json.assert_called_once_with(changed=False)

    def test_update_policy_enabled_change(self):
        """Test update PATCHes an enabled flip"""
        mock_module = _mock_module(enabled=False)
        mock_blade = Mock()
        mock_blade.patch_management_authentication_policies.return_value = (
            _ok_response()
        )
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {})
        )
        existing = _mock_policy(enabled=True, allowed=["password"])
        try:
            update_policy(mock_module, mock_blade, {}, existing)
        except SystemExit:
            pass
        mock_blade.patch_management_authentication_policies.assert_called_once()
        mock_module.exit_json.assert_called_once_with(changed=True)

    @patch(
        "plugins.modules.purefb_mgmt_auth_policy.ManagementAuthenticationPolicyConfig"
    )
    def test_update_policy_mode_switch(self, mock_config_cls):
        """Test switching allowed -> required PATCHes with the old list cleared"""
        mock_module = _mock_module(ssh_required_methods=["password", "key"])
        mock_blade = Mock()
        mock_blade.patch_management_authentication_policies.return_value = (
            _ok_response()
        )
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {})
        )
        existing = _mock_policy(allowed=["password"])
        try:
            update_policy(mock_module, mock_blade, {}, existing)
        except SystemExit:
            pass
        mock_blade.patch_management_authentication_policies.assert_called_once()
        assert mock_config_cls.call_args[1] == {
            "allowed_methods": [],
            "required_methods": ["key", "password"],
        }
        mock_module.exit_json.assert_called_once_with(changed=True)

    def test_update_policy_warns_when_members_attached(self):
        """Test a config change on an attached policy emits a lockout warning"""
        mock_module = _mock_module(ssh_required_methods=["key"])
        mock_blade = Mock()
        mock_blade.patch_management_authentication_policies.return_value = (
            _ok_response()
        )
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([_member_item("ssh-mfa", "admins", "alice")], {})
        )
        existing = _mock_policy(allowed=["password"])
        # members param omitted -> reconcile is a no-op; only the warning
        # path reads membership.
        try:
            update_policy(mock_module, mock_blade, {}, existing)
        except SystemExit:
            pass
        mock_module.warn.assert_called_once()
        assert "subsequent SSH logins" in mock_module.warn.call_args[0][0]

    def test_update_policy_check_mode_skips_patch(self):
        """Test check mode reports the pending update without PATCHing"""
        mock_module = _mock_module(enabled=False)
        mock_module.check_mode = True
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {})
        )
        existing = _mock_policy(enabled=True, allowed=["password"])
        try:
            update_policy(mock_module, mock_blade, {}, existing)
        except SystemExit:
            pass
        mock_blade.patch_management_authentication_policies.assert_not_called()
        mock_module.exit_json.assert_called_once_with(changed=True)

    def test_update_policy_api_error_fails(self):
        """Test update surfaces an API failure"""
        mock_module = _mock_module(enabled=False)
        mock_blade = Mock()
        error = Mock()
        error.status_code = 400
        error.errors = []
        mock_blade.patch_management_authentication_policies.return_value = error
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {})
        )
        existing = _mock_policy(enabled=True, allowed=["password"])
        try:
            update_policy(mock_module, mock_blade, {}, existing)
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "Failed to update policy" in mock_module.fail_json.call_args[1]["msg"]

    def test_update_policy_members_only_change(self):
        """Test membership-only reconciliation reports changed without PATCH"""
        mock_module = _mock_module(members=[{"name": "alice", "type": "admin"}])
        mock_blade = Mock()
        _members_exist(mock_blade)
        mock_blade.get_management_authentication_policies_members.side_effect = (
            _members_side_effect([], {})
        )
        mock_blade.post_management_authentication_policies_members.return_value = (
            _ok_response()
        )
        existing = _mock_policy(allowed=["password"])
        try:
            update_policy(mock_module, mock_blade, {}, existing)
        except SystemExit:
            pass
        mock_blade.patch_management_authentication_policies.assert_not_called()
        mock_module.exit_json.assert_called_once_with(changed=True)

    # ==== delete_policy ====

    def test_delete_policy_fails_when_members_attached(self):
        """Test the client-side delete guard (the array itself would allow it)"""
        mock_module = _mock_module(state="absent")
        mock_blade = Mock()
        mock_blade.get_management_authentication_policies_members.return_value = (
            _ok_response([_member_item("ssh-mfa", "arrays", "fb1")])
        )
        try:
            delete_policy(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        msg = mock_module.fail_json.call_args[1]["msg"]
        assert "has attached members" in msg
        assert "Detach members first" in msg
        mock_blade.delete_management_authentication_policies.assert_not_called()

    def test_delete_policy_success(self):
        """Test delete removes an unattached policy"""
        mock_module = _mock_module(state="absent")
        mock_blade = Mock()
        mock_blade.get_management_authentication_policies_members.return_value = (
            _ok_response([])
        )
        mock_blade.delete_management_authentication_policies.return_value = (
            _ok_response()
        )
        try:
            delete_policy(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_blade.delete_management_authentication_policies.assert_called_once()
        mock_module.exit_json.assert_called_once_with(changed=True)

    def test_delete_policy_check_mode_skips_delete(self):
        """Test check mode reports the pending delete without DELETEing"""
        mock_module = _mock_module(state="absent")
        mock_module.check_mode = True
        mock_blade = Mock()
        mock_blade.get_management_authentication_policies_members.return_value = (
            _ok_response([])
        )
        try:
            delete_policy(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_blade.delete_management_authentication_policies.assert_not_called()
        mock_module.exit_json.assert_called_once_with(changed=True)

    def test_delete_policy_api_error_fails(self):
        """Test delete surfaces an API failure"""
        mock_module = _mock_module(state="absent")
        mock_blade = Mock()
        mock_blade.get_management_authentication_policies_members.return_value = (
            _ok_response([])
        )
        error = Mock()
        error.status_code = 400
        error.errors = []
        mock_blade.delete_management_authentication_policies.return_value = error
        try:
            delete_policy(mock_module, mock_blade, {})
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "Failed to delete policy" in mock_module.fail_json.call_args[1]["msg"]

    # ==== main / version gating ====

    @patch("plugins.modules.purefb_mgmt_auth_policy.LooseVersion")
    @patch("plugins.modules.purefb_mgmt_auth_policy.get_rest_api_version")
    @patch("plugins.modules.purefb_mgmt_auth_policy.get_system")
    @patch("plugins.modules.purefb_mgmt_auth_policy.AnsibleModule")
    def test_main_fails_below_minimum_api_version(
        self, mock_ansible_module, mock_get_system, mock_get_version, mock_loose
    ):
        """Test main fails when the array REST version predates 2.22"""
        mock_module = _mock_module()
        mock_ansible_module.return_value = mock_module
        mock_get_system.return_value = Mock()
        mock_get_version.return_value = "2.21"
        mock_loose.side_effect = lambda v: tuple(int(p) for p in v.split("."))
        try:
            main()
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        msg = mock_module.fail_json.call_args[1]["msg"]
        assert "does not support management authentication policies" in msg
        assert "2.22" in msg

    @patch("plugins.modules.purefb_mgmt_auth_policy.get_error_message")
    @patch("plugins.modules.purefb_mgmt_auth_policy.LooseVersion")
    @patch("plugins.modules.purefb_mgmt_auth_policy.get_rest_api_version")
    @patch("plugins.modules.purefb_mgmt_auth_policy.get_system")
    @patch("plugins.modules.purefb_mgmt_auth_policy.AnsibleModule")
    def test_main_absent_nonexistent_policy_no_change(
        self,
        mock_ansible_module,
        mock_get_system,
        mock_get_version,
        mock_loose,
        mock_gem,
    ):
        """Test state=absent on a missing policy exits changed=False"""
        mock_gem.return_value = "Management authentication policy does not exist."
        mock_module = _mock_module(state="absent")
        mock_ansible_module.return_value = mock_module
        mock_blade = Mock()
        error = Mock()
        error.status_code = 400
        mock_blade.get_management_authentication_policies.return_value = error
        mock_get_system.return_value = mock_blade
        mock_get_version.return_value = "2.28"
        mock_loose.side_effect = lambda v: tuple(int(p) for p in v.split("."))
        try:
            main()
        except SystemExit:
            pass
        mock_module.exit_json.assert_called_once_with(changed=False)

# Copyright: (c) 2026, Pure Storage Ansible Team <pure-ansible-team@everpuredata.com>
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for purefb_password_policy module."""

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

from plugins.modules.purefb_password_policy import (
    main,
    _validate_params,
    get_policy,
    update_policy,
)

MODULE_PATH = "plugins.modules.purefb_password_policy"

# Current policy as returned by the GET endpoint, in API units (ms durations).
POLICY_DEFAULTS = {
    "name": "management",
    "enabled": True,
    "enforce_dictionary_check": True,
    "enforce_username_check": True,
    "lockout_duration": 3600000,
    "max_login_attempts": 10,
    "max_password_age": 8640000000,
    "min_character_groups": 3,
    "min_characters_per_group": 1,
    "min_password_age": 86400000,
    "min_password_length": 8,
    "password_history": 5,
}


def _base_params(**overrides):
    """Return a full params dict with every setting omitted, patched by overrides."""
    params = {
        "name": "management",
        "enabled": None,
        "enforce_dictionary_check": None,
        "enforce_username_check": None,
        "lockout_duration": None,
        "max_login_attempts": None,
        "max_password_age": None,
        "min_character_groups": None,
        "min_characters_per_group": None,
        "min_password_age": None,
        "min_password_length": None,
        "password_history": None,
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
    return module


def _mock_policy(missing=(), **overrides):
    """Mock policy object as returned by the get endpoint.

    Fields named in ``missing`` are absent from the object entirely,
    mirroring an older REST version that predates them.
    """
    fields = dict(POLICY_DEFAULTS)
    fields.update(overrides)
    for field in missing:
        del fields[field]
    policy = Mock(spec=list(fields))
    for field, value in fields.items():
        setattr(policy, field, value)
    return policy


class TestPurefbPasswordPolicy:
    """Test cases for purefb_password_policy module"""

    # ==== parameter validation ====

    def test_validate_params_noop_when_all_omitted(self):
        """Test _validate_params passes when no setting is supplied"""
        mock_module = _mock_module()
        _validate_params(mock_module)
        mock_module.fail_json.assert_not_called()

    def test_validate_params_rejects_out_of_range_values(self):
        """Test _validate_params rejects values outside documented ranges"""
        out_of_range = [
            ("min_password_length", 0),
            ("min_password_length", 101),
            ("max_login_attempts", 0),
            ("max_login_attempts", 101),
            ("lockout_duration", 0),
            ("lockout_duration", 7776001),
            ("password_history", -1),
            ("password_history", 65),
            ("min_character_groups", 0),
            ("min_character_groups", 5),
            ("min_password_age", -3600),
            ("min_password_age", 608400),
        ]
        for param, value in out_of_range:
            mock_module = _mock_module(**{param: value})
            try:
                _validate_params(mock_module)
            except SystemExit:
                pass
            mock_module.fail_json.assert_called_once()
            assert param in mock_module.fail_json.call_args[1]["msg"]

    def test_validate_params_rejects_min_characters_per_group_below_one(self):
        """Test _validate_params rejects min_characters_per_group of 0"""
        mock_module = _mock_module(min_characters_per_group=0)
        try:
            _validate_params(mock_module)
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "must be 1 or greater" in mock_module.fail_json.call_args[1]["msg"]

    def test_validate_params_rejects_non_hour_ages(self):
        """Test _validate_params rejects ages that are not whole hours"""
        for param, value in [
            ("min_password_age", 1800),
            ("max_password_age", 90001),
        ]:
            mock_module = _mock_module(**{param: value})
            try:
                _validate_params(mock_module)
            except SystemExit:
                pass
            mock_module.fail_json.assert_called_once()
            assert "whole number of hours" in mock_module.fail_json.call_args[1]["msg"]

    def test_validate_params_rejects_max_age_below_one_day(self):
        """Test _validate_params rejects a non-zero max age under 1 day"""
        mock_module = _mock_module(max_password_age=3600)
        try:
            _validate_params(mock_module)
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "at least 86400" in mock_module.fail_json.call_args[1]["msg"]

    def test_validate_params_accepts_zero_max_age(self):
        """Test _validate_params allows 0 (expiration disabled)"""
        mock_module = _mock_module(max_password_age=0)
        _validate_params(mock_module)
        mock_module.fail_json.assert_not_called()

    def test_validate_params_rejects_max_age_not_above_min_age(self):
        """Test _validate_params rejects max age <= min age"""
        mock_module = _mock_module(max_password_age=86400, min_password_age=86400)
        try:
            _validate_params(mock_module)
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert (
            "greater than min_password_age" in mock_module.fail_json.call_args[1]["msg"]
        )

    def test_validate_params_allows_min_age_with_expiration_disabled(self):
        """Test _validate_params allows any min age when max age is 0"""
        mock_module = _mock_module(max_password_age=0, min_password_age=604800)
        _validate_params(mock_module)
        mock_module.fail_json.assert_not_called()

    def test_validate_params_accepts_boundary_values(self):
        """Test _validate_params passes documented boundary values"""
        mock_module = _mock_module(
            min_password_length=100,
            max_login_attempts=1,
            lockout_duration=7776000,
            password_history=64,
            min_character_groups=4,
            min_characters_per_group=1,
            min_password_age=604800,
            max_password_age=8639913600,
        )
        _validate_params(mock_module)
        mock_module.fail_json.assert_not_called()

    # ==== get_policy ====

    def test_get_policy_returns_singleton(self):
        """Test get_policy returns the policy object on success"""
        mock_module = _mock_module()
        mock_blade = Mock()
        policy = _mock_policy()
        response = Mock()
        response.status_code = 200
        response.items = [policy]
        mock_blade.get_password_policies.return_value = response

        assert get_policy(mock_module, mock_blade) is policy
        mock_blade.get_password_policies.assert_called_once_with(names=["management"])

    @patch(MODULE_PATH + ".get_error_message")
    def test_get_policy_fails_on_error_response(self, mock_gem):
        """Test get_policy fails the task on a non-200 response"""
        mock_gem.return_value = "Test error message"
        mock_module = _mock_module()
        mock_blade = Mock()
        response = Mock()
        response.status_code = 400
        mock_blade.get_password_policies.return_value = response

        try:
            get_policy(mock_module, mock_blade)
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        msg = mock_module.fail_json.call_args[1]["msg"]
        assert "Failed to read password policy management" in msg
        assert "Test error message" in msg

    def test_get_policy_fails_on_empty_result(self):
        """Test get_policy fails when the response has no items"""
        mock_module = _mock_module()
        mock_blade = Mock()
        response = Mock()
        response.status_code = 200
        response.items = []
        mock_blade.get_password_policies.return_value = response

        try:
            get_policy(mock_module, mock_blade)
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        assert "was not found" in mock_module.fail_json.call_args[1]["msg"]

    # ==== update_policy ====

    def test_update_policy_no_settings_no_change(self):
        """Test update_policy exits changed=False when nothing is supplied"""
        mock_module = _mock_module()
        mock_blade = Mock()

        try:
            update_policy(mock_module, mock_blade, _mock_policy())
        except SystemExit:
            pass
        mock_blade.patch_password_policies.assert_not_called()
        mock_module.exit_json.assert_called_once_with(changed=False)

    def test_update_policy_idempotent_when_values_match(self):
        """Test update_policy exits changed=False when settings already match"""
        mock_module = _mock_module(
            enabled=True,
            enforce_dictionary_check=True,
            lockout_duration=3600,
            max_login_attempts=10,
            max_password_age=8640000,
            min_password_age=86400,
            min_password_length=8,
            password_history=5,
        )
        mock_blade = Mock()

        try:
            update_policy(mock_module, mock_blade, _mock_policy())
        except SystemExit:
            pass
        mock_blade.patch_password_policies.assert_not_called()
        mock_module.exit_json.assert_called_once_with(changed=False)

    @patch(MODULE_PATH + ".PasswordPolicy")
    def test_update_policy_patches_only_differing_fields(self, mock_policy_class):
        """Test update_policy sends only the fields that differ"""
        mock_module = _mock_module(
            enabled=True,  # matches current -> omitted
            min_password_length=12,  # differs -> patched
        )
        mock_blade = Mock()
        response = Mock()
        response.status_code = 200
        mock_blade.patch_password_policies.return_value = response

        try:
            update_policy(mock_module, mock_blade, _mock_policy())
        except SystemExit:
            pass
        mock_policy_class.assert_called_once_with(min_password_length=12)
        mock_blade.patch_password_policies.assert_called_once_with(
            names=["management"], policy=mock_policy_class.return_value
        )
        mock_module.exit_json.assert_called_once_with(changed=True)

    @patch(MODULE_PATH + ".PasswordPolicy")
    def test_update_policy_converts_seconds_to_milliseconds(self, mock_policy_class):
        """Test update_policy converts duration params to milliseconds"""
        mock_module = _mock_module(
            lockout_duration=1800,
            min_password_age=7200,
            max_password_age=7776000,
        )
        mock_blade = Mock()
        response = Mock()
        response.status_code = 200
        mock_blade.patch_password_policies.return_value = response

        try:
            update_policy(mock_module, mock_blade, _mock_policy())
        except SystemExit:
            pass
        mock_policy_class.assert_called_once_with(
            lockout_duration=1800000,
            min_password_age=7200000,
            max_password_age=7776000000,
        )
        mock_module.exit_json.assert_called_once_with(changed=True)

    @patch(MODULE_PATH + ".PasswordPolicy")
    def test_update_policy_disables_expiration_with_zero(self, mock_policy_class):
        """Test update_policy sends max_password_age=0 to disable expiration"""
        mock_module = _mock_module(max_password_age=0)
        mock_blade = Mock()
        response = Mock()
        response.status_code = 200
        mock_blade.patch_password_policies.return_value = response

        try:
            update_policy(mock_module, mock_blade, _mock_policy())
        except SystemExit:
            pass
        mock_policy_class.assert_called_once_with(max_password_age=0)
        mock_module.exit_json.assert_called_once_with(changed=True)

    @patch(MODULE_PATH + ".PasswordPolicy")
    def test_update_policy_patches_field_missing_from_current(self, mock_policy_class):
        """Test a field the current policy lacks entirely is still patched"""
        mock_module = _mock_module(max_password_age=7776000)
        mock_blade = Mock()
        response = Mock()
        response.status_code = 200
        mock_blade.patch_password_policies.return_value = response

        try:
            update_policy(
                mock_module, mock_blade, _mock_policy(missing=["max_password_age"])
            )
        except SystemExit:
            pass
        mock_policy_class.assert_called_once_with(max_password_age=7776000000)
        mock_module.exit_json.assert_called_once_with(changed=True)

    def test_update_policy_check_mode_reports_change_without_patch(self):
        """Test check mode reports changed=True but does not PATCH"""
        mock_module = _mock_module(enabled=False)
        mock_module.check_mode = True
        mock_blade = Mock()

        try:
            update_policy(mock_module, mock_blade, _mock_policy())
        except SystemExit:
            pass
        mock_blade.patch_password_policies.assert_not_called()
        mock_module.exit_json.assert_called_once_with(changed=True)

    @patch(MODULE_PATH + ".get_error_message")
    @patch(MODULE_PATH + ".PasswordPolicy")
    def test_update_policy_fails_on_patch_error(self, mock_policy_class, mock_gem):
        """Test update_policy fails the task when the PATCH is rejected"""
        mock_gem.return_value = "Test error message"
        mock_module = _mock_module(enabled=False)
        mock_blade = Mock()
        response = Mock()
        response.status_code = 400
        mock_blade.patch_password_policies.return_value = response

        try:
            update_policy(mock_module, mock_blade, _mock_policy())
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        msg = mock_module.fail_json.call_args[1]["msg"]
        assert "Failed to update password policy management" in msg
        assert "Test error message" in msg

    # ==== main / version gating ====

    @patch(MODULE_PATH + ".get_system")
    @patch(MODULE_PATH + ".AnsibleModule")
    @patch(MODULE_PATH + ".HAS_PYPURECLIENT", False)
    def test_main_missing_sdk(self, mock_ansible_module, mock_get_system):
        """Test main fails before any API access when the SDK is missing"""
        mock_module = _mock_module()
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
        mock_get_system.assert_not_called()

    @patch(MODULE_PATH + ".LooseVersion")
    @patch(MODULE_PATH + ".get_rest_api_version")
    @patch(MODULE_PATH + ".get_system")
    @patch(MODULE_PATH + ".AnsibleModule")
    def test_main_fails_below_minimum_api_version(
        self, mock_ansible_module, mock_get_system, mock_get_version, mock_loose
    ):
        """Test main fails when the array REST version predates 2.16"""
        mock_module = _mock_module()
        mock_ansible_module.return_value = mock_module
        mock_get_system.return_value = Mock()
        mock_get_version.return_value = "2.15"
        mock_loose.side_effect = lambda v: tuple(int(p) for p in v.split("."))

        try:
            main()
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        msg = mock_module.fail_json.call_args[1]["msg"]
        assert "does not support password policies" in msg
        assert "2.16" in msg

    @patch(MODULE_PATH + ".LooseVersion")
    @patch(MODULE_PATH + ".get_rest_api_version")
    @patch(MODULE_PATH + ".get_system")
    @patch(MODULE_PATH + ".AnsibleModule")
    def test_main_fails_max_age_below_218(
        self, mock_ansible_module, mock_get_system, mock_get_version, mock_loose
    ):
        """Test main fails when max_password_age is used before REST 2.18"""
        mock_module = _mock_module(max_password_age=7776000)
        mock_ansible_module.return_value = mock_module
        mock_get_system.return_value = Mock()
        mock_get_version.return_value = "2.17"
        mock_loose.side_effect = lambda v: tuple(int(p) for p in v.split("."))

        try:
            main()
        except SystemExit:
            pass
        mock_module.fail_json.assert_called_once()
        msg = mock_module.fail_json.call_args[1]["msg"]
        assert "does not support max_password_age" in msg
        assert "2.18" in msg

    @patch(MODULE_PATH + ".PasswordPolicy")
    @patch(MODULE_PATH + ".LooseVersion")
    @patch(MODULE_PATH + ".get_rest_api_version")
    @patch(MODULE_PATH + ".get_system")
    @patch(MODULE_PATH + ".AnsibleModule")
    def test_main_updates_differing_setting(
        self,
        mock_ansible_module,
        mock_get_system,
        mock_get_version,
        mock_loose,
        mock_policy_class,
    ):
        """Test main end-to-end: read the singleton, patch the difference"""
        mock_module = _mock_module(max_login_attempts=5)
        mock_ansible_module.return_value = mock_module

        mock_blade = Mock()
        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [_mock_policy()]
        mock_blade.get_password_policies.return_value = get_response
        patch_response = Mock()
        patch_response.status_code = 200
        mock_blade.patch_password_policies.return_value = patch_response
        mock_get_system.return_value = mock_blade
        mock_get_version.return_value = "2.28"
        mock_loose.side_effect = lambda v: tuple(int(p) for p in v.split("."))

        try:
            main()
        except SystemExit:
            pass
        mock_policy_class.assert_called_once_with(max_login_attempts=5)
        mock_blade.patch_password_policies.assert_called_once_with(
            names=["management"], policy=mock_policy_class.return_value
        )
        mock_module.exit_json.assert_called_once_with(changed=True)

    @patch(MODULE_PATH + ".LooseVersion")
    @patch(MODULE_PATH + ".get_rest_api_version")
    @patch(MODULE_PATH + ".get_system")
    @patch(MODULE_PATH + ".AnsibleModule")
    def test_main_idempotent_run_no_change(
        self, mock_ansible_module, mock_get_system, mock_get_version, mock_loose
    ):
        """Test main end-to-end: matching settings make no PATCH call"""
        mock_module = _mock_module(min_password_length=8, lockout_duration=3600)
        mock_ansible_module.return_value = mock_module

        mock_blade = Mock()
        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [_mock_policy()]
        mock_blade.get_password_policies.return_value = get_response
        mock_get_system.return_value = mock_blade
        mock_get_version.return_value = "2.16"
        mock_loose.side_effect = lambda v: tuple(int(p) for p in v.split("."))

        try:
            main()
        except SystemExit:
            pass
        mock_blade.patch_password_policies.assert_not_called()
        mock_module.exit_json.assert_called_once_with(changed=False)

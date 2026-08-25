# Copyright: (c) 2026, Pure Storage Ansible Team <pure-ansible-team@everpuredata.com>
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for purefb_local_ds module."""

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

from plugins.modules.purefb_local_ds import (
    main,
    _get_lds,
    _find_attached_server,
    _context_kwargs,
)


def _base_params(**overrides):
    params = {
        "name": "myserver_local",
        "state": "present",
        "domain": None,
        "context": "",
    }
    params.update(overrides)
    return params


class TestPurefbLocalDs:
    """Test cases for purefb_local_ds module"""

    # ---------------- helper-function unit tests ----------------

    def test_context_kwargs_returns_empty_without_context(self):
        """_context_kwargs returns {} when no context is set"""
        module = Mock()
        module.params = {"context": ""}
        assert _context_kwargs(module) == {}

    def test_context_kwargs_returns_kwargs_when_set(self):
        """_context_kwargs returns context_names when a context is set"""
        module = Mock()
        module.params = {"context": "peer1"}
        assert _context_kwargs(module) == {"context_names": ["peer1"]}

    def test_get_lds_returns_first_item(self):
        """_get_lds returns the first item when present"""
        module = Mock()
        module.params = {"name": "myserver_local", "context": ""}

        lds = Mock()
        lds.name = "myserver_local"

        blade = Mock()
        response = Mock()
        response.status_code = 200
        response.items = [lds]
        blade.get_directory_services_local_directory_services.return_value = response

        assert _get_lds(module, blade) is lds
        blade.get_directory_services_local_directory_services.assert_called_once_with(
            names=["myserver_local"]
        )

    def test_get_lds_returns_none_when_empty(self):
        """_get_lds returns None when items is empty"""
        module = Mock()
        module.params = {"name": "myserver_local", "context": ""}

        blade = Mock()
        response = Mock()
        response.status_code = 200
        response.items = []
        blade.get_directory_services_local_directory_services.return_value = response

        assert _get_lds(module, blade) is None

    def test_get_lds_returns_none_on_error(self):
        """_get_lds returns None when status is non-200"""
        module = Mock()
        module.params = {"name": "myserver_local", "context": ""}

        blade = Mock()
        response = Mock()
        response.status_code = 400
        response.items = []
        blade.get_directory_services_local_directory_services.return_value = response

        assert _get_lds(module, blade) is None

    def test_find_attached_server_returns_name(self):
        """_find_attached_server returns server name when one is attached"""
        module = Mock()
        module.params = {"name": "myserver_local", "context": ""}

        server = Mock()
        server.name = "myserver"
        response = Mock()
        response.status_code = 200
        response.items = [server]

        blade = Mock()
        blade.get_servers.return_value = response

        assert _find_attached_server(module, blade) == "myserver"
        blade.get_servers.assert_called_once_with(
            filter="local_directory_service.name='myserver_local'"
        )

    def test_find_attached_server_returns_none_when_no_server(self):
        """_find_attached_server returns None when no server is attached"""
        module = Mock()
        module.params = {"name": "myserver_local", "context": ""}

        response = Mock()
        response.status_code = 200
        response.items = []

        blade = Mock()
        blade.get_servers.return_value = response

        assert _find_attached_server(module, blade) is None

    def test_find_attached_server_returns_none_on_error(self):
        """_find_attached_server returns None on API error"""
        module = Mock()
        module.params = {"name": "myserver_local", "context": ""}

        response = Mock()
        response.status_code = 400
        response.items = []

        blade = Mock()
        blade.get_servers.return_value = response

        assert _find_attached_server(module, blade) is None

    # ---------------- main() flows ----------------

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.LocalDirectoryServicePost")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", True)
    def test_main_creates_lds_with_domain(
        self, mock_ansible_module, mock_get_system, mock_lds_post, mock_loose_version
    ):
        """Test creating a new LDS with an explicit domain"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(domain="local")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.17", "2.24"]
        mock_get_system.return_value = blade

        # LDS doesn't exist yet
        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        blade.get_directory_services_local_directory_services.return_value = (
            get_response
        )

        # Successful create
        post_response = Mock()
        post_response.status_code = 200
        post_response.items = []
        blade.post_directory_services_local_directory_services.return_value = (
            post_response
        )

        try:
            main()
        except SystemExit:
            pass

        blade.post_directory_services_local_directory_services.assert_called_once()
        call_kwargs = blade.post_directory_services_local_directory_services.call_args[
            1
        ]
        assert call_kwargs["names"] == ["myserver_local"]
        mock_lds_post.assert_called_once_with(domain="local")
        module.exit_json.assert_called_once()
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.LocalDirectoryServicePost")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", True)
    def test_main_creates_lds_without_domain(
        self, mock_ansible_module, mock_get_system, mock_lds_post, mock_loose_version
    ):
        """Test creating a new LDS without a domain (array default)"""
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
        blade.get_directory_services_local_directory_services.return_value = (
            get_response
        )

        post_response = Mock()
        post_response.status_code = 200
        post_response.items = []
        blade.post_directory_services_local_directory_services.return_value = (
            post_response
        )

        try:
            main()
        except SystemExit:
            pass

        # domain omitted → body built with no arguments
        mock_lds_post.assert_called_once_with()
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", True)
    def test_main_create_check_mode_skips_post(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test create reports changed but skips POST in check mode"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(domain="local")
        module.check_mode = True
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        blade.get_directory_services_local_directory_services.return_value = (
            get_response
        )

        try:
            main()
        except SystemExit:
            pass

        blade.post_directory_services_local_directory_services.assert_not_called()
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", True)
    def test_main_create_fails_on_api_error(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test create surfaces API error via fail_json"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(domain="local")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = []
        blade.get_directory_services_local_directory_services.return_value = (
            get_response
        )

        post_response = Mock()
        post_response.status_code = 400
        post_response.errors = []
        blade.post_directory_services_local_directory_services.return_value = (
            post_response
        )

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        assert (
            "Failed to create local directory service"
            in module.fail_json.call_args[1]["msg"]
        )

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.LocalDirectoryService")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", True)
    def test_main_updates_domain(
        self, mock_ansible_module, mock_get_system, mock_lds, mock_loose_version
    ):
        """Test PATCHing the domain of an existing LDS"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(domain="corp.local")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "myserver_local"
        existing.domain = "local"
        existing.server = None
        existing.realms = []

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_directory_services.return_value = (
            get_response
        )

        patch_response = Mock()
        patch_response.status_code = 200
        patch_response.items = []
        blade.patch_directory_services_local_directory_services.return_value = (
            patch_response
        )

        try:
            main()
        except SystemExit:
            pass

        blade.patch_directory_services_local_directory_services.assert_called_once()
        mock_lds.assert_called_once_with(domain="corp.local")
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", True)
    def test_main_update_idempotent_when_domain_matches(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test update is a no-op when the domain already matches"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(domain="local")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "myserver_local"
        existing.domain = "local"
        existing.server = None
        existing.realms = []

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_directory_services.return_value = (
            get_response
        )

        try:
            main()
        except SystemExit:
            pass

        blade.patch_directory_services_local_directory_services.assert_not_called()
        assert module.exit_json.call_args[1]["changed"] is False

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", True)
    def test_main_update_no_domain_is_noop(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test update is a no-op when domain param is omitted (never resets it)"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params()  # domain=None
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "myserver_local"
        existing.domain = "somedomain"
        existing.server = None
        existing.realms = []

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_directory_services.return_value = (
            get_response
        )

        try:
            main()
        except SystemExit:
            pass

        blade.patch_directory_services_local_directory_services.assert_not_called()
        assert module.exit_json.call_args[1]["changed"] is False

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.LocalDirectoryService")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", True)
    def test_main_update_warns_when_attached(
        self, mock_ansible_module, mock_get_system, mock_lds, mock_loose_version
    ):
        """Test update warns when patching domain on an LDS that is server-attached"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.warn = Mock()
        module.params = _base_params(domain="new.domain")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        server = Mock()
        server.name = "myserver"
        existing = Mock()
        existing.name = "myserver_local"
        existing.domain = "local"
        existing.server = server
        existing.realms = []

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_directory_services.return_value = (
            get_response
        )

        patch_response = Mock()
        patch_response.status_code = 200
        patch_response.items = []
        blade.patch_directory_services_local_directory_services.return_value = (
            patch_response
        )

        try:
            main()
        except SystemExit:
            pass

        module.warn.assert_called_once()
        assert "myserver" in module.warn.call_args[0][0]
        blade.patch_directory_services_local_directory_services.assert_called_once()

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.LocalDirectoryService")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", True)
    def test_main_update_fails_with_attached_context_in_message(
        self, mock_ansible_module, mock_get_system, mock_lds, mock_loose_version
    ):
        """Test update failure mentions attached server name in error message"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.warn = Mock()
        module.params = _base_params(domain="new.domain")
        module.check_mode = False
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        server = Mock()
        server.name = "myserver"
        existing = Mock()
        existing.name = "myserver_local"
        existing.domain = "local"
        existing.server = server
        existing.realms = []

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_directory_services.return_value = (
            get_response
        )

        patch_response = Mock()
        patch_response.status_code = 400
        patch_response.errors = []
        blade.patch_directory_services_local_directory_services.return_value = (
            patch_response
        )

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        msg = module.fail_json.call_args[1]["msg"]
        assert "myserver" in msg
        assert "myserver_local" in msg

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", True)
    def test_main_deletes_lds(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test deleting an existing, detached LDS"""
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
        existing.name = "myserver_local"

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_directory_services.return_value = (
            get_response
        )

        server_response = Mock()
        server_response.status_code = 200
        server_response.items = []
        blade.get_servers.return_value = server_response

        delete_response = Mock()
        delete_response.status_code = 200
        blade.delete_directory_services_local_directory_services.return_value = (
            delete_response
        )

        try:
            main()
        except SystemExit:
            pass

        blade.delete_directory_services_local_directory_services.assert_called_once_with(
            names=["myserver_local"]
        )
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", True)
    def test_main_delete_refused_when_attached(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test delete refuses when LDS is still attached to a server"""
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
        existing.name = "myserver_local"

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_directory_services.return_value = (
            get_response
        )

        server = Mock()
        server.name = "myserver"
        server_response = Mock()
        server_response.status_code = 200
        server_response.items = [server]
        blade.get_servers.return_value = server_response

        try:
            main()
        except SystemExit:
            pass

        module.fail_json.assert_called_once()
        msg = module.fail_json.call_args[1]["msg"]
        assert "myserver" in msg
        assert "Detach" in msg or "detach" in msg
        blade.delete_directory_services_local_directory_services.assert_not_called()

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", True)
    def test_main_delete_nonexistent_is_noop(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test state=absent on a nonexistent LDS reports changed=False"""
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
        blade.get_directory_services_local_directory_services.return_value = (
            get_response
        )

        try:
            main()
        except SystemExit:
            pass

        blade.delete_directory_services_local_directory_services.assert_not_called()
        assert module.exit_json.call_args[1]["changed"] is False

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", True)
    def test_main_delete_check_mode_skips_call(
        self, mock_ansible_module, mock_get_system, mock_loose_version
    ):
        """Test delete reports changed but skips the DELETE call in check mode"""
        mock_loose_version.return_value.__gt__ = Mock(return_value=False)
        module = Mock()
        module.exit_json = Mock(side_effect=SystemExit)
        module.fail_json = Mock(side_effect=SystemExit)
        module.params = _base_params(state="absent")
        module.check_mode = True
        mock_ansible_module.return_value = module

        blade = Mock()
        blade.get_versions.return_value.items = ["2.24"]
        mock_get_system.return_value = blade

        existing = Mock()
        existing.name = "myserver_local"

        get_response = Mock()
        get_response.status_code = 200
        get_response.items = [existing]
        blade.get_directory_services_local_directory_services.return_value = (
            get_response
        )

        server_response = Mock()
        server_response.status_code = 200
        server_response.items = []
        blade.get_servers.return_value = server_response

        try:
            main()
        except SystemExit:
            pass

        blade.delete_directory_services_local_directory_services.assert_not_called()
        assert module.exit_json.call_args[1]["changed"] is True

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", True)
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

    @patch("plugins.modules.purefb_local_ds.LooseVersion")
    @patch("plugins.modules.purefb_local_ds.get_system")
    @patch("plugins.modules.purefb_local_ds.AnsibleModule")
    @patch("plugins.modules.purefb_local_ds.HAS_PYPURECLIENT", False)
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

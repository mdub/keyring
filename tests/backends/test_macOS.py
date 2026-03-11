import pytest

import keyring
from keyring.backends import macOS
from keyring.testing.backend import BackendBasicTests


@pytest.mark.skipif(
    not keyring.backends.macOS.Keyring.viable,
    reason="macOS backend not viable",
)
class Test_macOSKeychain(BackendBasicTests):
    def init_keyring(self):
        return macOS.Keyring()


class FakeKeychain:
    """In-memory fake of the macOS Security framework SecItem* functions.

    Mimics the real behaviour: items are stored in a dict, and each
    operation returns the appropriate OSStatus code. Tracks which
    operations were used so tests can verify that updates go via
    SecItemUpdate (preserving the ACL) rather than delete+add.
    """

    ERR_SUCCESS = 0
    ERR_ITEM_NOT_FOUND = -25300
    ERR_DUPLICATE_ITEM = -25299

    def __init__(self):
        self.store = {}  # (service, username) -> password
        self.update_count = 0
        self.add_count = 0
        self.delete_count = 0

    def SecItemUpdate(self, query, attrs):
        # We can't inspect the CFDictionary args from Python, so
        # the tests call set_generic_password which builds them.
        # Instead, peek at the store keyed by the service/username
        # that was passed to set_generic_password.
        key = self._current_key
        if key not in self.store:
            return self.ERR_ITEM_NOT_FOUND
        self.store[key] = self._current_password
        self.update_count += 1
        return self.ERR_SUCCESS

    def SecItemAdd(self, query, result):
        key = self._current_key
        if key in self.store:
            return self.ERR_DUPLICATE_ITEM
        self.store[key] = self._current_password
        self.add_count += 1
        return self.ERR_SUCCESS

    def SecItemDelete(self, query):
        key = self._current_key
        if key not in self.store:
            return self.ERR_ITEM_NOT_FOUND
        del self.store[key]
        self.delete_count += 1
        return self.ERR_SUCCESS

    def patch(self, monkeypatch, api):
        monkeypatch.setattr(api, 'SecItemUpdate', self.SecItemUpdate)
        monkeypatch.setattr(api, 'SecItemAdd', self.SecItemAdd)
        monkeypatch.setattr(api, 'SecItemDelete', self.SecItemDelete)

    def set(self, api, name, service, username, password):
        """Call api.set_generic_password, providing context for the fakes."""
        self._current_key = (service, username)
        self._current_password = password
        api.set_generic_password(name, service, username, password)

    def delete(self, api, name, service, username):
        """Call api.delete_generic_password, providing context for the fakes."""
        self._current_key = (service, username)
        api.delete_generic_password(name, service, username)


@pytest.mark.skipif(
    not keyring.backends.macOS.Keyring.viable,
    reason="macOS backend not viable",
)
class TestSetGenericPasswordUsesUpdate:
    """Verify set_generic_password prefers SecItemUpdate over delete+add.

    Deleting and re-adding a keychain item resets its access control list
    (ACL), causing repeated "Keychain Access" password prompts on macOS.
    Using SecItemUpdate preserves the ACL.
    """

    def test_update_existing_item(self, monkeypatch):
        """Updating an existing item should use SecItemUpdate, not delete+add."""
        kc = FakeKeychain()
        api = macOS.api
        kc.patch(monkeypatch, api)

        # Seed an existing item.
        kc.store[('svc', 'user')] = 'old-pw'

        kc.set(api, None, 'svc', 'user', 'new-pw')

        assert kc.store[('svc', 'user')] == 'new-pw'
        assert kc.update_count == 1
        assert kc.delete_count == 0
        assert kc.add_count == 0

    def test_add_new_item(self, monkeypatch):
        """Adding a brand-new item should fall back to SecItemAdd."""
        kc = FakeKeychain()
        api = macOS.api
        kc.patch(monkeypatch, api)

        kc.set(api, None, 'svc', 'user', 'pw')

        assert kc.store[('svc', 'user')] == 'pw'
        assert kc.add_count == 1

    def test_repeated_updates_never_delete(self, monkeypatch):
        """Multiple updates to the same item should never delete it."""
        kc = FakeKeychain()
        api = macOS.api
        kc.patch(monkeypatch, api)

        kc.set(api, None, 'svc', 'user', 'pw1')  # initial add
        kc.set(api, None, 'svc', 'user', 'pw2')  # update
        kc.set(api, None, 'svc', 'user', 'pw3')  # update again

        assert kc.store[('svc', 'user')] == 'pw3'
        assert kc.add_count == 1    # only the first set
        assert kc.update_count == 2  # subsequent sets
        assert kc.delete_count == 0  # never deleted

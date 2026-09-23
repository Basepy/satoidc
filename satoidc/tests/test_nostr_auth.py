import importlib.util
import sys
from pathlib import Path

import pytest


def load_nostr_module():
    module_path = Path(__file__).resolve().parents[1] / "satoidc" / "auth" / "nostr.py"
    spec = importlib.util.spec_from_file_location("nostr_auth_test_module", module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


nostr = load_nostr_module()


def test_generate_keys_can_be_restored_from_nsec():
    keys = nostr.generate_keys()

    restored = nostr.keys_from_private_key(keys.nsec)

    assert restored.private_key_hex == keys.private_key_hex
    assert restored.public_key_hex == keys.public_key_hex
    assert restored.npub == keys.npub


def test_public_key_can_be_normalized_from_npub():
    keys = nostr.generate_keys()

    assert nostr.normalize_public_key(keys.npub) == keys.public_key_hex


def test_invalid_private_key_is_rejected():
    with pytest.raises(nostr.NostrKeyError):
        nostr.keys_from_private_key("not-a-valid-nsec")

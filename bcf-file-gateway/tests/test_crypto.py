"""mounts.py 加密工具测试（PBKDF2 密钥派生 + Fernet 加解密）。"""

from __future__ import annotations

import pytest

from gateway.approval.mounts import (
    _derive_key,
    decrypt_password,
    encrypt_password,
)


class TestDeriveKey:
    """PBKDF2 密钥派生测试。"""

    def test_derive_key_returns_valid_fernet_key(self):
        """派生的密钥应是有效的 Fernet base64 编码密钥。"""
        key = _derive_key("test-secret")
        assert len(key) == 44  # 32 bytes → base64 = 44 chars
        assert key.endswith(b"=")  # base64 padding

    def test_derive_key_is_deterministic(self):
        """相同 secret 应派生出相同的密钥。"""
        key1 = _derive_key("my-secret")
        key2 = _derive_key("my-secret")
        assert key1 == key2

    def test_derive_key_differs_for_different_secrets(self):
        """不同 secret 应派生出不同的密钥。"""
        key1 = _derive_key("secret-a")
        key2 = _derive_key("secret-b")
        assert key1 != key2


class TestEncryptDecryptPassword:
    """Fernet 加解密往返测试。"""

    def test_roundtrip(self):
        """加密后解密应恢复原始明文。"""
        secret = "test-secret-key"
        plain = "my_smb_password"

        encrypted = encrypt_password(plain, secret)
        decrypted = decrypt_password(encrypted, secret)

        assert decrypted == plain

    def test_encrypted_differs_from_plain(self):
        """加密结果不应与明文相同。"""
        secret = "test-secret-key"
        plain = "my_smb_password"

        encrypted = encrypt_password(plain, secret)
        assert encrypted != plain

    def test_wrong_secret_fails(self):
        """使用错误的 secret 解密应抛出异常。"""
        from cryptography.fernet import InvalidToken

        encrypted = encrypt_password("password", "correct-secret")

        with pytest.raises(InvalidToken):
            decrypt_password(encrypted, "wrong-secret")

    def test_unicode_password_roundtrip(self):
        """Unicode 密码应能正确加解密。"""
        secret = "test-secret"
        plain = "密码テスト"

        encrypted = encrypt_password(plain, secret)
        decrypted = decrypt_password(encrypted, secret)

        assert decrypted == plain

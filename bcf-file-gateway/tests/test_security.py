"""security.py 路径白名单校验和 token 测试。"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from gateway.security import (
    FileNotAvailableError,
    InvalidPathError,
    LinkInvalidError,
    build_download_url,
    generate_token,
    validate_path,
    verify_download_token,
)


# ── validate_path 测试 ──


class TestValidatePath:
    """路径白名单校验测试。"""

    def test_rejects_relative_path(self, tmp_path: Path):
        """相对路径应被拒绝。"""
        with pytest.raises(InvalidPathError, match="必须是绝对路径"):
            validate_path("relative/path.txt", [str(tmp_path)])

    def test_rejects_empty_path(self, tmp_path: Path):
        """空路径应被拒绝。"""
        with pytest.raises(InvalidPathError):
            validate_path("", [str(tmp_path)])

    def test_rejects_path_outside_allowed_roots(self, tmp_path: Path):
        """不在白名单目录内的路径应被拒绝。"""
        allowed = [str(tmp_path / "allowed")]
        (tmp_path / "allowed").mkdir()
        outside = tmp_path / "outside" / "file.txt"
        outside.parent.mkdir()
        outside.write_text("secret")

        with pytest.raises(InvalidPathError, match="不在允许"):
            validate_path(str(outside), allowed)

    def test_accepts_path_inside_allowed_root(self, tmp_path: Path):
        """白名单目录内的文件应被接受。"""
        allowed = [str(tmp_path)]
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        result = validate_path(str(test_file), allowed)
        assert result == str(test_file)

    def test_resolves_symlinks(self, tmp_path: Path):
        """符号链接应被解析为真实路径后再校验。"""
        allowed = [str(tmp_path / "real")]
        (tmp_path / "real").mkdir()
        real_file = tmp_path / "real" / "file.txt"
        real_file.write_text("content")

        # 创建符号链接指向真实文件
        link = tmp_path / "link.txt"
        link.symlink_to(real_file)

        result = validate_path(str(link), allowed)
        assert result == str(real_file)

    def test_symlink_escape_rejected(self, tmp_path: Path):
        """符号链接穿越到白名单外的路径应被拒绝。"""
        allowed = [str(tmp_path / "allowed")]
        (tmp_path / "allowed").mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        outside_file = outside_dir / "secret.txt"
        outside_file.write_text("secret")

        # 在白名单目录内创建指向外部的符号链接
        link = tmp_path / "allowed" / "escape.txt"
        link.symlink_to(outside_file)

        with pytest.raises(InvalidPathError, match="不在允许"):
            validate_path(str(link), allowed)

    def test_bypass_whitelist_skips_root_check(self, tmp_path: Path):
        """bypass_whitelist=True 应跳过白名单检查。"""
        test_file = tmp_path / "anywhere" / "file.txt"
        test_file.parent.mkdir()
        test_file.write_text("content")

        result = validate_path(str(test_file), [], bypass_whitelist=True)
        assert result == str(test_file)

    def test_nonexistent_file_rejected(self, tmp_path: Path):
        """不存在的文件应被拒绝。"""
        allowed = [str(tmp_path)]
        missing = tmp_path / "does_not_exist.txt"

        with pytest.raises(FileNotAvailableError, match="不存在"):
            validate_path(str(missing), allowed)

    def test_directory_rejected(self, tmp_path: Path):
        """目录（非普通文件）应被拒绝。"""
        allowed = [str(tmp_path)]
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        with pytest.raises(FileNotAvailableError):
            validate_path(str(subdir), allowed)


# ── generate_token 测试 ──


class TestGenerateToken:
    """Token 生成测试。"""

    def test_token_length(self):
        """生成的 token 应为 64 个十六进制字符。"""
        token = generate_token()
        assert len(token) == 64
        assert all(c in "0123456789abcdef" for c in token)

    def test_tokens_are_unique(self):
        """连续生成的 token 应不同。"""
        tokens = {generate_token() for _ in range(100)}
        assert len(tokens) == 100


# ── build_download_url / verify_download_token 测试 ──


class TestDownloadTokenFlow:
    """下载链接生成和验证流程测试。"""

    def test_build_download_url_returns_tuple(self):
        """build_download_url 应返回 (url, exp, token) 三元组。"""
        config = MagicMock()
        config.base_url.return_value = "http://192.168.1.1:8790"

        url, exp, token = build_download_url(config, "/path/to/file.txt", 3600)

        assert url.startswith("http://192.168.1.1:8790/dl/")
        assert len(token) == 64
        assert isinstance(exp, int)
        assert exp > 0

    def test_verify_download_token_invalid_token(self):
        """无效 token 应抛出 LinkInvalidError。"""
        config = MagicMock()
        config.allowed_roots = ["/tmp"]
        db = MagicMock()
        db.verify_link_token.return_value = None

        with pytest.raises(LinkInvalidError, match="无效或已过期"):
            verify_download_token(config, db, "invalid_token")

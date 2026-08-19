"""挂载点 CRUD + 四种协议（SMB/FTP/WebDAV/SCP）的连接与文件操作。"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet
import base64
import hashlib

from .models import _connect


# ── 加密工具（挂载点密码存储） ──

def _derive_key(secret: str) -> bytes:
    """从 config secret 派生 Fernet 密钥。"""
    digest = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_password(plain: str, secret: str) -> str:
    f = Fernet(_derive_key(secret))
    return f.encrypt(plain.encode()).decode()


def decrypt_password(enc: str, secret: str) -> str:
    f = Fernet(_derive_key(secret))
    return f.decrypt(enc.encode()).decode()


# ── 文件信息 ──

@dataclass
class FileInfo:
    name: str
    path: str          # 相对于挂载点根的路径
    size: int
    mtime: float
    is_dir: bool


# ── 协议适配器抽象层 ──

class ProtocolAdapter:
    """远程文件系统的统一接口。"""

    def test_connection(self) -> bool:
        raise NotImplementedError

    def list_files(self, remote_path: str = "") -> list[FileInfo]:
        raise NotImplementedError

    def copy_file(self, src_rel_path: str, local_dest: str) -> None:
        """从远程复制到本地路径。"""
        raise NotImplementedError

    def move_to_status_dir(self, src_rel_path: str, status_dir: str) -> None:
        """将源文件移动到状态目录（.accepted/.rejected/.exception/.review）。"""
        raise NotImplementedError

    def write_text_file(self, rel_path: str, content: str) -> None:
        """在远程指定路径写入文本文件。"""
        raise NotImplementedError

    def upload_file(self, local_path: str, dest_rel_path: str) -> None:
        """从本地上传文件到远程指定相对路径。"""
        raise NotImplementedError


class LocalAdapter(ProtocolAdapter):
    """本地文件系统适配器（用于测试或本地目录）。"""

    def __init__(self, base_path: str):
        self.base = Path(base_path)

    def test_connection(self) -> bool:
        return self.base.is_dir()

    def list_files(self, remote_path: str = "") -> list[FileInfo]:
        target = self.base / remote_path if remote_path else self.base
        if not target.is_dir():
            return []
        result = []
        for item in target.rglob("*"):
            rel = str(item.relative_to(self.base))
            # 跳过状态目录
            parts = Path(rel).parts
            if any(p.startswith(".") and p in (".accepted", ".rejected", ".exception", ".review") for p in parts):
                continue
            try:
                stat = item.stat()
                result.append(FileInfo(
                    name=item.name,
                    path=rel,
                    size=stat.st_size if item.is_file() else 0,
                    mtime=stat.st_mtime,
                    is_dir=item.is_dir(),
                ))
            except OSError:
                continue
        return [f for f in result if not f.is_dir]

    def copy_file(self, src_rel_path: str, local_dest: str) -> None:
        import shutil
        src = self.base / src_rel_path
        dest = Path(local_dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)

    def move_to_status_dir(self, src_rel_path: str, status_dir: str) -> None:
        import shutil
        src = self.base / src_rel_path
        dest = self.base / status_dir / src_rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dest))

    def write_text_file(self, rel_path: str, content: str) -> None:
        dest = self.base / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")

    def upload_file(self, local_path: str, dest_rel_path: str) -> None:
        import shutil
        dest = self.base / dest_rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(local_path, str(dest))


class SMBAdapter(ProtocolAdapter):
    """SMB/CIFS 协议适配器。"""

    def __init__(self, host: str, port: int, username: str, password: str, remote_path: str):
        self.host = host
        self.port = port or 445
        self.username = username
        self.password = password
        self.remote_path = remote_path.strip("/")

    def _get_connection(self):
        from smbprotocol.connection import Connection
        from smbprotocol.session import Session
        from smbprotocol.tree import TreeConnect
        conn = Connection(uuid_gen=True, server_name=self.host, port=self.port)
        conn.connect()
        session = Session(conn, self.username, self.password)
        session.connect()
        share = self.remote_path.split("/")[0] if self.remote_path else ""
        tree = TreeConnect(session, r"\\{}\{}".format(self.host, share))
        tree.connect()
        return conn, session, tree

    def test_connection(self) -> bool:
        try:
            _, session, tree = self._get_connection()
            return True
        except Exception:
            return False

    def _walk_dir(self, tree, remote_dir: str) -> list[FileInfo]:
        """递归遍历 SMB 目录。"""
        from smbprotocol.open import Open, CreateDisposition, FilePipePrinterAccessMask, ImpersonationLevel, ShareAccess, FileAttributes, CreateOptions
        from smbprotocol.file_info import FileInformationClass
        results = []
        try:
            dir_open = Open(tree, remote_dir)
            dir_open.create(
                impersonation_level=2,
                desired_access=FilePipePrinterAccessMask.FILE_LIST_DIRECTORY,
                share_access=ShareAccess.FILE_SHARE_READ,
                create_disposition=CreateDisposition.FILE_OPEN,
                create_options=CreateOptions.FILE_DIRECTORY_FILE,
            )
            entries = dir_open.query_directory("*", FileInformationClass.FILE_DIRECTORY_INFORMATION)
            dir_open.close()
            for entry in entries:
                name = entry["file_name"].get_value().decode("utf-16-le", errors="replace")
                if name in (".", ".."):
                    continue
                attrs = entry.get("file_attributes", 0)
                is_dir = bool(attrs & 0x10) if isinstance(attrs, int) else False
                rel = f"{remote_dir}/{name}" if remote_dir else name
                if is_dir:
                    if name in (".accepted", ".rejected", ".exception", ".review"):
                        continue
                    results.extend(self._walk_dir(tree, rel))
                else:
                    results.append(FileInfo(
                        name=name, path=rel,
                        size=entry.get("end_of_file", 0),
                        mtime=time.time(), is_dir=False,
                    ))
        except Exception:
            pass
        return results

    def list_files(self, remote_path: str = "") -> list[FileInfo]:
        try:
            _, session, tree = self._get_connection()
        except Exception:
            return []
        return self._walk_dir(tree, self.remote_path)

    def copy_file(self, src_rel_path: str, local_dest: str) -> None:
        from smbprotocol.open import Open, CreateDisposition, FilePipePrinterAccessMask, ShareAccess, CreateOptions
        from smbprotocol.file_info import FileInformationClass
        _, session, tree = self._get_connection()
        full_path = f"{self.remote_path}/{src_rel_path}".strip("/")
        dest = Path(local_dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        file_open = Open(tree, full_path)
        file_open.create(
            impersonation_level=2,
            desired_access=FilePipePrinterAccessMask.FILE_READ_DATA,
            share_access=ShareAccess.FILE_SHARE_READ,
            create_disposition=CreateDisposition.FILE_OPEN,
        )
        data = b""
        offset = 0
        while True:
            chunk = file_open.read(offset, 65536)
            if not chunk:
                break
            data += chunk
            offset += len(chunk)
        file_open.close()
        with open(local_dest, "wb") as f:
            f.write(data)

    def move_to_status_dir(self, src_rel_path: str, status_dir: str) -> None:
        from smbprotocol.open import Open, CreateDisposition, FilePipePrinterAccessMask, ShareAccess, CreateOptions
        _, session, tree = self._get_connection()
        src = f"{self.remote_path}/{src_rel_path}".strip("/")
        dest = f"{self.remote_path}/{status_dir}/{src_rel_path}".strip("/")
        # 确保目标目录存在（通过创建一个临时文件再删除来创建目录）
        dest_dir = "/".join(dest.split("/")[:-1])
        try:
            dir_open = Open(tree, dest_dir)
            dir_open.create(
                impersonation_level=2,
                desired_access=FilePipePrinterAccessMask.FILE_LIST_DIRECTORY,
                share_access=ShareAccess.FILE_SHARE_READ,
                create_disposition=CreateDisposition.FILE_CREATE,
                create_options=CreateOptions.FILE_DIRECTORY_FILE,
            )
            dir_open.close()
        except Exception:
            pass
        # 移动文件
        file_open = Open(tree, src)
        file_open.create(
            impersonation_level=2,
            desired_access=FilePipePrinterAccessMask.FILE_READ_DATA | FilePipePrinterAccessMask.FILE_WRITE_DATA | FilePipePrinterAccessMask.DELETE,
            share_access=ShareAccess.FILE_SHARE_READ,
            create_disposition=CreateDisposition.FILE_OPEN,
        )
        file_open.set_file_info({"file_name": dest}, FileInformationClass.FILE_RENAME_INFORMATION)
        file_open.close()

    def write_text_file(self, rel_path: str, content: str) -> None:
        from smbprotocol.open import Open, CreateDisposition, FilePipePrinterAccessMask, ShareAccess, CreateOptions
        _, session, tree = self._get_connection()
        full_path = f"{self.remote_path}/{rel_path}".strip("/")
        # 确保目录存在
        dir_path = "/".join(full_path.split("/")[:-1])
        try:
            dir_open = Open(tree, dir_path)
            dir_open.create(
                impersonation_level=2,
                desired_access=FilePipePrinterAccessMask.FILE_LIST_DIRECTORY,
                share_access=ShareAccess.FILE_SHARE_READ,
                create_disposition=CreateDisposition.FILE_CREATE,
                create_options=CreateOptions.FILE_DIRECTORY_FILE,
            )
            dir_open.close()
        except Exception:
            pass
        file_open = Open(tree, full_path)
        file_open.create(
            impersonation_level=2,
            desired_access=FilePipePrinterAccessMask.FILE_WRITE_DATA,
            share_access=ShareAccess.FILE_SHARE_READ,
            create_disposition=CreateDisposition.FILE_CREATE,
        )
        file_open.write(content.encode("utf-8"), 0)
        file_open.close()

    def upload_file(self, local_path: str, dest_rel_path: str) -> None:
        from smbprotocol.open import Open, CreateDisposition, FilePipePrinterAccessMask, ShareAccess, CreateOptions
        _, session, tree = self._get_connection()
        full_path = f"{self.remote_path}/{dest_rel_path}".strip("/")
        dir_path = "/".join(full_path.split("/")[:-1])
        try:
            dir_open = Open(tree, dir_path)
            dir_open.create(
                impersonation_level=2,
                desired_access=FilePipePrinterAccessMask.FILE_LIST_DIRECTORY,
                share_access=ShareAccess.FILE_SHARE_READ,
                create_disposition=CreateDisposition.FILE_CREATE,
                create_options=CreateOptions.FILE_DIRECTORY_FILE,
            )
            dir_open.close()
        except Exception:
            pass
        with open(local_path, "rb") as f:
            data = f.read()
        file_open = Open(tree, full_path)
        file_open.create(
            impersonation_level=2,
            desired_access=FilePipePrinterAccessMask.FILE_WRITE_DATA,
            share_access=ShareAccess.FILE_SHARE_READ,
            create_disposition=CreateDisposition.FILE_CREATE,
        )
        file_open.write(data, 0)
        file_open.close()


class FTPAdapter(ProtocolAdapter):
    """FTP 协议适配器。"""

    def __init__(self, host: str, port: int, username: str, password: str, remote_path: str):
        self.host = host
        self.port = port or 21
        self.username = username
        self.password = password
        self.remote_path = remote_path.strip("/")

    def _get_ftp(self):
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(self.host, self.port)
        ftp.login(self.username, self.password)
        return ftp

    def test_connection(self) -> bool:
        try:
            ftp = self._get_ftp()
            ftp.quit()
            return True
        except Exception:
            return False

    def _list_dir_recursive(self, ftp, ftp_dir: str, base_rel: str, results: list) -> None:
        """递归列出 FTP 目录中的文件。"""
        try:
            ftp.cwd(ftp_dir)
            entries = []
            ftp.retrlines("LIST", entries.append)
            for line in entries:
                parts = line.split(None, 8)
                if len(parts) < 9:
                    continue
                name = parts[8]
                is_dir = line.startswith("d")
                rel = f"{base_rel}/{name}" if base_rel else name
                if is_dir:
                    if name in (".", "..", ".accepted", ".rejected", ".exception", ".review"):
                        continue
                    sub_dir = f"{ftp_dir}/{name}"
                    self._list_dir_recursive(ftp, sub_dir, rel, results)
                else:
                    size = int(parts[4]) if parts[4].isdigit() else 0
                    results.append(FileInfo(
                        name=name, path=rel,
                        size=size, mtime=time.time(), is_dir=False,
                    ))
        except Exception:
            pass

    def list_files(self, remote_path: str = "") -> list[FileInfo]:
        results = []
        try:
            ftp = self._get_ftp()
            base = f"{self.remote_path}/{remote_path}".strip("/") if remote_path else self.remote_path
            ftp_dir = "/" + base if base else "/"
            self._list_dir_recursive(ftp, ftp_dir, "", results)
            ftp.quit()
        except Exception:
            pass
        return results

    def copy_file(self, src_rel_path: str, local_dest: str) -> None:
        import ftplib
        ftp = self._get_ftp()
        full_path = f"/{self.remote_path}/{src_rel_path}".replace("//", "/")
        dest = Path(local_dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            ftp.retrbinary(f"RETR {full_path}", f.write)
        ftp.quit()

    def move_to_status_dir(self, src_rel_path: str, status_dir: str) -> None:
        import ftplib
        ftp = self._get_ftp()
        src = f"/{self.remote_path}/{src_rel_path}".replace("//", "/")
        dest = f"/{self.remote_path}/{status_dir}/{src_rel_path}".replace("//", "/")
        # 确保目标目录存在
        status_base = f"/{self.remote_path}/{status_dir}".replace("//", "/")
        try:
            ftp.mkd(status_base)
        except ftplib.error_perm:
            pass  # 目录可能已存在
        # 创建子目录
        dest_dir = "/".join(dest.split("/")[:-1])
        try:
            ftp.mkd(dest_dir)
        except ftplib.error_perm:
            pass
        ftp.rename(src, dest)
        ftp.quit()

    def write_text_file(self, rel_path: str, content: str) -> None:
        import ftplib
        import io
        ftp = self._get_ftp()
        full_path = f"/{self.remote_path}/{rel_path}".replace("//", "/")
        # 确保目录存在
        parts = full_path.split("/")[:-1]
        for i in range(2, len(parts) + 1):
            d = "/".join(parts[:i])
            try:
                ftp.mkd(d)
            except ftplib.error_perm:
                pass
        data = io.BytesIO(content.encode("utf-8"))
        ftp.storbinary(f"STOR {full_path}", data)
        ftp.quit()

    def upload_file(self, local_path: str, dest_rel_path: str) -> None:
        import ftplib
        ftp = self._get_ftp()
        full_path = f"/{self.remote_path}/{dest_rel_path}".replace("//", "/")
        parts = full_path.split("/")[:-1]
        for i in range(2, len(parts) + 1):
            d = "/".join(parts[:i])
            try:
                ftp.mkd(d)
            except ftplib.error_perm:
                pass
        with open(local_path, "rb") as f:
            ftp.storbinary(f"STOR {full_path}", f)
        ftp.quit()


class WebDAVAdapter(ProtocolAdapter):
    """WebDAV 协议适配器。"""

    def __init__(self, host: str, port: int, username: str, password: str, remote_path: str):
        self.host = host
        self.port = port or 80
        self.username = username
        self.password = password
        self.remote_path = remote_path.strip("/")

    def _get_client(self):
        from webdav3.client import Client
        options = {
            "webdav_hostname": f"http://{self.host}:{self.port}",
            "webdav_login": self.username,
            "webdav_password": self.password,
            "webdav_root": f"/{self.remote_path}" if self.remote_path else "/",
        }
        return Client(options)

    def test_connection(self) -> bool:
        try:
            client = self._get_client()
            client.list()
            return True
        except Exception:
            return False

    def _list_dir_recursive(self, client, dir_path: str, base_rel: str, results: list) -> None:
        """递归列出 WebDAV 目录中的文件。"""
        try:
            items = client.list(dir_path) if dir_path else client.list()
            for item_name in items:
                rel = f"{base_rel}/{item_name}" if base_rel else item_name
                try:
                    info = client.info(rel)
                    is_dir = info.get("isdir", False) or info.get("content_type", "") == "httpd/unix-directory"
                    if is_dir:
                        if item_name in (".accepted", ".rejected", ".exception", ".review"):
                            continue
                        self._list_dir_recursive(client, rel, rel, results)
                    else:
                        size = int(info.get("size", 0) or 0)
                        results.append(FileInfo(
                            name=item_name, path=rel,
                            size=size, mtime=time.time(), is_dir=False,
                        ))
                except Exception:
                    continue
        except Exception:
            pass

    def list_files(self, remote_path: str = "") -> list[FileInfo]:
        results = []
        try:
            client = self._get_client()
            self._list_dir_recursive(client, "", "", results)
        except Exception:
            pass
        return results

    def copy_file(self, src_rel_path: str, local_dest: str) -> None:
        client = self._get_client()
        dest = Path(local_dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        client.download_sync(src_rel_path, str(dest))

    def move_to_status_dir(self, src_rel_path: str, status_dir: str) -> None:
        client = self._get_client()
        dest = f"{status_dir}/{src_rel_path}"
        # 确保目录存在
        try:
            client.mkdir(status_dir)
        except Exception:
            pass
        dest_dir = "/".join(dest.split("/")[:-1])
        try:
            client.mkdir(dest_dir)
        except Exception:
            pass
        client.move(src_rel_path, dest)

    def write_text_file(self, rel_path: str, content: str) -> None:
        import tempfile
        client = self._get_client()
        # 确保目录存在
        parts = rel_path.split("/")
        if len(parts) > 1:
            dir_path = "/".join(parts[:-1])
            try:
                client.mkdir(dir_path)
            except Exception:
                pass
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            client.upload_sync(tmp_path, rel_path)
        finally:
            os.unlink(tmp_path)

    def upload_file(self, local_path: str, dest_rel_path: str) -> None:
        client = self._get_client()
        parts = dest_rel_path.split("/")
        if len(parts) > 1:
            dir_path = "/".join(parts[:-1])
            try:
                client.mkdir(dir_path)
            except Exception:
                pass
        client.upload_sync(local_path, dest_rel_path)


class SCPAdapter(ProtocolAdapter):
    """SCP/SFTP 协议适配器（基于 paramiko）。"""

    def __init__(self, host: str, port: int, username: str, password: str, remote_path: str):
        self.host = host
        self.port = port or 22
        self.username = username
        self.password = password
        self.remote_path = remote_path.strip("/")

    def _get_sftp(self):
        import paramiko
        transport = paramiko.Transport((self.host, self.port))
        transport.connect(username=self.username, password=self.password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        return transport, sftp

    def test_connection(self) -> bool:
        try:
            transport, sftp = self._get_sftp()
            sftp.close()
            transport.close()
            return True
        except Exception:
            return False

    def _list_dir_recursive(self, sftp, remote_dir: str, base_rel: str, results: list) -> None:
        """递归列出 SFTP 目录中的文件。"""
        import stat
        try:
            entries = sftp.listdir_attr(remote_dir)
            for entry in entries:
                name = entry.filename
                rel = f"{base_rel}/{name}" if base_rel else name
                is_dir = stat.S_ISDIR(entry.st_mode) if entry.st_mode else False
                if is_dir:
                    if name in (".accepted", ".rejected", ".exception", ".review"):
                        continue
                    sub_dir = f"{remote_dir}/{name}"
                    self._list_dir_recursive(sftp, sub_dir, rel, results)
                else:
                    results.append(FileInfo(
                        name=name, path=rel,
                        size=entry.st_size or 0,
                        mtime=entry.st_mtime or time.time(), is_dir=False,
                    ))
        except Exception:
            pass

    def list_files(self, remote_path: str = "") -> list[FileInfo]:
        results = []
        try:
            transport, sftp = self._get_sftp()
            base = f"{self.remote_path}/{remote_path}".strip("/") if remote_path else self.remote_path
            self._list_dir_recursive(sftp, base if base else ".", "", results)
            sftp.close()
            transport.close()
        except Exception:
            pass
        return results

    def copy_file(self, src_rel_path: str, local_dest: str) -> None:
        transport, sftp = self._get_sftp()
        full_path = f"{self.remote_path}/{src_rel_path}"
        dest = Path(local_dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        sftp.get(full_path, str(dest))
        sftp.close()
        transport.close()

    def move_to_status_dir(self, src_rel_path: str, status_dir: str) -> None:
        import stat as stat_mod
        transport, sftp = self._get_sftp()
        src = f"{self.remote_path}/{src_rel_path}"
        dest = f"{self.remote_path}/{status_dir}/{src_rel_path}"
        # 确保目标目录存在
        status_base = f"{self.remote_path}/{status_dir}"
        try:
            sftp.mkdir(status_base)
        except OSError:
            pass
        dest_dir = "/".join(dest.split("/")[:-1])
        try:
            # 递归创建目录
            parts = dest_dir.split("/")
            for i in range(len(parts)):
                d = "/".join(parts[:i+1])
                try:
                    sftp.mkdir(d)
                except OSError:
                    pass
        except Exception:
            pass
        sftp.rename(src, dest)
        sftp.close()
        transport.close()

    def write_text_file(self, rel_path: str, content: str) -> None:
        transport, sftp = self._get_sftp()
        full_path = f"{self.remote_path}/{rel_path}"
        # 确保目录存在
        parts = full_path.split("/")[:-1]
        for i in range(2, len(parts) + 1):
            d = "/".join(parts[:i])
            try:
                sftp.mkdir(d)
            except OSError:
                pass
        with sftp.open(full_path, "w") as f:
            f.write(content)
        sftp.close()
        transport.close()

    def upload_file(self, local_path: str, dest_rel_path: str) -> None:
        transport, sftp = self._get_sftp()
        full_path = f"{self.remote_path}/{dest_rel_path}"
        parts = full_path.split("/")[:-1]
        for i in range(2, len(parts) + 1):
            d = "/".join(parts[:i])
            try:
                sftp.mkdir(d)
            except OSError:
                pass
        sftp.put(local_path, full_path)
        sftp.close()
        transport.close()


# ── 适配器工厂 ──

def create_adapter(mount: dict, secret: str) -> ProtocolAdapter:
    """根据挂载点配置创建对应的协议适配器。"""
    protocol = mount["protocol"]
    password = ""
    if mount.get("password_enc"):
        password = decrypt_password(mount["password_enc"], secret)

    if protocol == "local":
        return LocalAdapter(mount["remote_path"])
    elif protocol == "smb":
        return SMBAdapter(mount["host"], mount.get("port", 445),
                         mount.get("username", ""), password, mount["remote_path"])
    elif protocol == "ftp":
        return FTPAdapter(mount["host"], mount.get("port", 21),
                         mount.get("username", ""), password, mount["remote_path"])
    elif protocol == "webdav":
        return WebDAVAdapter(mount["host"], mount.get("port", 80),
                            mount.get("username", ""), password, mount["remote_path"])
    elif protocol == "scp":
        return SCPAdapter(mount["host"], mount.get("port", 22),
                         mount.get("username", ""), password, mount["remote_path"])
    else:
        raise ValueError(f"不支持的协议类型: {protocol}")


# ── 挂载点 CRUD ──

def create_mount(db_path: Path, secret: str, name: str, protocol: str, host: str,
                 port: int | None, remote_path: str, username: str | None,
                 password: str | None, mount_type: str, created_by: int) -> int:
    """创建挂载点，返回 mount_id。"""
    now = time.time()
    pwd_enc = encrypt_password(password, secret) if password else None
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO mounts
               (name, protocol, host, port, remote_path, username, password_enc,
                mount_type, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, protocol, host, port, remote_path, username, pwd_enc,
             mount_type, created_by, now, now),
        )
        return cursor.lastrowid


def get_mount(db_path: Path, mount_id: int) -> dict | None:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM mounts WHERE id = ?", (mount_id,)).fetchone()
    return dict(row) if row else None


def list_mounts(db_path: Path, mount_type: str | None = None) -> list[dict]:
    with _connect(db_path) as conn:
        if mount_type:
            rows = conn.execute(
                "SELECT * FROM mounts WHERE mount_type = ? AND is_active = 1 ORDER BY name",
                (mount_type,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM mounts WHERE is_active = 1 ORDER BY name"
            ).fetchall()
    return [dict(r) for r in rows]


def update_mount(db_path: Path, mount_id: int, **kwargs) -> None:
    allowed = {"name", "protocol", "host", "port", "remote_path", "username",
               "password_enc", "mount_type", "is_active"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return
    updates["updated_at"] = time.time()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [mount_id]
    with _connect(db_path) as conn:
        conn.execute(f"UPDATE mounts SET {set_clause} WHERE id = ?", values)


def delete_mount(db_path: Path, mount_id: int) -> None:
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM mounts WHERE id = ?", (mount_id,))


def test_mount_connection(mount: dict, secret: str) -> bool:
    """测试挂载点连接是否可用。"""
    try:
        adapter = create_adapter(mount, secret)
        return adapter.test_connection()
    except Exception:
        return False

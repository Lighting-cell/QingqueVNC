"""Multi-server VNC connection manager implemented with PySide6."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import select
import socket
import sys
import threading
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path

import paramiko
import qdarktheme
from app_paths import application_logs_directory, migrate_legacy_logs
from PySide6.QtCore import Qt, QTimer, QSignalBlocker, QTranslator, QUrl
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTreeView,
    QToolButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)
from qt_window_chrome import (
    apply_custom_chrome,
    create_dialog_body,
    qingque_icon,
)
from vnc_viewer import VncViewerWindow, connect_viewer


APP_NAME = "QingQueVNC"
SERVER_EXPORT_FORMAT = "QingQueVNC.servers"


def install_qt_chinese_translation(app):
    """Localize Qt-owned controls such as the file browser to Simplified Chinese."""
    package = sys.modules.get("PySide6")
    if package is None or not getattr(package, "__file__", None):
        return
    translation = Path(package.__file__).resolve().parent / "translations" / "qtbase_zh_CN.qm"
    if not translation.is_file():
        return
    translator = QTranslator(app)
    if translator.load(str(translation)):
        app.installTranslator(translator)
        app._qtbase_zh_cn_translator = translator


def install_app_font(app):
    font = QFont("Microsoft YaHei", 10)
    font.setBold(True)
    app.setFont(font)


class _ConfirmUnknownHostKey(paramiko.MissingHostKeyPolicy):
    def __init__(self, worker):
        self.worker = worker

    def missing_host_key(self, client, hostname, key):
        fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")
        prompt = (
            f"服务器 {hostname} 的主机密钥尚未记录。\n"
            f"{key.get_name()} SHA256:{fingerprint}\n"
            "请核对服务器指纹；确认可信后输入 yes，否则输入 no。"
        )
        accepted, answer = self.worker.request_ui(prompt)
        if not accepted or answer.strip().casefold() != "yes":
            raise paramiko.SSHException("用户未确认 SSH 主机密钥")
        client.get_host_keys().add(hostname, key.get_name(), key)
        known_hosts = self.worker.known_hosts_path
        known_hosts.parent.mkdir(parents=True, exist_ok=True)
        client.save_host_keys(str(known_hosts))


class _SSHForwardWorker(threading.Thread):
    """Owns the SSH session and local TCP forward so all network waits stay off the UI thread."""

    def __init__(self, server: dict, local_port: int, ui_queue: queue.Queue):
        super().__init__(name=f"SSH-Tunnel-{server['id'][:8]}", daemon=True)
        self.server_config = dict(server)
        self.server_id = server["id"]
        self.local_port = local_port
        self.ui_queue = ui_queue
        self.stop_event = threading.Event()
        self.client = None
        self.listener = None
        self.known_hosts_path = Path.home() / ".ssh" / "known_hosts"

    def request_ui(self, prompt: str):
        if self.stop_event.is_set():
            return False, ""
        response = queue.Queue(maxsize=1)
        self.ui_queue.put(("ssh_prompt", self.server_id, prompt, response))
        try:
            return response.get(timeout=300)
        except queue.Empty:
            return False, ""

    def emit(self, kind: str, *values):
        self.ui_queue.put((kind, self.server_id, *values))

    def stop(self):
        self.stop_event.set()
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError:
                pass
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass

    def run(self):
        password = ""
        try:
            cfg = self.server_config
            self.emit("ssh_output", f"正在连接 SSH：{cfg['ssh_user']}@{cfg['ssh_host']}:{cfg['ssh_port']}")
            self.client = paramiko.SSHClient()
            self.client.load_system_host_keys()
            if self.known_hosts_path.is_file():
                self.client.load_host_keys(str(self.known_hosts_path))
            self.client.set_missing_host_key_policy(_ConfirmUnknownHostKey(self))

            accepted, password = self.request_ui(f"{cfg['ssh_user']}@{cfg['ssh_host']}'s password:")
            if not accepted or self.stop_event.is_set():
                return

            identity_file = str(cfg.get("identity_file", "")).strip()
            if identity_file and not Path(identity_file).is_file():
                raise FileNotFoundError(f"找不到 SSH 私钥文件：{identity_file}")

            self.client.connect(
                hostname=cfg["ssh_host"],
                port=int(cfg["ssh_port"]),
                username=cfg["ssh_user"],
                password=password,
                key_filename=identity_file or None,
                allow_agent=False,
                look_for_keys=True,
                timeout=15,
                banner_timeout=15,
                auth_timeout=30,
                channel_timeout=15,
            )
            password = ""
            if self.stop_event.is_set():
                return

            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind(("127.0.0.1", self.local_port))
            self.listener.listen(64)
            self.listener.settimeout(0.5)
            self.emit("ssh_ready", self.local_port)

            while not self.stop_event.is_set():
                try:
                    local_socket, peer = self.listener.accept()
                except socket.timeout:
                    transport = self.client.get_transport()
                    if not transport or not transport.is_active():
                        raise paramiko.SSHException("SSH 连接已断开")
                    continue
                except OSError:
                    if self.stop_event.is_set():
                        break
                    raise
                threading.Thread(
                    target=self._forward_connection,
                    args=(local_socket, peer),
                    name=f"SSH-Forward-{self.server_id[:8]}",
                    daemon=True,
                ).start()
        except paramiko.AuthenticationException:
            if not self.stop_event.is_set():
                self.emit("ssh_failed", "SSH 认证失败：服务器拒绝了本次凭据，请核对用户名、密码或密钥。")
        except paramiko.BadHostKeyException:
            if not self.stop_event.is_set():
                self.emit("ssh_failed", "SSH 主机密钥与 known_hosts 中的记录不一致，已拒绝连接。请先核对服务器身份。")
        except Exception as exc:
            if not self.stop_event.is_set():
                message = str(exc).replace(password, "[已隐藏]") if password else str(exc)
                self.emit("ssh_failed", f"SSH 隧道失败：{type(exc).__name__}: {message}")
        finally:
            password = ""
            if self.listener is not None:
                try:
                    self.listener.close()
                except OSError:
                    pass
            if self.client is not None:
                try:
                    self.client.close()
                except Exception:
                    pass

    def _forward_connection(self, local_socket: socket.socket, peer):
        channel = None
        try:
            if self.stop_event.is_set():
                return
            transport = self.client.get_transport()
            if not transport or not transport.is_active():
                return
            target = self.server_config
            channel = transport.open_channel(
                "direct-tcpip",
                (target["target_host"], int(target["target_port"])),
                peer,
                timeout=15,
            )
            if channel is None:
                return
            endpoints = (local_socket, channel)
            while not self.stop_event.is_set():
                readable, _, _ = select.select(endpoints, [], [], 0.5)
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    destination = channel if source is local_socket else local_socket
                    destination.sendall(data)
        except (OSError, EOFError, paramiko.SSHException) as exc:
            if not self.stop_event.is_set():
                self.emit("ssh_output", f"VNC 转发通道已关闭：{type(exc).__name__}: {exc}")
        finally:
            try:
                local_socket.close()
            except OSError:
                pass
            if channel is not None:
                channel.close()


DEFAULT_CONFIG = {"servers": []}

APP_QSS = """
QWidget { color: #DEE0E6; font-family: "Microsoft YaHei"; font-size: 10.5pt; font-weight: 700; }
QMainWindow, QDialog { background: transparent; }
QWidget#WindowResizeSurface { background: #181A1F; border: 0px; border-radius: 0px; }
QWidget#DialogSurface { background: #24272E; border: 1px solid #3A3E47; border-radius: 16px; }
QWidget#DialogBody { background: #24272E; }
QWidget#MainPage { background: #181A1F; }
QWidget#CustomTitleBar { background: #181A1F; border: 0px; border-top-left-radius: 16px; border-top-right-radius: 16px; }
QLabel#TitleBarBrand {
    background: transparent; min-width: 27px; max-width: 27px;
    min-height: 27px; max-height: 27px;
}
QLabel#TitleBarText { color: #E5E7EC; font-size: 12px; font-weight: 700; }
QToolButton#TitleBarButton {
    background: transparent; color: #ABAFB9; border: 0px; border-radius: 10px;
    font-size: 16px; padding: 0px;
}
QToolButton#TitleBarButton:hover { background: #2D313A; color: #F2F3F5; }
QToolButton#TitleBarButton:pressed { background: #3A3E46; color: #FFFFFF; }
QToolButton#TitleBarClose:hover { background: #B84B55; color: #FFFFFF; }
QToolButton#TitleBarClose:pressed { background: #963A44; color: #FFFFFF; }
QLabel { color: #DEE0E6; }
QFrame#Card { background: #22262D; border: 1px solid #30343C; border-radius: 14px; }
QFrame#ViewerToolbar { background: #181A1F; border: 0px; border-bottom: 1px solid #343A44; }
QLabel#BrandBadge { background: transparent; }
QLabel#PageTitle { color: #E9EBEF; font-size: 23px; font-weight: 700; }
QLabel#Subtitle, QLabel#Muted { color: #9DA2AE; font-size: 10.5pt; }
QLabel#Eyebrow { color: #808FB1; font-size: 9pt; font-weight: 700; }
QLabel#SectionTitle { color: #DFE1E7; font-size: 13pt; font-weight: 700; }
QLabel#DetailTitle { color: #F1F2F4; font-size: 19px; font-weight: 700; }
QLabel#StatusPill { background: #20372F; color: #91D0B5; border-radius: 12px; padding: 7px 11px; font-weight: 700; }
QLabel#CountPill { background: #2A2E37; color: #B4B9C3; border-radius: 10px; padding: 6px 10px; font-weight: 700; }
QLabel#FooterStatus { color: #9EA3AE; font-size: 9.5pt; }
QLabel#ViewerStatus { color: #D7DAE1; font-weight: 700; }
QLabel#ViewerServerName { color: #E9EBEF; font-size: 11pt; font-weight: 700; }
QLabel#OnlineDot { color: #6EC6A2; font-size: 13px; }
QFrame#DetailInfo, QFrame#FormSection { background: #24272E; border: 1px solid #32363E; border-radius: 10px; }
QLabel#FieldCaption { color: #979CA7; font-size: 9pt; }
QLabel#FieldValue { color: #DDDFE5; font-size: 10pt; font-weight: 700; }
QTableWidget {
    background: #1A1C22; alternate-background-color: #22262D;
    color: #D7DAE1; border: 0px; gridline-color: transparent;
    selection-background-color: #33466D; selection-color: #F1F3FA; outline: 0px;
}
QTableWidget::item { padding: 9px 7px; border-bottom: 1px solid #292D36; }
QTableWidget::item:hover { background: #292D35; color: #F1F2F4; }
QTableWidget::item:selected { background: #33466D; color: #F1F3FA; }
QTableWidget::item:selected:hover { background: #3B4C75; }
QFileDialog QTreeView {
    background: #1A1C22; alternate-background-color: #22262D; color: #D7DAE1;
    border: 1px solid #353942; outline: 0px; selection-background-color: #33466D;
    selection-color: #F1F3FA;
}
QFileDialog QTreeView::item { padding: 6px 5px; }
QFileDialog QTreeView::item:hover { background: #292D35; }
QFileDialog QTreeView::item:selected { background: #33466D; color: #F1F3FA; }
QHeaderView::section {
    background: #24272E; color: #ADB1BB; border: 0px;
    border-bottom: 1px solid #393D45; padding: 11px 8px; font-weight: 700;
}
QPushButton {
    background: #292D35; color: #D8DBE2; border: 1px solid #3E424C;
    border-radius: 12px; min-height: 37px; padding: 0px 15px; font-weight: 700;
}
QPushButton:hover { background: #32363E; border-color: #5D626C; color: #F3F3F5; }
QPushButton:pressed { background: #24272D; border-color: #545C6E; }
QPushButton:focus { border: 1px solid #84A1F7; }
QPushButton:disabled { color: #787C84; background: #23262C; border-color: #30333A; }
QPushButton[primary="true"] { background: #4F75DF; color: #F6F7F9; border: 1px solid #5E83E9; }
QPushButton[primary="true"]:hover { background: #5E83E9; border-color: #84A1F7; color: #FFFFFF; }
QPushButton[primary="true"]:pressed { background: #3E5CB8; border-color: #5E83E9; }
QPushButton[primary="true"]:disabled { color: #878C97; background: #2F343E; border-color: #3C424F; }
QPushButton[danger="true"] { color: #E99A9D; background: #302629; border: 1px solid #624047; }
QPushButton[danger="true"]:hover { color: #FFD8D8; background: #493036; border-color: #A6535D; }
QPushButton[danger="true"]:pressed { background: #38282D; border-color: #8E4852; }
QPushButton[quiet="true"] { background: transparent; border-color: transparent; color: #ACB0BA; }
QPushButton[quiet="true"]:hover { background: #2A2E36; border-color: #333741; color: #E5E8ED; }
QPushButton#SshConsoleOpenLog, QPushButton#SshConsoleHide {
    min-height: 28px; padding: 0px 10px; background: #292D35; color: #BEC2CC;
    border: 1px solid #3E424C; border-radius: 10px;
}
QLineEdit, QSpinBox, QComboBox {
    background: #16181E; color: #E1E3E8; border: 1px solid #3C4049;
    border-radius: 8px; min-height: 24px; padding: 7px 10px;
    selection-background-color: #4F75DF; selection-color: #FFFFFF;
}
QLineEdit:hover, QSpinBox:hover, QComboBox:hover { border-color: #555A65; }
QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border: 1px solid #84A1F7; background: #1B1E24; }
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled { background: #22262D; color: #797E88; border-color: #30333A; }
QLineEdit::placeholder { color: #7A7F8A; }
QComboBox::drop-down { border: 0px; width: 28px; }
QComboBox QAbstractItemView { background: #24272E; color: #DEE0E6; border: 1px solid #3F434C; selection-background-color: #4F75DF; }
QSpinBox::up-button, QSpinBox::down-button { background: #292D35; border: 0px; width: 20px; }
QToolButton#PasswordToggle {
    color: #B7BBC5; background: #2A2E37; border: 1px solid #3F434C;
    border-radius: 10px; min-width: 50px; padding: 0px 9px;
}
QToolButton#PasswordToggle:hover { color: #EBEDF2; background: #363B45; border-color: #626979; }
QToolButton#PasswordToggle:pressed { background: #282C35; }
QCheckBox { color: #CBCED6; spacing: 8px; }
QCheckBox::indicator { width: 17px; height: 17px; border-radius: 4px; background: #181A20; border: 1px solid #4E525B; }
QCheckBox::indicator:hover { border-color: #717D97; }
QCheckBox::indicator:checked { background: #4F75DF; border-color: #84A1F7; }
QRadioButton { color: #CBCED6; spacing: 8px; }
QRadioButton::indicator { width: 17px; height: 17px; border-radius: 9px; background: #181A20; border: 1px solid #4E525B; }
QRadioButton::indicator:checked { background: #84A1F7; border: 4px solid #4F75DF; }
QScrollArea { background: transparent; border: 0px; }
QScrollBar:vertical, QScrollBar:horizontal { background: transparent; border: 0px; margin: 2px; width: 10px; height: 10px; }
QScrollBar::handle:vertical, QScrollBar::handle:horizontal { background: #454A54; border-radius: 5px; min-width: 24px; min-height: 24px; }
QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover { background: #616671; }
QScrollBar::handle:vertical:pressed, QScrollBar::handle:horizontal:pressed { background: #747985; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0px; height: 0px; }
QSplitter::handle { background: transparent; }
QSplitter::handle:horizontal { width: 12px; }
QSplitter::handle:vertical { height: 12px; }
QFrame#SshConsole { background: #181A1F; border: 1px solid #393D46; border-radius: 13px; }
QLabel#SshConsoleTitle { color: #E1E4EA; font-weight: 700; }
QLabel#SshConsoleStatus { color: #9EA3AE; font-size: 9.5pt; }
QPlainTextEdit#SshConsoleOutput {
    background: #131519; color: #C9CDD6; border: 1px solid #353942;
    border-radius: 8px; padding: 9px; font-family: "Microsoft YaHei"; font-weight: 700;
}
QLineEdit#SshConsoleInput { background: #14161C; color: #E1E3E8; border: 1px solid #3F434C; }
QFrame#DialogIcon { border: 0px; border-radius: 21px; }
QFrame#DialogIcon[tone="info"] { background: #2A2E37; }
QFrame#DialogIcon[tone="warning"] { background: #40382B; }
QFrame#DialogIcon[tone="danger"] { background: #422B30; }
QLabel#DialogIconText { font-size: 17px; font-weight: 700; }
QLabel#DialogIconText[tone="info"] { color: #8293B8; }
QLabel#DialogIconText[tone="warning"] { color: #E2BB75; }
QLabel#DialogIconText[tone="danger"] { color: #F08E94; }
QToolTip { color: #E5E7EC; background: #292D35; border: 1px solid #4D515A; padding: 5px 8px; }
QMenu { background: #24272E; color: #DEE0E6; border: 1px solid #3F434C; padding: 5px; }
QMenu::item { padding: 7px 24px 7px 10px; border-radius: 5px; }
QMenu::item:selected { background: #33466D; color: #F1F3FA; }
QProgressBar { background: #24272E; color: #DEE0E6; border: 1px solid #3A3E46; border-radius: 5px; text-align: center; }
QProgressBar::chunk { background: #6389ED; border-radius: 4px; }
"""


def config_path() -> Path:
    base = Path(os.environ.get("APPDATA") or Path.home())
    return base / "VncTunnelManager" / "config.json"


def ssh_log_path() -> Path:
    return application_logs_directory() / "ssh-session.log"


def load_config() -> dict:
    path = config_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("配置文件格式无效")
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        data = json.loads(json.dumps(DEFAULT_CONFIG))

    data.setdefault("servers", [])
    for server in data["servers"]:
        server.setdefault("id", str(uuid.uuid4()))
        server.setdefault("ssh_host", "")
        server.setdefault("ssh_user", "")
        server.setdefault("identity_file", "")
        server.setdefault("ssh_port", 22)
        server.setdefault("target_host", "127.0.0.1")
        server.setdefault("target_port", 5900)
        server.setdefault("local_port", 0)
    return data


class AppMessageDialog(QDialog):
    def __init__(self, parent, title: str, message: str, *, tone="info", question=False):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(410)
        self.question = question
        body = create_dialog_body(self)

        layout = QVBoxLayout(body)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(18)
        row = QHBoxLayout()
        row.setSpacing(14)
        icon = QFrame()
        icon.setObjectName("DialogIcon")
        icon.setProperty("tone", tone)
        icon.setFixedSize(42, 42)
        icon_layout = QVBoxLayout(icon)
        icon_layout.setContentsMargins(0, 0, 0, 0)
        icon_text = QLabel({"info": "i", "warning": "!", "danger": "×"}.get(tone, "i"))
        icon_text.setObjectName("DialogIconText")
        icon_text.setProperty("tone", tone)
        icon_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_layout.addWidget(icon_text)
        row.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)

        text = QLabel(message)
        text.setTextFormat(Qt.TextFormat.PlainText)
        text.setWordWrap(True)
        text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        text.setMinimumWidth(285)
        text.setMaximumWidth(470)
        row.addWidget(text, 1, Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(row)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        if question:
            cancel = QPushButton("取消")
            cancel.clicked.connect(self.reject)
            buttons.addWidget(cancel)
            confirm = QPushButton("删除")
            confirm.setProperty("danger", True)
            confirm.clicked.connect(self.accept)
            buttons.addWidget(confirm)
        else:
            ok = QPushButton("知道了")
            ok.setProperty("primary", True)
            ok.clicked.connect(self.accept)
            buttons.addWidget(ok)
        layout.addLayout(buttons)
        self.adjustSize()


def show_notice(parent, title: str, message: str, tone="info"):
    AppMessageDialog(parent, title, message, tone=tone).exec()


def ask_confirmation(parent, title: str, message: str) -> bool:
    dialog = AppMessageDialog(parent, title, message, tone="warning", question=True)
    return dialog.exec() == QDialog.DialogCode.Accepted


class VncPasswordDialog(QDialog):
    def __init__(self, parent, host: str, port: int):
        super().__init__(parent)
        self.setWindowTitle("VNC 身份验证")
        self.setModal(True)
        self.setMinimumWidth(440)
        self.password = ""
        body = create_dialog_body(self)

        layout = QVBoxLayout(body)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(13)
        heading = QLabel(f"连接到 {host}:{port}")
        heading.setObjectName("SectionTitle")
        layout.addWidget(heading)
        explanation = QLabel("输入 VNC 密码继续连接。如果服务器没有设置密码，请留空。")
        explanation.setObjectName("Muted")
        explanation.setWordWrap(True)
        layout.addWidget(explanation)

        password_row = QHBoxLayout()
        password_row.setSpacing(8)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("VNC 密码")
        self.password_edit.returnPressed.connect(self.accept_password)
        password_row.addWidget(self.password_edit, 1)
        self.reveal_button = QToolButton()
        self.reveal_button.setText("显示")
        self.reveal_button.setObjectName("PasswordToggle")
        self.reveal_button.setCheckable(True)
        self.reveal_button.toggled.connect(self._toggle_password)
        password_row.addWidget(self.reveal_button)
        layout.addLayout(password_row)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton("取消")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        connect = QPushButton("连接")
        connect.setProperty("primary", True)
        connect.clicked.connect(self.accept_password)
        buttons.addWidget(connect)
        layout.addLayout(buttons)
        self.adjustSize()
        self.password_edit.setFocus()

    def _toggle_password(self, visible: bool):
        self.password_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        )
        self.reveal_button.setText("隐藏" if visible else "显示")

    def accept_password(self):
        self.password = self.password_edit.text()
        self.accept()


class AppFileDialog(QDialog):
    def __init__(self, parent, title, name_filter, *, save=False, default_name=""):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumSize(860, 520)
        self.resize(980, 620)
        body = create_dialog_body(self)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(0)

        self.file_dialog = QFileDialog(body)
        self.file_dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        self.file_dialog.setMinimumSize(840, 500)
        self.file_dialog.setWindowFlags(Qt.WindowType.Widget)
        self.file_dialog.setWindowModality(Qt.WindowModality.NonModal)
        self.file_dialog.setFileMode(
            QFileDialog.FileMode.AnyFile if save else QFileDialog.FileMode.ExistingFile
        )
        self.file_dialog.setAcceptMode(
            QFileDialog.AcceptMode.AcceptSave if save else QFileDialog.AcceptMode.AcceptOpen
        )
        self.file_dialog.setNameFilter(name_filter)
        if save:
            self.file_dialog.setDefaultSuffix("json")
        if default_name:
            self.file_dialog.selectFile(default_name)
        self._configure_file_view()
        QTimer.singleShot(150, self._configure_file_view)
        self.file_dialog.accepted.connect(self.accept)
        self.file_dialog.rejected.connect(self.reject)
        layout.addWidget(self.file_dialog, 1)

    def _configure_file_view(self):
        view = self.file_dialog.findChild(QTreeView)
        if view is None:
            return
        header = view.header()
        header.setMinimumSectionSize(72)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for section, width in enumerate((360, 100, 145, 230)):
            if section < header.count():
                header.resizeSection(section, width)
        header.setStretchLastSection(True)
        model = view.model()
        for section, label in enumerate(("名称", "大小", "类型", "修改时间")):
            if section < header.count():
                model.setHeaderData(section, Qt.Orientation.Horizontal, label)

    def selected_file(self):
        files = self.file_dialog.selectedFiles()
        return files[0] if files else ""


class ServerDialog(QDialog):
    def __init__(self, parent, server: dict | None = None):
        super().__init__(parent)
        self.setWindowTitle("编辑服务器" if server else "添加服务器")
        self.setModal(True)
        self.setMinimumSize(540, 480)
        self.resize(650, 690)
        self.result = None
        initial = server or {
            "name": "", "ssh_host": "", "ssh_user": "", "ssh_port": 22,
            "target_host": "127.0.0.1", "target_port": 5900,
            "local_port": 0, "identity_file": "",
        }
        self.original_id = initial.get("id", "")
        body = create_dialog_body(self)
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        intro = QWidget(body)
        intro_layout = QVBoxLayout(intro)
        intro_layout.setContentsMargins(24, 20, 24, 12)
        intro_layout.setSpacing(5)
        intro_title = QLabel("连接参数")
        intro_title.setObjectName("DetailTitle")
        intro_layout.addWidget(intro_title)
        subtitle = QLabel("配置远程 VNC 地址；需要 SSH 隧道时再补充 SSH 信息。")
        subtitle.setObjectName("Muted")
        subtitle.setWordWrap(True)
        intro_layout.addWidget(subtitle)
        body_layout.addWidget(intro)

        form_scroll = QScrollArea(body)
        form_scroll.setWidgetResizable(True)
        form_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        form_content = QWidget()
        form_content.setObjectName("DialogFormContent")
        form_layout = QVBoxLayout(form_content)
        form_layout.setContentsMargins(24, 8, 24, 18)
        form_layout.setSpacing(12)

        self.name_edit = QLineEdit(str(initial.get("name", "")))
        name_section, name_form = self._section(form_layout, "基本信息")
        name_form.addRow("显示名称", self.name_edit)

        self.target_host_edit = QLineEdit(str(initial.get("target_host", "127.0.0.1")))
        self.target_port_spin = self._port_spin(initial.get("target_port", 5900), 1)
        self.local_port_spin = self._port_spin(initial.get("local_port", 0), 0)
        vnc_section, vnc_form = self._section(form_layout, "VNC 桌面")
        vnc_form.addRow("远端地址", self.target_host_edit)
        vnc_form.addRow("远端端口", self.target_port_spin)
        vnc_form.addRow("本地监听端口", self.local_port_spin)

        self.ssh_host_edit = QLineEdit(str(initial.get("ssh_host", "")))
        self.ssh_user_edit = QLineEdit(str(initial.get("ssh_user", "")))
        self.ssh_port_spin = self._port_spin(initial.get("ssh_port", 22), 1)
        self.identity_edit = QLineEdit(str(initial.get("identity_file", "")))
        ssh_section, ssh_form = self._section(form_layout, "SSH 隧道（可选）")
        ssh_form.addRow("SSH 服务器", self.ssh_host_edit)
        ssh_form.addRow("SSH 用户名", self.ssh_user_edit)
        ssh_form.addRow("SSH 端口", self.ssh_port_spin)
        key_row = QWidget()
        key_layout = QHBoxLayout(key_row)
        key_layout.setContentsMargins(0, 0, 0, 0)
        key_layout.setSpacing(8)
        key_layout.addWidget(self.identity_edit, 1)
        browse = QPushButton("选择文件")
        browse.setMinimumWidth(88)
        browse.clicked.connect(self.browse_key)
        key_layout.addWidget(browse)
        ssh_form.addRow("私钥文件", key_row)

        note = QLabel("SSH 服务器和用户名同时留空时使用 VNC 直连。本地端口填 0 可自动分配。")
        note.setObjectName("Muted")
        note.setWordWrap(True)
        form_layout.addWidget(note)
        form_layout.addStretch(1)
        form_scroll.setWidget(form_content)
        body_layout.addWidget(form_scroll, 1)

        footer = QWidget(body)
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(24, 12, 24, 18)
        footer_layout.addStretch(1)
        cancel = QPushButton("取消")
        cancel.clicked.connect(self.reject)
        footer_layout.addWidget(cancel)
        save = QPushButton("保存服务器")
        save.setProperty("primary", True)
        save.clicked.connect(self.save)
        footer_layout.addWidget(save)
        body_layout.addWidget(footer)
        self.name_edit.setFocus()

    @staticmethod
    def _section(parent_layout, title):
        section = QFrame()
        section.setObjectName("FormSection")
        layout = QVBoxLayout(section)
        layout.setContentsMargins(14, 12, 14, 14)
        layout.setSpacing(10)
        heading = QLabel(title)
        heading.setObjectName("SectionTitle")
        layout.addWidget(heading)
        form = QFormLayout()
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(9)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(form)
        parent_layout.addWidget(section)
        return section, form

    @staticmethod
    def _port_spin(value, minimum):
        spin = QSpinBox()
        spin.setRange(minimum, 65535)
        spin.setValue(int(value))
        return spin

    def browse_key(self):
        picker = AppFileDialog(
            self,
            "选择 SSH 私钥",
            "SSH 私钥和所有文件 (*);;所有文件 (*.*)",
        )
        if picker.exec() == QDialog.DialogCode.Accepted and picker.selected_file():
            self.identity_edit.setText(picker.selected_file())

    def save(self):
        values = {
            "name": self.name_edit.text().strip(),
            "ssh_host": self.ssh_host_edit.text().strip(),
            "ssh_user": self.ssh_user_edit.text().strip(),
            "ssh_port": self.ssh_port_spin.value(),
            "target_host": self.target_host_edit.text().strip(),
            "target_port": self.target_port_spin.value(),
            "local_port": self.local_port_spin.value(),
            "identity_file": self.identity_edit.text().strip(),
        }
        if not values["name"] or not values["target_host"]:
            show_notice(self, "信息不完整", "显示名称和 VNC 远端地址不能为空。", tone="warning")
            return
        if bool(values["ssh_host"]) != bool(values["ssh_user"]):
            show_notice(
                self,
                "SSH 配置不完整",
                "使用 SSH 隧道时，SSH 服务器和用户名需要同时填写；直连时两项都留空。",
                tone="warning",
            )
            return
        values["id"] = self.original_id
        self.result = values
        self.accept()


class StatusText:
    """Small adapter for status updates from the connection-management code."""

    def __init__(self, label: QLabel):
        self.label = label

    def set(self, text: str):
        self.label.setText(text)


class VncTunnelManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        screen = QApplication.primaryScreen()
        if screen is not None:
            available = screen.availableGeometry()
            initial_width = min(1600, max(820, round(available.width() * 0.92)))
            initial_height = min(1000, max(580, round(available.height() * 0.90)))
            self.resize(initial_width, initial_height)
            self.move(available.center() - self.rect().center())
        else:
            self.resize(1440, 900)
        self.setMinimumSize(820, 580)
        self.config = load_config()
        self.tunnels: dict[str, dict] = {}
        self.viewer_windows: dict[str, VncViewerWindow] = {}
        self.ui_queue: queue.Queue = queue.Queue()
        self._queued_ssh_prompts = deque()
        self._active_ssh_prompt = None
        self._ssh_auth_rejected: set[str] = set()
        self._ssh_log_write_error_reported = False
        self._compact_layout = None
        self.server_by_id = {server["id"]: server for server in self.config["servers"]}
        self._closing = False

        self._build_ui()
        apply_custom_chrome(self)
        self.refresh_servers()
        self._events_timer = QTimer(self)
        self._events_timer.setInterval(30)
        self._events_timer.timeout.connect(self.process_ui_events)
        self._events_timer.start()
        self._tunnel_timer = QTimer(self)
        self._tunnel_timer.setInterval(1000)
        self._tunnel_timer.timeout.connect(self.monitor_tunnels)
        self._tunnel_timer.start()

    @staticmethod
    def _card():
        frame = QFrame()
        frame.setObjectName("Card")
        return frame

    @staticmethod
    def _button(text, slot, primary=False, danger=False, quiet=False):
        button = QPushButton(text)
        if primary:
            button.setProperty("primary", True)
        if danger:
            button.setProperty("danger", True)
        if quiet:
            button.setProperty("quiet", True)
        button.clicked.connect(slot)
        return button

    def _build_ui(self):
        central = QWidget(self)
        shell = QVBoxLayout(central)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        self.main_scroll = QScrollArea(central)
        self.main_scroll.setWidgetResizable(True)
        self.main_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.main_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        page = QWidget()
        page.setObjectName("MainPage")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(24, 16, 24, 16)
        outer.setSpacing(14)
        self.main_scroll.setWidget(page)
        shell.addWidget(self.main_scroll)

        header = QHBoxLayout()
        header.setSpacing(14)
        badge = QLabel()
        badge.setObjectName("BrandBadge")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setFixedSize(48, 48)
        badge.setPixmap(qingque_icon().pixmap(48, 48))
        header.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)
        heading_box = QVBoxLayout()
        heading_box.setSpacing(4)
        title = QLabel(APP_NAME)
        title.setObjectName("PageTitle")
        heading_box.addWidget(title)
        subtitle = QLabel("管理远程桌面连接 · 支持 VNC 直连与 SSH 隧道")
        subtitle.setObjectName("Subtitle")
        heading_box.addWidget(subtitle)
        header.addLayout(heading_box, 1)
        pill = QLabel("●  连接管理")
        pill.setObjectName("StatusPill")
        pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.addWidget(pill, 0, Qt.AlignmentFlag.AlignVCenter)
        outer.addLayout(header)

        self.content_splitter = QSplitter(Qt.Orientation.Horizontal, page)
        self.content_splitter.setObjectName("ContentSplitter")
        self.content_splitter.setChildrenCollapsible(False)
        self.content_splitter.setHandleWidth(12)
        outer.addWidget(self.content_splitter, 1)

        list_card = self._card()
        list_card.setMinimumHeight(310)
        list_layout = QVBoxLayout(list_card)
        list_layout.setContentsMargins(18, 17, 18, 16)
        list_layout.setSpacing(12)
        list_header = QHBoxLayout()
        list_title = QLabel("服务器")
        list_title.setObjectName("SectionTitle")
        list_header.addWidget(list_title)
        list_header.addSpacing(8)
        self.server_count_label = QLabel("0 个连接")
        self.server_count_label.setObjectName("CountPill")
        list_header.addWidget(self.server_count_label)
        list_header.addStretch(1)
        add_button = self._button("＋ 添加服务器", self.add_server, primary=True)
        add_button.setMinimumWidth(132)
        list_header.addWidget(add_button)
        list_layout.addLayout(list_header)

        self.table = QTableWidget(0, 4, list_card)
        self.table.setHorizontalHeaderLabels(["名称", "连接方式 / SSH", "VNC 地址", "状态"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(48)
        self.table.horizontalHeader().setMinimumSectionSize(76)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.itemSelectionChanged.connect(self.update_details)
        self.table.cellDoubleClicked.connect(lambda _row, _column: self.connect_selected())
        list_layout.addWidget(self.table, 1)

        actions = QHBoxLayout()
        actions.setSpacing(7)
        self.edit_button = self._button("编辑", self.edit_server)
        self.edit_button.setEnabled(False)
        self.delete_button = self._button("删除", self.delete_server, danger=True)
        self.delete_button.setEnabled(False)
        self.import_button = self._button("导入配置", self.import_servers, quiet=True)
        self.import_button.setToolTip("从 JSON 文件导入服务器连接配置")
        self.export_button = self._button("导出配置", self.export_servers, quiet=True)
        self.export_button.setToolTip("将服务器连接参数导出为 JSON；不包含密码")
        actions.addWidget(self.edit_button)
        actions.addWidget(self.delete_button)
        actions.addWidget(self.import_button)
        actions.addWidget(self.export_button)
        actions.addWidget(self._button("连接说明", self.show_help, quiet=True))
        actions.addStretch(1)
        list_layout.addLayout(actions)
        self.content_splitter.addWidget(list_card)

        detail_card = self._card()
        detail_card.setMinimumHeight(310)
        detail_layout = QVBoxLayout(detail_card)
        detail_layout.setContentsMargins(18, 17, 18, 16)
        detail_layout.setSpacing(13)
        detail_header = QHBoxLayout()
        detail_title = QLabel("连接详情")
        detail_title.setObjectName("SectionTitle")
        detail_header.addWidget(detail_title)
        detail_header.addStretch(1)
        self.detail_state = QLabel("未连接")
        self.detail_state.setObjectName("CountPill")
        detail_header.addWidget(self.detail_state)
        detail_layout.addLayout(detail_header)

        self.detail_name = QLabel("请选择一台服务器")
        self.detail_name.setObjectName("DetailTitle")
        self.detail_name.setTextFormat(Qt.TextFormat.PlainText)
        self.detail_name.setWordWrap(True)
        detail_layout.addWidget(self.detail_name)

        info = QFrame()
        info.setObjectName("DetailInfo")
        info.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        info_grid = QVBoxLayout(info)
        info_grid.setContentsMargins(13, 10, 13, 10)
        info_grid.setSpacing(8)
        self.detail_type_value = self._detail_field(info_grid, "连接方式")
        self.detail_ssh_value = self._detail_field(info_grid, "SSH 服务器")
        self.detail_vnc_value = self._detail_field(info_grid, "远端 VNC")
        self.detail_local_value = self._detail_field(info_grid, "本地监听")
        detail_layout.addWidget(info)

        self.connect_button = self._button("连接并显示桌面", self.connect_selected, primary=True)
        self.connect_button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.connect_button.setMinimumHeight(42)
        detail_layout.addWidget(self.connect_button)
        self.disconnect_button = self._button("断开连接", self.disconnect_selected, quiet=True)
        self.disconnect_button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        detail_layout.addWidget(self.disconnect_button)
        detail_layout.addStretch(1)
        self.content_splitter.addWidget(detail_card)
        self.content_splitter.setStretchFactor(0, 7)
        self.content_splitter.setStretchFactor(1, 4)
        self.content_splitter.setSizes([730, 420])

        self.ssh_console = QFrame(page)
        self.ssh_console.setObjectName("SshConsole")
        console_layout = QVBoxLayout(self.ssh_console)
        console_layout.setContentsMargins(15, 13, 15, 14)
        console_layout.setSpacing(9)
        console_header = QHBoxLayout()
        self.ssh_console_title = QLabel("SSH 交互终端")
        self.ssh_console_title.setObjectName("SshConsoleTitle")
        console_header.addWidget(self.ssh_console_title)
        console_header.addStretch(1)
        self.ssh_console_status = QLabel("等待 SSH 连接")
        self.ssh_console_status.setObjectName("SshConsoleStatus")
        console_header.addWidget(self.ssh_console_status)
        self.ssh_console_open_log_button = QPushButton("打开日志")
        self.ssh_console_open_log_button.setObjectName("SshConsoleOpenLog")
        self.ssh_console_open_log_button.setToolTip(str(ssh_log_path()))
        self.ssh_console_open_log_button.clicked.connect(self._open_ssh_log)
        console_header.addWidget(self.ssh_console_open_log_button)
        self.ssh_console_hide_button = QPushButton("收起")
        self.ssh_console_hide_button.setObjectName("SshConsoleHide")
        self.ssh_console_hide_button.clicked.connect(self._hide_ssh_console)
        console_header.addWidget(self.ssh_console_hide_button)
        console_layout.addLayout(console_header)

        self.ssh_console_output = QPlainTextEdit(self.ssh_console)
        self.ssh_console_output.setObjectName("SshConsoleOutput")
        self.ssh_console_output.setReadOnly(True)
        self.ssh_console_output.setMaximumBlockCount(500)
        self.ssh_console_output.setMinimumHeight(86)
        self.ssh_console_output.setMaximumHeight(150)
        console_layout.addWidget(self.ssh_console_output)

        self.ssh_console_prompt = QLabel("")
        self.ssh_console_prompt.setObjectName("SshConsoleStatus")
        self.ssh_console_prompt.setWordWrap(True)
        console_layout.addWidget(self.ssh_console_prompt)
        self.ssh_console_input = QLineEdit(self.ssh_console)
        self.ssh_console_input.setObjectName("SshConsoleInput")
        self.ssh_console_input.setPlaceholderText("SSH 密码或主机确认提示会显示在这里")
        self.ssh_console_input.setEnabled(False)
        self.ssh_console_input.returnPressed.connect(self._submit_ssh_prompt)
        console_layout.addWidget(self.ssh_console_input)
        outer.addWidget(self.ssh_console)
        self.ssh_console.hide()

        footer = QHBoxLayout()
        dot = QLabel("●")
        dot.setObjectName("OnlineDot")
        footer.addWidget(dot)
        self.status_label = QLabel("配置已就绪 · 自动保存在本机")
        self.status_label.setObjectName("FooterStatus")
        footer.addWidget(self.status_label, 1)
        footer.addWidget(self._button("关于", self.show_about, quiet=True))
        footer.setContentsMargins(2, 2, 2, 0)
        outer.addLayout(footer)
        self.status_var = StatusText(self.status_label)
        self.workspace = QStackedWidget(self)
        self.manager_page = central
        self.workspace.addWidget(central)
        self.setCentralWidget(self.workspace)

    def show_manager_page(self):
        self.workspace.setCurrentWidget(self.manager_page)

    @staticmethod
    def _detail_field(parent_layout, caption):
        item = QWidget()
        item.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        layout = QVBoxLayout(item)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(3)
        caption_label = QLabel(caption)
        caption_label.setObjectName("FieldCaption")
        value_label = QLabel("—")
        value_label.setObjectName("FieldValue")
        value_label.setTextFormat(Qt.TextFormat.PlainText)
        value_label.setWordWrap(True)
        value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(caption_label)
        layout.addWidget(value_label)
        parent_layout.addWidget(item, 0, Qt.AlignmentFlag.AlignTop)
        return value_label

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if not hasattr(self, "content_splitter"):
            return
        compact = self.width() < 1080
        if compact == self._compact_layout:
            return
        self._compact_layout = compact
        orientation = Qt.Orientation.Vertical if compact else Qt.Orientation.Horizontal
        self.content_splitter.setOrientation(orientation)
        if compact:
            self.content_splitter.setSizes([390, 330])
        else:
            self.content_splitter.setSizes([730, 420])

    def _append_ssh_console(self, text: str, server_id: str | None = None):
        line = str(text).rstrip("\r\n")
        if not line:
            return
        if server_id and (
            "permission denied" in line.casefold() or "认证失败" in line
        ):
            self._ssh_auth_rejected.add(server_id)
            self.ssh_console_status.setText("SSH 拒绝了本次登录凭据，请检查用户名和 SSH 密码")
        if server_id:
            server = self.server_by_id.get(server_id, {})
            prefix = server.get("name") or server.get("ssh_host") or server_id
            line = f"[{prefix}] {line}"
        self.ssh_console_output.appendPlainText(line)
        self._save_ssh_log_line(line)

    def _save_ssh_log_line(self, line: str):
        path = ssh_log_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
            with path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(f"[{timestamp}] {line}\n")
        except OSError as exc:
            if not self._ssh_log_write_error_reported:
                self._ssh_log_write_error_reported = True
                self.ssh_console_status.setText(f"日志写入失败：{exc}")

    def _open_ssh_log(self):
        path = ssh_log_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(exist_ok=True)
        except OSError as exc:
            show_notice(self, "无法打开日志", f"{exc}\n\n日志路径：{path}", tone="warning")
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(path))):
            show_notice(self, "SSH 日志位置", f"无法自动打开文件，请到这里查看：\n{path}")

    def _hide_ssh_console(self):
        if self._active_ssh_prompt is None:
            self.ssh_console.hide()

    def _queue_ssh_prompt(self, server_id: str, prompt: str, response: queue.Queue):
        self._queued_ssh_prompts.append(
            {"server_id": server_id, "prompt": prompt, "response": response}
        )
        self._activate_ssh_prompt()

    def _activate_ssh_prompt(self):
        if self._active_ssh_prompt is not None:
            return
        while self._queued_ssh_prompts:
            item = self._queued_ssh_prompts.popleft()
            tunnel = self.tunnels.get(item["server_id"])
            worker = tunnel.get("worker") if tunnel else None
            if not tunnel or not worker or not worker.is_alive():
                try:
                    item["response"].put_nowait((False, ""))
                except queue.Full:
                    pass
                continue
            self._active_ssh_prompt = item
            prompt = item["prompt"].strip()
            lowered = prompt.lower()
            secret = any(word in lowered for word in ("password", "passphrase", "密码", "口令"))
            self.ssh_console_prompt.setText(prompt)
            self.ssh_console_input.clear()
            self.ssh_console_input.setEchoMode(
                QLineEdit.EchoMode.Password if secret else QLineEdit.EchoMode.Normal
            )
            self.ssh_console_input.setPlaceholderText(
                "输入 SSH 密码（不是 VNC 密码），按 Enter 提交" if secret else "输入 yes / no 或提示所需内容，然后按 Enter"
            )
            self.ssh_console_input.setEnabled(True)
            if item["server_id"] in self._ssh_auth_rejected:
                self.ssh_console_status.setText("上次 SSH 登录被拒绝，请重新核对用户名和密码")
                self._ssh_auth_rejected.discard(item["server_id"])
            else:
                self.ssh_console_status.setText("等待输入")
            self.ssh_console.show()
            self.ssh_console_input.setFocus()
            self._append_ssh_console(prompt, item["server_id"])
            return
        self.ssh_console_prompt.clear()
        self.ssh_console_input.clear()
        self.ssh_console_input.setEchoMode(QLineEdit.EchoMode.Normal)
        self.ssh_console_input.setPlaceholderText("SSH 密码或主机确认提示会显示在这里")
        self.ssh_console_input.setEnabled(False)

    def _submit_ssh_prompt(self):
        item = self._active_ssh_prompt
        if item is None:
            return
        text = self.ssh_console_input.text()
        self._append_ssh_console("交互响应已提交（内容已隐藏）", item["server_id"])
        try:
            item["response"].put_nowait((True, text))
        except queue.Full:
            pass
        self._active_ssh_prompt = None
        self._activate_ssh_prompt()

    def _cancel_ssh_prompts(self, server_id: str | None = None):
        if self._active_ssh_prompt is not None:
            item = self._active_ssh_prompt
            if server_id is None or item["server_id"] == server_id:
                try:
                    item["response"].put_nowait((False, ""))
                except queue.Full:
                    pass
                self._active_ssh_prompt = None
        remaining = deque()
        while self._queued_ssh_prompts:
            item = self._queued_ssh_prompts.popleft()
            if server_id is None or item["server_id"] == server_id:
                try:
                    item["response"].put_nowait((False, ""))
                except queue.Full:
                    pass
            else:
                remaining.append(item)
        self._queued_ssh_prompts = remaining
        self._activate_ssh_prompt()

    def save_config(self):
        path = config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.config, ensure_ascii=False, indent=2), encoding="utf-8")
        self.status_var.set("服务器配置已保存")

    def refresh_servers(self):
        selected = self.selected_id()
        self.server_by_id = {server["id"]: server for server in self.config["servers"]}
        self.export_button.setEnabled(bool(self.config["servers"]))
        self.server_count_label.setText(f"{len(self.config['servers'])} 个连接")
        blocker = QSignalBlocker(self.table)
        self.table.setRowCount(0)
        selected_row = -1
        for row, server in enumerate(self.config["servers"]):
            self.table.insertRow(row)
            values = (
                server["name"],
                (f'{server["ssh_user"]}@{server["ssh_host"]}:{server["ssh_port"]}'
                 if server.get("ssh_host") else "直接连接"),
                f'{server["target_host"]}:{server["target_port"]}',
                self.status_for(server["id"]),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, server["id"])
                self.table.setItem(row, column, item)
            if server["id"] == selected:
                selected_row = row
        if selected_row < 0 and self.config["servers"]:
            selected_row = 0
        if selected_row >= 0:
            self.table.setCurrentCell(selected_row, 0)
            self.table.selectRow(selected_row)
        del blocker
        self.update_details()

    def status_for(self, server_id: str) -> str:
        viewer = self.viewer_windows.get(server_id)
        if viewer and not viewer.closed:
            if viewer.connected:
                return "VNC 已连接"
            return "VNC 连接失败" if viewer.failed else "VNC 连接中…"
        tunnel = self.tunnels.get(server_id)
        if not tunnel:
            return "未连接"
        if tunnel["status"] == "connecting":
            return "正在连接…"
        if tunnel["status"] == "active":
            return f'已连接 · {tunnel["local_port"]}'
        return "连接失败"

    def selected_id(self):
        row = self.table.currentRow() if hasattr(self, "table") else -1
        item = self.table.item(row, 0) if row >= 0 else None
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def update_details(self):
        server_id = self.selected_id()
        server = self.server_by_id.get(server_id)
        if not server:
            self.detail_name.setText("请选择一台服务器")
            self.detail_type_value.setText("—")
            self.detail_ssh_value.setText("—")
            self.detail_vnc_value.setText("—")
            self.detail_local_value.setText("—")
            self.detail_state.setText("未连接")
            self.edit_button.setEnabled(False)
            self.delete_button.setEnabled(False)
            self.connect_button.setEnabled(False)
            self.connect_button.setText("连接并显示桌面")
            self.disconnect_button.setEnabled(False)
            return
        tunnel = self.tunnels.get(server_id)
        state = self.status_for(server_id)
        if server.get("ssh_host"):
            self.detail_type_value.setText("SSH 隧道")
            self.detail_ssh_value.setText(
                f'{server["ssh_user"]}@{server["ssh_host"]}:{server["ssh_port"]}'
            )
            local = (
                f'127.0.0.1:{tunnel["local_port"]}'
                if tunnel and tunnel.get("local_port")
                else (str(server["local_port"]) if server["local_port"] else "自动分配")
            )
            self.detail_local_value.setText(local)
        else:
            self.detail_type_value.setText("VNC 直连")
            self.detail_ssh_value.setText("未启用")
            self.detail_local_value.setText("—")
        self.detail_vnc_value.setText(f'{server["target_host"]}:{server["target_port"]}')
        self.detail_state.setText(state)
        self.detail_name.setText(server["name"])
        self.edit_button.setEnabled(True)
        self.delete_button.setEnabled(True)
        viewer = self.viewer_windows.get(server_id)
        if viewer and not viewer.closed:
            label = "切换到 VNC 桌面" if viewer.connected else ("重新连接 VNC" if viewer.failed else "VNC 连接中…")
            self.connect_button.setEnabled(True)
            self.connect_button.setText(label)
            self.disconnect_button.setEnabled(True)
        elif tunnel and tunnel["status"] == "active":
            self.connect_button.setEnabled(True)
            self.connect_button.setText("连接并显示桌面")
            self.disconnect_button.setEnabled(True)
        elif tunnel and tunnel["status"] == "connecting":
            self.connect_button.setEnabled(False)
            self.connect_button.setText("正在建立隧道…")
            self.disconnect_button.setEnabled(True)
        else:
            self.connect_button.setEnabled(True)
            self.connect_button.setText("连接并显示桌面")
            self.disconnect_button.setEnabled(bool(tunnel))

    def add_server(self):
        dialog = ServerDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.result:
            if not dialog.result["id"]:
                dialog.result["id"] = str(uuid.uuid4())
            self.config["servers"].append(dialog.result)
            self.save_config()
            self.refresh_servers()
            for row, server in enumerate(self.config["servers"]):
                if server["id"] == dialog.result["id"]:
                    self.table.setCurrentCell(row, 0)
                    self.table.selectRow(row)
                    break

    @staticmethod
    def _normalize_imported_server(entry: dict, index: int) -> dict:
        def required_text(field: str, label: str) -> str:
            value = entry.get(field, "")
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"第 {index} 条服务器配置缺少有效的{label}。")
            return value.strip()

        def port_value(field: str, label: str, default: int, minimum: int) -> int:
            value = entry.get(field, default)
            if isinstance(value, bool):
                raise ValueError(f"第 {index} 条服务器配置的{label}无效。")
            if isinstance(value, int):
                port = value
            elif isinstance(value, str) and value.strip().isdigit():
                port = int(value.strip())
            else:
                raise ValueError(f"第 {index} 条服务器配置的{label}无效。")
            if not minimum <= port <= 65535:
                raise ValueError(f"第 {index} 条服务器配置的{label}必须在 {minimum} 到 65535 之间。")
            return port

        name = required_text("name", "服务器名称")
        target_host = required_text("target_host", "VNC 地址")
        ssh_host = entry.get("ssh_host", "")
        ssh_user = entry.get("ssh_user", "")
        identity_file = entry.get("identity_file", "")
        if not isinstance(ssh_host, str) or not isinstance(ssh_user, str):
            raise ValueError(f"第 {index} 条服务器配置中的 SSH 地址或用户名无效。")
        ssh_host = ssh_host.strip()
        ssh_user = ssh_user.strip()
        if bool(ssh_host) != bool(ssh_user):
            raise ValueError(f"第 {index} 条服务器配置需要同时填写 SSH 地址和用户名，或同时留空。")
        if not isinstance(identity_file, str):
            raise ValueError(f"第 {index} 条服务器配置中的私钥路径无效。")

        server_id = entry.get("id")
        if server_id is None or server_id == "":
            server_id = str(uuid.uuid4())
        if not isinstance(server_id, str) or not server_id.strip() or len(server_id.strip()) > 128:
            raise ValueError(f"第 {index} 条服务器配置的 ID 无效。")

        # Use an explicit allowlist so credentials or unrelated JSON fields are never persisted.
        return {
            "id": server_id.strip(),
            "name": name,
            "ssh_host": ssh_host,
            "ssh_user": ssh_user,
            "ssh_port": port_value("ssh_port", "SSH 端口", 22, 1),
            "target_host": target_host,
            "target_port": port_value("target_port", "VNC 端口", 5900, 1),
            "local_port": port_value("local_port", "本地端口", 0, 0),
            "identity_file": identity_file.strip(),
        }

    def export_servers(self):
        if not self.config["servers"]:
            show_notice(self, "导出配置", "当前没有可导出的服务器配置。")
            return
        dialog = AppFileDialog(
            self,
            "导出服务器配置",
            "JSON 配置 (*.json)",
            save=True,
            default_name="QingQueVNC-servers.json",
        )
        if dialog.exec() != QDialog.DialogCode.Accepted or not dialog.selected_file():
            return
        path = Path(dialog.selected_file())
        if not path.suffix:
            path = path.with_suffix(".json")
        payload = {
            "format": SERVER_EXPORT_FORMAT,
            "version": 1,
            "servers": [
                {
                    key: server.get(key, "")
                    for key in (
                        "id", "name", "ssh_host", "ssh_user", "ssh_port",
                        "target_host", "target_port", "local_port", "identity_file",
                    )
                }
                for server in self.config["servers"]
            ],
        }
        try:
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            show_notice(self, "导出失败", f"无法写入配置文件：\n{exc}", tone="danger")
            return
        show_notice(self, "导出完成", f"已导出 {len(payload['servers'])} 台服务器配置。")

    def import_servers(self):
        dialog = AppFileDialog(
            self,
            "导入服务器配置",
            "JSON 配置 (*.json);;所有文件 (*)",
        )
        if dialog.exec() != QDialog.DialogCode.Accepted or not dialog.selected_file():
            return
        path = Path(dialog.selected_file())
        try:
            document = json.loads(path.read_text(encoding="utf-8-sig"))
            if isinstance(document, list):
                entries = document
            elif isinstance(document, dict):
                file_format = document.get("format")
                if file_format not in (None, SERVER_EXPORT_FORMAT):
                    raise ValueError("这不是 QingQueVNC 支持的服务器配置文件。")
                version = document.get("version", 1)
                if isinstance(version, bool) or not isinstance(version, int) or version != 1:
                    raise ValueError(f"不支持的配置文件版本：{version}。")
                entries = document.get("servers")
            else:
                raise ValueError("配置文件格式错误：最外层应为服务器列表或包含 servers 的对象。")

            if not isinstance(entries, list):
                raise ValueError("配置文件中没有有效的 servers 服务器列表。")
            if not entries:
                show_notice(self, "未导入配置", "文件中的服务器列表为空。")
                return

            imported = []
            for index, entry in enumerate(entries, start=1):
                if not isinstance(entry, dict):
                    raise ValueError(f"第 {index} 条服务器配置必须是对象。")
                imported.append(self._normalize_imported_server(entry, index))
            imported_ids = [server["id"] for server in imported]
            if len(imported_ids) != len(set(imported_ids)):
                raise ValueError("导入文件中存在重复的服务器 ID，请先修正文件。")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            show_notice(self, "导入失败", f"无法导入服务器配置：\n{exc}", tone="danger")
            return

        existing = list(self.config["servers"])
        existing_by_id = {server["id"]: server for server in existing}
        imported_by_id = {server["id"]: server for server in imported}
        added = sum(server_id not in existing_by_id for server_id in imported_by_id)
        updated = sum(
            server_id in existing_by_id and existing_by_id[server_id] != server
            for server_id, server in imported_by_id.items()
        )
        merged = [imported_by_id.get(server["id"], server) for server in existing]
        merged.extend(server for server in imported if server["id"] not in existing_by_id)
        changed_ids = {
            server_id
            for server_id, server in imported_by_id.items()
            if server_id in existing_by_id and existing_by_id[server_id] != server
        }

        old_servers = self.config["servers"]
        self.config["servers"] = merged
        try:
            self.save_config()
        except OSError as exc:
            self.config["servers"] = old_servers
            show_notice(self, "导入失败", f"无法保存服务器配置：\n{exc}", tone="danger")
            return

        for server_id in changed_ids:
            self.disconnect(server_id, quiet=True)
        self.refresh_servers()
        show_notice(
            self,
            "导入完成",
            f"新增 {added} 台，更新 {updated} 台。原有的其他服务器配置已保留；导入和导出均不包含密码。",
        )

    def edit_server(self):
        server_id = self.selected_id()
        server = self.server_by_id.get(server_id)
        if not server:
            return
        dialog = ServerDialog(self, dict(server))
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.result:
            self.disconnect(server_id, quiet=True)
            updated = dialog.result
            updated["id"] = server_id
            self.config["servers"] = [updated if entry["id"] == server_id else entry for entry in self.config["servers"]]
            self.save_config()
            self.refresh_servers()

    def delete_server(self):
        server_id = self.selected_id()
        server = self.server_by_id.get(server_id)
        if not server:
            return
        if not ask_confirmation(self, "删除服务器", f'确定删除“{server["name"]}”吗？此操作无法撤销。'):
            return
        self.disconnect(server_id, quiet=True)
        self.config["servers"] = [entry for entry in self.config["servers"] if entry["id"] != server_id]
        self.save_config()
        self.refresh_servers()

    def show_help(self):
        show_notice(
            self,
            "连接说明",
            "直连：添加服务器时，SSH 服务器和用户名留空，VNC 地址填写服务器 IP/域名。\n\n"
            "SSH 隧道：填写 SSH 服务器和用户名，VNC 地址填写 SSH 服务器可访问的地址，通常是 127.0.0.1。\n\n"
            "连接时输入 VNC 密码；无密码的 VNC 服务可留空。键盘和鼠标可直接操作远程桌面。",
        )

    def connect_selected(self):
        server_id = self.selected_id()
        server = self.server_by_id.get(server_id)
        if not server:
            return
        viewer = self.viewer_windows.get(server_id)
        if viewer and not viewer.closed:
            if not viewer.failed:
                self.workspace.setCurrentWidget(viewer)
                self.showNormal()
                self.raise_()
                self.activateWindow()
                return
            viewer.close()
        if not server.get("ssh_host"):
            self.open_vnc_viewer(server, server["target_host"], int(server["target_port"]))
            return
        tunnel = self.tunnels.get(server_id)
        if tunnel and tunnel["status"] == "active":
            self.launch_viewer(server, tunnel["local_port"])
            return
        if tunnel and tunnel["status"] == "connecting":
            return
        if tunnel:
            worker = tunnel.get("worker")
            if worker:
                worker.stop()
            self.tunnels.pop(server_id, None)

        port = self.choose_local_port(server)
        if port is None:
            return

        worker = _SSHForwardWorker(server, port, self.ui_queue)
        self.tunnels[server_id] = {
            "worker": worker,
            "local_port": port,
            "status": "connecting",
        }
        self.status_var.set(f'正在连接 {server["ssh_user"]}@{server["ssh_host"]}，请在主窗口内完成 SSH 认证。')
        self.refresh_servers()
        self.ssh_console.show()
        self.ssh_console_status.setText(
            f'正在连接 {server["ssh_user"]}@{server["ssh_host"]}:{server["ssh_port"]}'
        )
        self.ssh_console_input.setEnabled(False)
        self._append_ssh_console(
            f'正在建立转发 127.0.0.1:{port} -> {server["target_host"]}:{server["target_port"]}',
            server_id,
        )
        self._append_ssh_console(f"SSH 日志文件：{ssh_log_path()}", server_id)
        self._append_ssh_console(f"SSH 客户端：内置 Paramiko {paramiko.__version__}", server_id)
        worker.start()

    def choose_local_port(self, server: dict) -> int | None:
        requested = int(server["local_port"])
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", requested))
                return int(probe.getsockname()[1])
        except OSError:
            show_notice(
                self,
                "本地端口被占用",
                f"本机端口 {requested} 已被占用。请在服务器设置中改用 0（自动分配）或其他端口。",
                tone="danger",
            )
            return None

    def launch_viewer(self, server: dict, local_port: int):
        self.open_vnc_viewer(server, "127.0.0.1", local_port)

    def open_vnc_viewer(self, server: dict, host: str, port: int):
        server_id = server["id"]
        current = self.viewer_windows.get(server_id)
        if current and not current.closed:
            self.workspace.setCurrentWidget(current)
            current.show()
            return
        dialog = VncPasswordDialog(self, host, port)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        password = dialog.password
        dialog.password = ""
        dialog.password_edit.clear()
        endpoint = f"{host}:{port}"
        window = VncViewerWindow(self, server_id, server["name"], endpoint)
        self.viewer_windows[server_id] = window
        self.workspace.addWidget(window)
        self.workspace.setCurrentWidget(window)
        self.status_var.set(f"正在连接 VNC：{endpoint}")
        self.refresh_servers()
        window.show()
        connect_viewer(self, window, host, port, password)
        password = ""

    def disconnect_vnc(self, window: VncViewerWindow):
        window.stop_viewer()

    def process_ui_events(self):
        try:
            while True:
                event = self.ui_queue.get_nowait()
                kind = event[0]
                if kind == "reactor_error":
                    self.status_var.set(event[1])
                elif kind == "ssh_prompt":
                    self._queue_ssh_prompt(event[1], event[2], event[3])
                elif kind == "ssh_output":
                    self._append_ssh_console(event[2], event[1])
                elif kind == "ssh_ready":
                    server_id, local_port = event[1], event[2]
                    tunnel = self.tunnels.get(server_id)
                    if tunnel and tunnel["status"] == "connecting":
                        tunnel["status"] = "active"
                        self.ssh_console_status.setText("SSH 隧道已建立")
                        self._append_ssh_console(
                            f"SSH 隧道已建立：127.0.0.1:{local_port}", server_id
                        )
                        self.status_var.set(f"隧道已建立：127.0.0.1:{local_port}")
                        self.refresh_servers()
                        server = self.server_by_id.get(server_id)
                        if server:
                            self.launch_viewer(server, local_port)
                elif kind == "ssh_failed":
                    server_id, message = event[1], event[2]
                    tunnel = self.tunnels.get(server_id)
                    if tunnel:
                        tunnel["status"] = "failed"
                        tunnel["message"] = message
                    if "认证失败" in message:
                        self._ssh_auth_rejected.add(server_id)
                    self.ssh_console_status.setText("SSH 连接失败")
                    self._append_ssh_console(message, server_id)
                    self.status_var.set(message)
                    self._cancel_ssh_prompts(server_id)
                    self.refresh_servers()
                elif kind == "vnc_connected":
                    window = self.viewer_windows.get(event[1])
                    if window:
                        window.set_connected(event[2])
                        self.status_var.set(f"VNC 已连接：{window.server_id}")
                    self.refresh_servers()
                elif kind in ("vnc_failed", "vnc_lost"):
                    window = self.viewer_windows.get(event[1])
                    message = event[2]
                    if window:
                        window.connected = False
                        window.failed = True
                        window.client = None
                        window.set_status("连接失败：" + message if kind == "vnc_failed" else "连接已断开：" + message)
                    self.status_var.set(f"VNC 连接失败或已断开：{message}")
                    self.refresh_servers()
        except queue.Empty:
            pass

    def disconnect_selected(self):
        server_id = self.selected_id()
        if server_id:
            self.disconnect(server_id)

    def disconnect(self, server_id: str, quiet: bool = False):
        self._cancel_ssh_prompts(server_id)
        viewer = self.viewer_windows.get(server_id)
        if viewer and not viewer.closed:
            viewer.close()
        tunnel = self.tunnels.pop(server_id, None)
        if tunnel:
            worker = tunnel.get("worker")
            if worker:
                worker.stop()
            if not quiet:
                self.status_var.set("VNC 连接和 SSH 隧道已断开。")
        self.refresh_servers()

    def monitor_tunnels(self):
        changed = False
        for _server_id, tunnel in list(self.tunnels.items()):
            worker = tunnel.get("worker")
            if tunnel["status"] == "active" and worker and not worker.is_alive():
                tunnel["status"] = "failed"
                tunnel["message"] = "SSH 连接已断开"
                changed = True
        if changed:
            self.refresh_servers()

    def show_about(self):
        show_notice(
            self,
            "关于 QingQueVNC",
            "界面使用加粗微软雅黑，并采用统一的深色石墨主题。",
        )

    def closeEvent(self, event):
        self._closing = True
        self._events_timer.stop()
        self._tunnel_timer.stop()
        self._cancel_ssh_prompts()
        for viewer in list(self.viewer_windows.values()):
            viewer.close()
        for server_id in list(self.tunnels):
            self.disconnect(server_id, quiet=True)
        event.accept()


def main():
    migrate_legacy_logs()
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(APP_NAME)
    app.setWindowIcon(qingque_icon())
    install_app_font(app)
    install_qt_chinese_translation(app)
    qdarktheme.setup_theme("dark", custom_colors={"primary": "#5B7FE0"})
    app.setStyleSheet(app.styleSheet() + APP_QSS)
    window = VncTunnelManager()
    window.show()
    sys.exit(app.exec())

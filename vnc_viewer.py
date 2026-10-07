"""QingQueVNC desktop window backed by the native TigerVNC decoder."""

from __future__ import annotations

import ctypes
import os
import queue
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QEvent, QPoint, Qt, QTimer
from app_paths import application_logs_directory
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

VNC_LOG = application_logs_directory() / "vnc-session.log"


def native_viewer_path() -> Path:
    """Find the bundled viewer in a PyInstaller build or a source checkout."""
    if getattr(sys, "frozen", False):
        root = Path(sys._MEIPASS)
        return root / "TigerVNC" / "vncviewer.exe"
    else:
        root = Path(__file__).resolve().parent
        return root / "vendor" / "TigerVNC" / "vncviewer.exe"


def _append_vnc_log(message: str) -> None:
    try:
        VNC_LOG.parent.mkdir(parents=True, exist_ok=True)
        with VNC_LOG.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"[{datetime.now().astimezone().isoformat(timespec='seconds')}] {message}\n")
    except OSError:
        pass


def _native_window_for_process(process_id: int) -> int | None:
    """Return the visible top-level viewer window, skipping standard dialogs."""
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    windows: list[tuple[bool, int, int]] = []
    enum_windows = user32.EnumWindows
    enum_proc_type = ctypes.WINFUNCTYPE(
        wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
    )
    enum_windows.argtypes = (enum_proc_type, wintypes.LPARAM)
    enum_windows.restype = wintypes.BOOL

    get_process_id = user32.GetWindowThreadProcessId
    get_process_id.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
    get_process_id.restype = ctypes.c_uint32

    is_visible = user32.IsWindowVisible
    is_visible.argtypes = (ctypes.c_void_p,)
    is_visible.restype = wintypes.BOOL

    get_owner = user32.GetWindow
    get_owner.argtypes = (ctypes.c_void_p, ctypes.c_uint)
    get_owner.restype = ctypes.c_void_p

    get_class_name = user32.GetClassNameW
    get_class_name.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int)
    get_class_name.restype = ctypes.c_int

    get_window_rect = user32.GetWindowRect
    get_window_rect.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.RECT))
    get_window_rect.restype = wintypes.BOOL

    get_window_text = user32.GetWindowTextW
    get_window_text.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int)
    get_window_text.restype = ctypes.c_int

    @enum_proc_type
    def visit(hwnd, _lparam):
        pid = ctypes.c_uint32()
        get_process_id(hwnd, ctypes.byref(pid))
        if pid.value != process_id or not is_visible(hwnd) or get_owner(hwnd, 4):
            return True
        class_name = ctypes.create_unicode_buffer(128)
        get_class_name(hwnd, class_name, len(class_name))
        if class_name.value == "#32770":
            return True
        handle = hwnd if isinstance(hwnd, int) else hwnd.value
        if handle:
            rect = wintypes.RECT()
            if get_window_rect(ctypes.c_void_p(handle), ctypes.byref(rect)):
                area = max(0, rect.right - rect.left) * max(0, rect.bottom - rect.top)
                title = ctypes.create_unicode_buffer(512)
                get_window_text(ctypes.c_void_p(handle), title, len(title))
                is_desktop_window = "tigervnc" in title.value.lower()
                windows.append((is_desktop_window, area, int(handle)))
        return True

    enum_windows(visit, 0)
    # Prefer the actual TigerVNC desktop window when its caption is available,
    # then use the largest visible non-dialog window as a fallback.
    return max(windows, key=lambda item: (item[0], item[1]))[2] if windows else None


class VncViewerWindow(QWidget):
    """QingQueVNC frame that hosts the native TigerVNC desktop surface."""

    def __init__(self, app, server_id: str, title: str, endpoint: str):
        super().__init__(app.workspace)
        self.app = app
        self.server_id = server_id
        self.display_name = title
        self.closed = False
        self.connected = False
        self.failed = False
        self.client = None
        self.factory = None
        self._process: subprocess.Popen | None = None
        self._output_thread: threading.Thread | None = None
        self._output_queue: queue.SimpleQueue[str] = queue.SimpleQueue()
        self._viewer_hwnd: int | None = None
        self._native_viewer_enabled = False
        self._embed_deadline = 0.0

        self.setObjectName("VncViewerPage")
        self.setWindowTitle(f"{title} · QingQueVNC")

        center = QWidget(self)
        center.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout = QVBoxLayout(center)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        toolbar = QFrame(center)
        toolbar.setObjectName("ViewerToolbar")
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(16, 8, 16, 8)
        toolbar_layout.setSpacing(10)
        back_button = QPushButton("连接管理", toolbar)
        back_button.setProperty("quiet", True)
        back_button.clicked.connect(self.app.show_manager_page)
        toolbar_layout.addWidget(back_button)
        server_label = QLabel(title, toolbar)
        server_label.setObjectName("ViewerServerName")
        toolbar_layout.addWidget(server_label)
        self.status_label = QLabel(f"正在启动原生解码器 · {endpoint}")
        self.status_label.setObjectName("ViewerStatus")
        toolbar_layout.addWidget(self.status_label, 1)
        engine_label = QLabel("TigerVNC · Tight")
        engine_label.setObjectName("ViewerStatus")
        toolbar_layout.addWidget(engine_label)
        cad_button = QPushButton("发送 Ctrl+Alt+Del")
        cad_button.clicked.connect(self.send_ctrl_alt_del)
        toolbar_layout.addWidget(cad_button)
        close_button = QPushButton("断开")
        close_button.setProperty("danger", True)
        close_button.clicked.connect(lambda: self.app.disconnect(self.server_id))
        toolbar_layout.addWidget(close_button)
        layout.addWidget(toolbar)

        self.desktop_host = QFrame(center)
        self.desktop_host.setObjectName("RemoteDesktopHost")
        self.desktop_host.setAttribute(Qt.WidgetAttribute.WA_NativeWindow, True)
        self.desktop_host.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.desktop_host.setStyleSheet(
            "QFrame#RemoteDesktopHost { background: #14161B; border: none; }"
            "QLabel#RemoteDesktopPlaceholder { color: #B7BEC9; padding: 24px; }"
        )
        self.desktop_host.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        host_layout = QVBoxLayout(self.desktop_host)
        host_layout.setContentsMargins(0, 0, 0, 0)
        host_layout.setSpacing(0)
        self.placeholder = QLabel("正在连接远程桌面…", self.desktop_host)
        self.placeholder.setObjectName("RemoteDesktopPlaceholder")
        self.placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        host_layout.addWidget(self.placeholder)
        layout.addWidget(self.desktop_host, 1)

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        root_layout.addWidget(center, 1)
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(40)
        self._poll_timer.timeout.connect(self._poll_native_viewer)
        self._position_timer = QTimer(self)
        self._position_timer.setSingleShot(True)
        self._position_timer.setInterval(16)
        self._position_timer.timeout.connect(self._sync_native_viewer)
        self.app.installEventFilter(self)
        self.desktop_host.installEventFilter(self)
        self.app.workspace.currentChanged.connect(self._workspace_changed)

    def start_native_viewer(self, host: str, port: int, password: str) -> None:
        executable = native_viewer_path()
        if not executable.is_file():
            raise FileNotFoundError(f"找不到内置 TigerVNC 解码器：{executable}")

        VNC_LOG.parent.mkdir(parents=True, exist_ok=True)
        address = f"{host}::{int(port)}"
        command = [
            str(executable),
            "-PreferredEncoding=Tight",
            "-AutoSelect=1",
            "-FullColor=1",
            "-QualityLevel=8",
            "-CompressLevel=2",
            "-Shared=1",
            "-FullScreen=0",
            "-Maximize=0",
            "-RemoteResize=0",
            "-ReconnectOnError=0",
            address,
        ]
        _append_vnc_log(f"[{self.server_id}] 启动 TigerVNC 原生客户端：{address}")
        child_env = os.environ.copy()
        child_env["VNC_PASSWORD"] = password
        self._process = subprocess.Popen(
            command,
            cwd=str(executable.parent),
            env=child_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        child_env.pop("VNC_PASSWORD", None)
        self._output_thread = threading.Thread(
            target=self._capture_native_output,
            args=(self._process,),
            name=f"TigerVNC-log-{self.server_id}",
            daemon=True,
        )
        self._output_thread.start()
        self._embed_deadline = time.monotonic() + 20
        self._poll_timer.start()

    def _capture_native_output(self, process: subprocess.Popen) -> None:
        stream = process.stdout
        if stream is None:
            return
        try:
            for raw_line in iter(stream.readline, b""):
                line = raw_line.decode("utf-8", "replace").rstrip("\r\n")
                if not line:
                    continue
                _append_vnc_log(f"[{self.server_id}] {line}")
                self._output_queue.put(line)
        finally:
            stream.close()

    def _consume_native_output(self) -> None:
        while True:
            try:
                line = self._output_queue.get_nowait()
            except queue.Empty:
                return

            if "too many security failures" in line.lower():
                self._mark_failed(
                    "VNC 服务端暂时封锁了连接（连续认证失败）。请等待解封或重启远程 VNC 服务，再重试。"
                )
            elif "authentication failed" in line.lower():
                self._mark_failed("VNC 身份验证失败：服务器拒绝了密码。")
            elif (
                "desktop name:" in line.lower()
                or "enabling continuous updates" in line.lower()
            ) and not self.connected:
                self.connected = True
                self.failed = False
                self.set_status("已连接 · TigerVNC Tight 原生解码")
                _append_vnc_log(f"[{self.server_id}] VNC 身份验证成功，远程桌面已就绪")
                self._refresh_app()

    def _poll_native_viewer(self) -> None:
        if self.closed or self._process is None:
            self._poll_timer.stop()
            return
        self._consume_native_output()
        exit_code = self._process.poll()
        if exit_code is not None:
            output_thread = self._output_thread
            if output_thread is not None and output_thread.is_alive():
                return
            self._consume_native_output()
            self._poll_timer.stop()
            if self.connected:
                self.connected = False
                self.failed = True
                self._show_placeholder("远程桌面连接已断开")
                self.set_status(f"连接已断开（退出代码 {exit_code}）")
                _append_vnc_log(f"[{self.server_id}] TigerVNC 退出，代码 {exit_code}")
                self._refresh_app()
            elif not self.failed:
                self._mark_failed(
                    f"TigerVNC 已退出（代码 {exit_code}）。请确认远程 VNC 服务和密码。"
                )
            return

        if self._viewer_hwnd is None:
            handle = _native_window_for_process(self._process.pid)
            if handle:
                try:
                    self._embed_native_window(handle)
                except Exception as exc:
                    self._mark_failed(
                        f"无法嵌入 TigerVNC 窗口：{type(exc).__name__}: {exc}"
                    )
                    self.stop_viewer()
                    return
            elif time.monotonic() >= self._embed_deadline:
                self._mark_failed("启动 TigerVNC 超时，未能载入远程桌面窗口。")
                self.stop_viewer()
                return

        if self._viewer_hwnd is not None and not self._is_window(self._viewer_hwnd):
            self._viewer_hwnd = None

    def _embed_native_window(self, hwnd: int) -> None:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        main_hwnd = int(self.app.winId())
        style_index = -16
        ex_style_index = -20
        owner_index = -8

        # Keep TigerVNC as a top-level window so its own renderer continues to
        # receive normal paint messages. Remove its frame and make it an owned
        # window of QingQueVNC, then align it over the remote canvas.
        user32.ShowWindow.argtypes = (ctypes.c_void_p, ctypes.c_int)
        user32.ShowWindow.restype = ctypes.c_bool
        user32.ShowWindow(ctypes.c_void_p(hwnd), 0)
        style = self._get_window_long(user32, hwnd, style_index)
        self._set_window_long(user32, hwnd, style_index, style & ~0x00CF0000)
        ex_style = self._get_window_long(user32, hwnd, ex_style_index)
        self._set_window_long(
            user32, hwnd, ex_style_index, (ex_style & ~0x00040000) | 0x00000080
        )
        ctypes.set_last_error(0)
        previous_owner = self._set_window_long(user32, hwnd, owner_index, main_hwnd)
        owner_error = ctypes.get_last_error()
        if previous_owner == 0 and owner_error:
            _append_vnc_log(
                f"[{self.server_id}] 设置 TigerVNC 窗口所有者失败：{ctypes.WinError(owner_error)}"
            )

        self._viewer_hwnd = hwnd
        self._native_viewer_enabled = True
        self.connected = False
        if not self.failed:
            self.set_status("TigerVNC 窗口已打开，正在验证 VNC 身份…")
        get_class_name = user32.GetClassNameW
        get_class_name.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int)
        get_class_name.restype = ctypes.c_int
        get_window_text = user32.GetWindowTextW
        get_window_text.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int)
        get_window_text.restype = ctypes.c_int
        class_name = ctypes.create_unicode_buffer(128)
        title = ctypes.create_unicode_buffer(512)
        get_class_name(ctypes.c_void_p(hwnd), class_name, len(class_name))
        get_window_text(ctypes.c_void_p(hwnd), title, len(title))
        _append_vnc_log(
            f"[{self.server_id}] TigerVNC 保持原生窗口并覆盖到远程画布 "
            f"(hwnd=0x{hwnd:X}, class={class_name.value!r}, title={title.value!r}, "
            f"size={self.desktop_host.width()}x{self.desktop_host.height()})"
        )
        self.placeholder.hide()
        self._sync_native_viewer()
        self._refresh_app()

    @staticmethod
    def _is_window(hwnd: int) -> bool:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.IsWindow.argtypes = (ctypes.c_void_p,)
        user32.IsWindow.restype = ctypes.c_bool
        return bool(user32.IsWindow(ctypes.c_void_p(hwnd)))

    @staticmethod
    def _get_window_long(user32, hwnd: int, index: int) -> int:
        function = getattr(user32, "GetWindowLongPtrW", user32.GetWindowLongW)
        function.argtypes = (ctypes.c_void_p, ctypes.c_int)
        function.restype = ctypes.c_ssize_t
        return int(function(ctypes.c_void_p(hwnd), index))

    @staticmethod
    def _set_window_long(user32, hwnd: int, index: int, value: int) -> int:
        function = getattr(user32, "SetWindowLongPtrW", user32.SetWindowLongW)
        function.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_ssize_t)
        function.restype = ctypes.c_ssize_t
        return int(function(ctypes.c_void_p(hwnd), index, value))

    def _workspace_changed(self, _index: int) -> None:
        self._schedule_native_sync()

    def _schedule_native_sync(self) -> None:
        if not self._position_timer.isActive():
            self._position_timer.start()

    def _sync_native_viewer(self) -> None:
        hwnd = self._viewer_hwnd
        if hwnd is None or not self._is_window(hwnd):
            return

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        visible = (
            self._native_viewer_enabled
            and self.app.workspace.currentWidget() is self
            and self.app.isVisible()
            and not self.app.isMinimized()
        )
        if not visible:
            user32.ShowWindow.argtypes = (ctypes.c_void_p, ctypes.c_int)
            user32.ShowWindow.restype = ctypes.c_bool
            user32.ShowWindow(ctypes.c_void_p(hwnd), 0)
            return

        main_hwnd = int(self.app.winId())
        client_origin = wintypes.POINT(0, 0)
        user32.ClientToScreen.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.POINT),
        )
        user32.ClientToScreen.restype = wintypes.BOOL
        if not user32.ClientToScreen(ctypes.c_void_p(main_hwnd), ctypes.byref(client_origin)):
            return

        local_origin = self.desktop_host.mapTo(self.app, QPoint(0, 0))
        scale = self.desktop_host.devicePixelRatioF()
        x = client_origin.x + round(local_origin.x() * scale)
        y = client_origin.y + round(local_origin.y() * scale)
        width = max(1, round(self.desktop_host.width() * scale))
        height = max(1, round(self.desktop_host.height() * scale))

        user32.SetWindowPos.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint,
        )
        user32.SetWindowPos.restype = ctypes.c_bool
        flags = 0x0004 | 0x0010 | 0x0020 | 0x0040 | 0x4000
        if not user32.SetWindowPos(
            ctypes.c_void_p(hwnd), None, x, y, width, height, flags
        ):
            error = ctypes.get_last_error()
            _append_vnc_log(
                f"[{self.server_id}] 对齐 TigerVNC 画面窗口失败："
                f"{ctypes.WinError(error) if error else '未知错误'}"
            )
            return
        self._apply_native_viewer_region(hwnd, width, height, scale)

    @staticmethod
    def _apply_native_viewer_region(hwnd: int, width: int, height: int, scale: float) -> None:
        gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        radius = max(1, round(16 * scale))
        radius = min(radius, width // 2, height // 2)
        if radius <= 0:
            return

        gdi32.CreateRectRgn.argtypes = (
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
        )
        gdi32.CreateRectRgn.restype = ctypes.c_void_p
        gdi32.CreateRoundRectRgn.argtypes = (
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
        )
        gdi32.CreateRoundRectRgn.restype = ctypes.c_void_p
        gdi32.CombineRgn.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_int,
        )
        gdi32.CombineRgn.restype = ctypes.c_int
        gdi32.DeleteObject.argtypes = (ctypes.c_void_p,)
        gdi32.DeleteObject.restype = ctypes.c_bool
        user32.SetWindowRgn.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool)
        user32.SetWindowRgn.restype = ctypes.c_int

        top = gdi32.CreateRectRgn(0, 0, width, max(1, height - radius))
        bottom = gdi32.CreateRoundRectRgn(
            0, height - 2 * radius, width, height, 2 * radius, 2 * radius
        )
        combined = gdi32.CreateRectRgn(0, 0, 0, 0)
        if not top or not bottom or not combined:
            for region in (top, bottom, combined):
                if region:
                    gdi32.DeleteObject(region)
            return

        gdi32.CombineRgn(combined, top, bottom, 2)
        gdi32.DeleteObject(top)
        gdi32.DeleteObject(bottom)
        if user32.SetWindowRgn(ctypes.c_void_p(hwnd), combined, True):
            # SetWindowRgn transfers ownership of the combined region on success.
            return
        gdi32.DeleteObject(combined)

    def eventFilter(self, watched, event):
        if watched is self.app and event.type() in (
            QEvent.Type.Move,
            QEvent.Type.Resize,
            QEvent.Type.Show,
            QEvent.Type.Hide,
            QEvent.Type.WindowStateChange,
        ):
            self._schedule_native_sync()
        elif watched is self.desktop_host and event.type() in (
            QEvent.Type.Move,
            QEvent.Type.Resize,
        ):
            self._schedule_native_sync()
        return False

    def _show_placeholder(self, message: str) -> None:
        self.placeholder.setText(message)
        self._native_viewer_enabled = False
        if self._viewer_hwnd is not None and self._is_window(self._viewer_hwnd):
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            user32.ShowWindow(ctypes.c_void_p(self._viewer_hwnd), 0)
        self.placeholder.show()

    def _mark_failed(self, message: str) -> None:
        self.connected = False
        self.failed = True
        self._show_placeholder(message)
        self.set_status(message)
        _append_vnc_log(f"[{self.server_id}] {message}")
        self._refresh_app()

    def set_connected(self, _client=None) -> None:
        self.connected = True
        self.failed = False
        self._refresh_app()

    def set_status(self, text: str) -> None:
        if not self.closed:
            self.status_label.setText(text)

    def _refresh_app(self) -> None:
        if self.closed:
            return
        if hasattr(self.app, "status_var"):
            self.app.status_var.set(f"VNC：{self.display_name}")
        if hasattr(self.app, "refresh_servers"):
            self.app.refresh_servers()

    def send_ctrl_alt_del(self) -> None:
        if self._viewer_hwnd is None or not self._is_window(self._viewer_hwnd):
            return
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.PostMessageW.argtypes = (
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_size_t,
            ctypes.c_ssize_t,
        )
        user32.PostMessageW.restype = ctypes.c_bool
        key_events = (
            (0x0100, 0x11, 0x0001),
            (0x0100, 0x12, 0x0001),
            (0x0100, 0x2E, 0x0001),
            (0x0101, 0x2E, 0xC0000001),
            (0x0101, 0x12, 0xC0000001),
            (0x0101, 0x11, 0xC0000001),
        )
        for message, key, flags in key_events:
            user32.PostMessageW(
                ctypes.c_void_p(self._viewer_hwnd), message, key, flags
            )
        self.desktop_host.setFocus()

    def stop_viewer(self) -> None:
        self._poll_timer.stop()
        process = self._process
        self._process = None
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except OSError:
                    pass
        self._viewer_hwnd = None

    def closeEvent(self, event):
        if not self.closed:
            self.closed = True
            self.stop_viewer()
            self.app.disconnect_vnc(self)
            self.app.viewer_windows.pop(self.server_id, None)
            if self.app.workspace.currentWidget() is self:
                self.app.show_manager_page()
            self.app.workspace.removeWidget(self)
            self.deleteLater()
            self.app.refresh_servers()
        event.accept()


def connect_viewer(app, window: VncViewerWindow, host: str, port: int, password: str):
    try:
        window.start_native_viewer(host, port, password)
    except Exception as exc:
        window._mark_failed(f"无法启动原生 VNC 解码器：{type(exc).__name__}: {exc}")

"""Lightweight custom title bars and resize handling for frameless Qt windows."""

from __future__ import annotations

import sys
from pathlib import Path

import ctypes
from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QRegion
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QToolButton,
    QVBoxLayout,
    QWidget,
)


def qingque_icon() -> QIcon:
    """Load the app mark from source assets or the PyInstaller bundle."""
    root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return QIcon(str(root / "assets" / "qingquevnc.png"))


def _apply_rounded_mask(window, radius: float = 16.0) -> None:
    width = max(1, window.width())
    height = max(1, window.height())
    path = QPainterPath()
    path.addRoundedRect(0.0, 0.0, float(width), float(height), radius, radius)
    window.setMask(QRegion(path.toFillPolygon().toPolygon()))


def _resize_edges(point, width: int, height: int, margin: int = 7):
    edges = Qt.Edges()
    if point.x() <= margin:
        edges |= Qt.Edge.LeftEdge
    elif point.x() >= width - margin:
        edges |= Qt.Edge.RightEdge
    if point.y() <= margin:
        edges |= Qt.Edge.TopEdge
    elif point.y() >= height - margin:
        edges |= Qt.Edge.BottomEdge
    return edges


def _resize_cursor(edges):
    left = bool(edges & Qt.Edge.LeftEdge)
    right = bool(edges & Qt.Edge.RightEdge)
    top = bool(edges & Qt.Edge.TopEdge)
    bottom = bool(edges & Qt.Edge.BottomEdge)
    if (left and top) or (right and bottom):
        return Qt.CursorShape.SizeFDiagCursor
    if (right and top) or (left and bottom):
        return Qt.CursorShape.SizeBDiagCursor
    if left or right:
        return Qt.CursorShape.SizeHorCursor
    if top or bottom:
        return Qt.CursorShape.SizeVerCursor
    return Qt.CursorShape.ArrowCursor


class _ResizeFilter(QObject):
    def __init__(self, window):
        super().__init__(window)
        self.window = window

    def eventFilter(self, watched, event):
        if event.type() == QEvent.Type.Resize:
            _apply_rounded_mask(self.window)
            return False
        if event.type() not in (QEvent.Type.MouseButtonPress, QEvent.Type.MouseMove):
            return False
        point = event.position().toPoint()
        edges = _resize_edges(point, watched.width(), watched.height())
        watched.setCursor(_resize_cursor(edges))
        if event.type() == QEvent.Type.MouseButtonPress and event.button() == Qt.MouseButton.LeftButton and edges:
            handle = self.window.windowHandle()
            if handle is not None:
                handle.startSystemResize(edges)
                return True
        return False


class CustomTitleBar(QWidget):
    def __init__(self, window, *, allow_maximize=True):
        super().__init__(window)
        self.window = window
        self.allow_maximize = allow_maximize
        self.setObjectName("CustomTitleBar")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedHeight(46)
        self.setCursor(Qt.CursorShape.OpenHandCursor)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 0, 8, 0)
        layout.setSpacing(11)

        self.brand = QLabel()
        self.brand.setObjectName("TitleBarBrand")
        self.brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.brand.setPixmap(qingque_icon().pixmap(27, 27))
        self.brand.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        layout.addWidget(self.brand)

        self.title = QLabel(window.windowTitle())
        self.title.setObjectName("TitleBarText")
        self.title.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        layout.addWidget(self.title, 1)
        window.windowTitleChanged.connect(self.title.setText)

        self.minimize_button = self._button("−", "最小化", window.showMinimized)
        layout.addWidget(self.minimize_button)
        self.maximize_button = None
        if self.allow_maximize:
            self.maximize_button = self._button("□", "最大化", self.toggle_maximize)
            layout.addWidget(self.maximize_button)
        else:
            self.minimize_button.hide()
        self.close_button = self._button("×", "关闭", window.close)
        self.close_button.setObjectName("TitleBarClose")
        layout.addWidget(self.close_button)
        window.installEventFilter(self)
        if self.maximize_button:
            self.sync_maximize_button()

    @staticmethod
    def _button(text: str, tooltip: str, slot):
        button = QToolButton()
        button.setText(text)
        button.setToolTip(tooltip)
        button.setObjectName("TitleBarButton")
        button.setFixedSize(40, 34)
        button.clicked.connect(slot)
        return button

    def toggle_maximize(self):
        if self.window.isMaximized():
            self.window.showNormal()
        else:
            self.window.showMaximized()
        self.sync_maximize_button()

    def sync_maximize_button(self):
        if not self.maximize_button:
            return
        maximized = self.window.isMaximized()
        self.maximize_button.setText("❐" if maximized else "□")
        self.maximize_button.setToolTip("还原" if maximized else "最大化")

    def eventFilter(self, watched, event):
        if watched is self.window and event.type() == QEvent.Type.WindowStateChange:
            self.sync_maximize_button()
        return False

    def paintEvent(self, event):
        # WA_TranslucentBackground on the top-level window can leave a menu widget
        # transparent on Windows even when a global QSS background is present.
        # Paint the chrome directly so wallpaper/console windows never show through.
        painter = QPainter(self)
        # Match the application canvas so the title bar and page read as one
        # continuous window surface rather than stacked panels.
        background = "#181A1F" if self.allow_maximize else "#24272E"
        painter.fillRect(self.rect(), QColor(background))

    def mousePressEvent(self, event):
        if event.button() != Qt.MouseButton.LeftButton:
            event.ignore()
            return
        point = event.position().toPoint()
        edges = _resize_edges(point, self.width(), self.height())
        handle = self.window.windowHandle()
        if handle is None:
            event.ignore()
            return
        if edges:
            handle.startSystemResize(edges)
        elif not self.window.isMaximized():
            self.setCursor(Qt.CursorShape.ClosedHandCursor)
            if sys.platform == "win32":
                # QWindow.startSystemMove() may return without initiating a native
                # move loop for a frameless QMainWindow. WM_NCLBUTTONDOWN delegates
                # the drag to the Windows window manager and keeps it smooth.
                hwnd = int(self.window.winId())
                user32 = ctypes.WinDLL("user32", use_last_error=True)
                user32.ReleaseCapture()
                user32.SendMessageW.argtypes = (
                    ctypes.c_void_p,
                    ctypes.c_uint,
                    ctypes.c_size_t,
                    ctypes.c_ssize_t,
                )
                user32.SendMessageW.restype = ctypes.c_ssize_t
                user32.SendMessageW(ctypes.c_void_p(hwnd), 0x00A1, 2, 0)
            else:
                handle.startSystemMove()
        event.accept()

    def mouseReleaseEvent(self, event):
        self.setCursor(Qt.CursorShape.OpenHandCursor)
        event.accept()

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.allow_maximize:
            self.toggle_maximize()
            event.accept()
        else:
            event.ignore()


def apply_custom_chrome(window):
    """Replace the native title bar and leave a narrow resize border around content."""
    window.setWindowIcon(qingque_icon())
    window.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
    window.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
    central = window.takeCentralWidget()

    surface = QWidget(window)
    surface.setObjectName("WindowResizeSurface")
    surface.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
    layout = QVBoxLayout(surface)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(0)
    if central is not None:
        layout.addWidget(central)
    window.setCentralWidget(surface)

    title_bar = CustomTitleBar(window)
    window.setMenuWidget(title_bar)
    resize_filter = _ResizeFilter(window)
    surface.installEventFilter(resize_filter)
    surface.setMouseTracking(True)

    # Keep Python references so Qt wrappers and the event filter live as long as the window.
    window._custom_title_bar = title_bar
    window._resize_filter = resize_filter
    window._resize_surface = surface
    _apply_rounded_mask(window)


def create_dialog_body(window):
    """Give a QDialog the same frameless title bar and resize affordance as the main window."""
    window.setWindowIcon(qingque_icon())
    window.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
    window.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

    surface = QWidget(window)
    surface.setObjectName("DialogSurface")
    surface_layout = QVBoxLayout(surface)
    surface_layout.setContentsMargins(1, 1, 1, 1)
    surface_layout.setSpacing(0)
    title_bar = CustomTitleBar(window, allow_maximize=False)
    surface_layout.addWidget(title_bar)

    body = QWidget(surface)
    body.setObjectName("DialogBody")
    surface_layout.addWidget(body, 1)

    root_layout = QVBoxLayout(window)
    root_layout.setContentsMargins(1, 1, 1, 1)
    root_layout.setSpacing(0)
    root_layout.addWidget(surface)

    resize_filter = _ResizeFilter(window)
    body.installEventFilter(resize_filter)
    body.setMouseTracking(True)
    window.installEventFilter(resize_filter)
    window._custom_title_bar = title_bar
    window._resize_filter = resize_filter
    window._dialog_surface = surface
    window._dialog_body = body
    _apply_rounded_mask(window)
    return body

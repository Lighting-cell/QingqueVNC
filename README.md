# QingQueVNC

QingQueVNC 是 Windows VNC 远程桌面管理器。界面基于 PySide6，画面由随程序提供的 TigerVNC 客户端解码，可直接连接 VNC，也可通过 SSH 隧道连接。

## 使用

启动 `release\QingQueVNC.exe`，在连接管理中添加服务器。直接连接时填写 VNC 地址和端口；使用 SSH 隧道时填写 SSH 服务器、用户名，以及服务器可访问的 VNC 地址和端口。

程序不预置服务器。SSH 和 VNC 密码在连接时输入，不会保存到连接配置。连接地址、用户名和私钥路径保存在 `%APPDATA%\VncTunnelManager\config.json`。SSH 主机指纹保存在 `%USERPROFILE%\.ssh\known_hosts`。

运行日志保存在项目目录的 `logs` 文件夹。分享项目或日志前，请检查并删除其中可能含有的连接信息。

## 项目结构

- `vnc_tunnel_manager_qt.py`：主窗口、服务器管理和 SSH 隧道
- `vnc_viewer.py`：TigerVNC 画面窗口及嵌入逻辑
- `qt_window_chrome.py`：自绘标题栏、窗口拖动和圆角处理
- `app_paths.py`：程序路径与日志迁移
- `assets`：程序图标
- `vendor/TigerVNC`：随程序分发的 TigerVNC 客户端
- `release`：当前 Windows 可执行文件与第三方许可
- `QingQueVNC.spec`：PyInstaller 打包配置

## 从源码构建

使用 Python 3.11 创建虚拟环境并安装依赖：

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
pyinstaller --noconfirm --clean --distpath .\release --workpath .\build .\QingQueVNC.spec
```

第三方组件许可见 `release\THIRD_PARTY_NOTICES.txt` 和 `release\licenses`。
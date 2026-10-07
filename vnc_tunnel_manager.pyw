"""Windows application entry point. The UI is implemented with PySide6/Qt."""

import os

if os.environ.get("VNC_TUNNEL_ASKPASS_PORT"):
    from ssh_askpass import main

    raise SystemExit(main())

from vnc_tunnel_manager_qt import main


if __name__ == "__main__":
    main()

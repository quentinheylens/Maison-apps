"""Replace the initial process so injected credentials leave even /proc environ."""

import os
import sys


def clean_environment() -> dict[str, str]:
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1"}


if __name__ == "__main__":
    os.execve(sys.executable, [sys.executable, "-m", "gateway.green_app"], clean_environment())

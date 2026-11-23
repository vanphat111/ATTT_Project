#!/usr/bin/env python3
"""Main Entry Point for the Cryptography Suite GUI Application."""

import sys
import os

# Ensure the root project directory is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from gui.app import CryptoApp


def main():
    """Launch the main GUI application window."""
    app = CryptoApp()
    app.mainloop()


if __name__ == "__main__":
    main()

import tkinter as tk
from tkinter import ttk

from gui.tab_sha256 import TabSHA256
from gui.tab_aes128 import TabAES128
from gui.tab_schnorr import TabSchnorr
from gui.tab_benchmark import TabBenchmark


class CryptoApp(tk.Tk):
    """Main application window for the Cryptography Suite."""

    def __init__(self):
        super().__init__()
        self.title("Information Security Cryptographic Suite - ATTT")
        self.geometry("1040x760")
        self.minsize(920, 680)

        self._configure_styles()
        self._build_header()
        self._build_notebook()
        self._build_statusbar()

    def _configure_styles(self):
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        # Global font and widget styles
        self.style.configure(".", font=("Helvetica", 10))
        self.style.configure("TLabel", padding=2)
        self.style.configure("TButton", padding=5, font=("Helvetica", 9, "bold"))
        self.style.configure("TLabelframe", padding=8)
        self.style.configure("TLabelframe.Label", font=("Helvetica", 10, "bold"), foreground="#1a365d")

        # Notebook tab styling
        self.style.configure("TNotebook", tabmargins=[4, 4, 4, 0])
        self.style.configure("TNotebook.Tab", padding=[14, 6], font=("Helvetica", 9, "bold"))
        self.style.map(
            "TNotebook.Tab",
            background=[("selected", "#ffffff"), ("!selected", "#e2e8f0")],
            foreground=[("selected", "#0f172a"), ("!selected", "#475569")],
        )

    def _build_header(self):
        header_frame = tk.Frame(self, bg="#1e293b", height=60)
        header_frame.pack(side="top", fill="x")
        header_frame.pack_propagate(False)

        lbl_title = tk.Label(
            header_frame,
            text="INFORMATION SECURITY - CRYPTOGRAPHIC SUITE",
            font=("Helvetica", 13, "bold"),
            bg="#1e293b",
            fg="#f8fafc",
        )
        lbl_title.pack(anchor="w", padx=15, pady=(8, 2))

        lbl_subtitle = tk.Label(
            header_frame,
            text="Pure First-Principles Python Implementation | SHA-256 | AES-128 CBC | ECC | Schnorr Digital Signature",
            font=("Helvetica", 9),
            bg="#1e293b",
            fg="#94a3b8",
        )
        lbl_subtitle.pack(anchor="w", padx=15, pady=(0, 6))

    def _build_notebook(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(side="top", fill="both", expand=True, padx=8, pady=6)

        # 4 Core Functional Tabs
        self.tab_sha256 = TabSHA256(self.notebook, self)
        self.tab_aes128 = TabAES128(self.notebook, self)
        self.tab_schnorr = TabSchnorr(self.notebook, self)
        self.tab_benchmark = TabBenchmark(self.notebook, self)

        self.notebook.add(self.tab_sha256, text=" 1. SHA-256 & Key Derivation ")
        self.notebook.add(self.tab_aes128, text=" 2. AES-128 (CBC Mode) ")
        self.notebook.add(self.tab_schnorr, text=" 3. Schnorr Signature (ECC) ")
        self.notebook.add(self.tab_benchmark, text=" 4. Test Runner & Benchmarks ")

    def _build_statusbar(self):
        status_frame = tk.Frame(self, bg="#f1f5f9", height=26, relief="sunken", borderwidth=1)
        status_frame.pack(side="bottom", fill="x")
        status_frame.pack_propagate(False)

        self.lbl_status = tk.Label(
            status_frame,
            text="STATUS: READY",
            font=("Courier", 9, "bold"),
            bg="#f1f5f9",
            fg="#0f172a",
        )
        self.lbl_status.pack(side="left", padx=10)

        lbl_info = tk.Label(
            status_frame,
            text="Python 3.14 | Standard Library Only | Zero External Crypto Dependencies",
            font=("Helvetica", 9),
            bg="#f1f5f9",
            fg="#64748b",
        )
        lbl_info.pack(side="right", padx=10)

    def set_status(self, text: str, fg: str = "#0f172a"):
        """Update bottom status bar message."""
        self.lbl_status.config(text=text, fg=fg)

    def transfer_key_to_aes(self, hex_key: str):
        """Pass derived AES key from Tab 1 directly to Tab 2 and switch view."""
        self.tab_aes128.set_key(hex_key)
        self.notebook.select(1)
        self.set_status("AES-128 key transferred successfully from Tab 1.", "#16a34a")

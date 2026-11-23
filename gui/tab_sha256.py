import tkinter as tk
from tkinter import ttk


class TabSHA256(ttk.Frame):
    """Tab 1: SHA-256 Hash Function & AES-128 Key Derivation."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)

        # 1. Input Section
        input_frame = ttk.LabelFrame(self, text=" 1. Input Message / Student Name ", padding=10)
        input_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        input_frame.columnconfigure(1, weight=1)

        ttk.Label(input_frame, text="Input Text:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.entry_input = ttk.Entry(input_frame, font=("Courier", 10))
        self.entry_input.insert(0, "Hồ Văn Phát")
        self.entry_input.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.entry_input.bind("<KeyRelease>", self._on_input_change)

        ttk.Label(input_frame, text="UTF-8 Hex:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.lbl_utf8_hex = ttk.Label(input_frame, text="", font=("Courier", 9), foreground="#555555")
        self.lbl_utf8_hex.grid(row=1, column=1, sticky="w", padx=5, pady=5)

        # 2. Action Buttons Frame
        btn_frame = ttk.Frame(self, padding=5)
        btn_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)

        self.btn_hash = ttk.Button(btn_frame, text="Compute SHA-256 Digest", command=self.compute_sha256)
        self.btn_hash.pack(side="left", padx=5)

        self.btn_extract_key = ttk.Button(btn_frame, text="Extract AES-128 Key (First 16 Bytes)", command=self.extract_aes_key)
        self.btn_extract_key.pack(side="left", padx=5)

        self.btn_send_aes = ttk.Button(btn_frame, text="Transfer Key to AES-128 Tab", command=self.transfer_key)
        self.btn_send_aes.pack(side="left", padx=5)

        # 3. Output Section
        output_frame = ttk.LabelFrame(self, text=" 2. Cryptographic Output ", padding=10)
        output_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=5)
        output_frame.columnconfigure(1, weight=1)

        ttk.Label(output_frame, text="SHA-256 Digest (256-bit / 64 Hex):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.entry_digest = ttk.Entry(output_frame, font=("Courier", 10), state="readonly")
        self.entry_digest.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        ttk.Label(output_frame, text="Derived AES-128 Key (128-bit / 32 Hex):").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.entry_aes_key = ttk.Entry(output_frame, font=("Courier", 10), state="readonly")
        self.entry_aes_key.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        # 4. Step-by-Step Info Section
        info_frame = ttk.LabelFrame(self, text=" 3. Algorithm Specifications ", padding=10)
        info_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=(5, 10))
        info_frame.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        self.txt_info = tk.Text(info_frame, font=("Courier", 9), height=10, wrap="word", bg="#f8f9fa", relief="solid", borderwidth=1)
        self.txt_info.pack(fill="both", expand=True, padx=5, pady=5)
        self._load_spec_info()

        # Initialize hex preview
        self._on_input_change(None)

    def _on_input_change(self, event):
        text = self.entry_input.get()
        raw_bytes = text.encode("utf-8")
        self.lbl_utf8_hex.config(text=raw_bytes.hex())

    def _load_spec_info(self):
        info_text = (
            "SHA-256 SPECIFICATION (FIPS 180-4):\n"
            "- Word size: 32 bits, Block size: 512 bits (64 bytes), Digest: 256 bits (32 bytes).\n"
            "- Message schedule: W_0 .. W_63 with sigma0 and sigma1 functions.\n"
            "- 64 compression rounds with round constants K_0 .. K_63.\n"
            "\n"
            "AES-128 KEY DERIVATION SPECIFICATION:\n"
            "- Student Name: 'Hồ Văn Phát' -> UTF-8 bytes -> SHA-256 digest.\n"
            "- AES-128 Key = First 16 bytes (128 bits) of SHA-256 digest.\n"
            "- Standard CBC mode uses this 128-bit key with PKCS#7 padding."
        )
        self.txt_info.insert("1.0", info_text)
        self.txt_info.config(state="disabled")

    def compute_sha256(self):
        """Placeholder for logic integration."""
        pass

    def extract_aes_key(self):
        """Placeholder for logic integration."""
        pass

    def transfer_key(self):
        """Transfer key to Tab 2."""
        pass

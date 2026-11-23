import tkinter as tk
from tkinter import ttk


class TabAES128(ttk.Frame):
    """Tab 2: AES-128 Symmetric Encryption & Decryption (CBC Mode)."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)

        # 1. Key & IV Parameters Frame
        param_frame = ttk.LabelFrame(self, text=" 1. Key & Initialization Vector (IV) Setup ", padding=10)
        param_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        param_frame.columnconfigure(1, weight=1)

        ttk.Label(param_frame, text="Secret Key (16 Bytes / 32 Hex):").grid(row=0, column=0, sticky="w", padx=5, pady=4)
        self.entry_key = ttk.Entry(param_frame, font=("Courier", 10))
        self.entry_key.grid(row=0, column=1, sticky="ew", padx=5, pady=4)

        btn_box_key = ttk.Frame(param_frame)
        btn_box_key.grid(row=0, column=2, padx=5, pady=4)

        self.btn_load_report_aes = ttk.Button(btn_box_key, text="Load Report Params", command=self.load_report_params)
        self.btn_load_report_aes.pack(side="left", padx=3)

        self.btn_validate_key = ttk.Button(btn_box_key, text="Validate Key", command=self.validate_key)
        self.btn_validate_key.pack(side="left", padx=3)

        ttk.Label(param_frame, text="IV (16 Bytes / 32 Hex):").grid(row=1, column=0, sticky="w", padx=5, pady=4)
        self.entry_iv = ttk.Entry(param_frame, font=("Courier", 10))
        self.entry_iv.grid(row=1, column=1, sticky="ew", padx=5, pady=4)

        self.btn_gen_iv = ttk.Button(param_frame, text="Generate Random IV", command=self.generate_random_iv)
        self.btn_gen_iv.grid(row=1, column=2, padx=5, pady=4)

        # 2. Encryption Frame
        enc_frame = ttk.LabelFrame(self, text=" 2. Encryption (CBC Mode with PKCS#7 Padding) ", padding=10)
        enc_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
        enc_frame.columnconfigure(1, weight=1)

        ttk.Label(enc_frame, text="Plaintext (UTF-8):").grid(row=0, column=0, sticky="nw", padx=5, pady=5)
        self.txt_plaintext_in = tk.Text(enc_frame, font=("Courier", 10), height=3, relief="solid", borderwidth=1)
        self.txt_plaintext_in.insert("1.0", "Hồ Văn Phát")
        self.txt_plaintext_in.grid(row=0, column=1, columnspan=2, sticky="ew", padx=5, pady=5)

        self.btn_encrypt = ttk.Button(enc_frame, text="Encrypt (CBC Mode)", command=self.encrypt_message)
        self.btn_encrypt.grid(row=1, column=0, sticky="w", padx=5, pady=5)

        ttk.Label(enc_frame, text="PKCS#7 Padded Bytes (Hex):").grid(row=2, column=0, sticky="w", padx=5, pady=3)
        self.entry_padded_hex = ttk.Entry(enc_frame, font=("Courier", 9), state="readonly")
        self.entry_padded_hex.grid(row=2, column=1, columnspan=2, sticky="ew", padx=5, pady=3)

        ttk.Label(enc_frame, text="Ciphertext (Hex):").grid(row=3, column=0, sticky="w", padx=5, pady=3)
        self.entry_ciphertext_hex = ttk.Entry(enc_frame, font=("Courier", 9), state="readonly")
        self.entry_ciphertext_hex.grid(row=3, column=1, columnspan=2, sticky="ew", padx=5, pady=3)

        ttk.Label(enc_frame, text="Ciphertext (Base64):").grid(row=4, column=0, sticky="w", padx=5, pady=3)
        self.entry_ciphertext_b64 = ttk.Entry(enc_frame, font=("Courier", 9), state="readonly")
        self.entry_ciphertext_b64.grid(row=4, column=1, sticky="ew", padx=5, pady=3)

        self.btn_copy_to_decrypt = ttk.Button(enc_frame, text="Copy to Decrypt Panel", command=self.copy_to_decrypt)
        self.btn_copy_to_decrypt.grid(row=4, column=2, padx=5, pady=3)

        # 3. Decryption Frame
        dec_frame = ttk.LabelFrame(self, text=" 3. Decryption (CBC Mode & PKCS#7 Unpadding) ", padding=10)
        dec_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(5, 10))
        dec_frame.columnconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)

        ttk.Label(dec_frame, text="Ciphertext (Hex):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.entry_decrypt_in = ttk.Entry(dec_frame, font=("Courier", 10))
        self.entry_decrypt_in.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        self.btn_decrypt = ttk.Button(dec_frame, text="Decrypt (CBC Mode)", command=self.decrypt_message)
        self.btn_decrypt.grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(dec_frame, text="Decrypted Plaintext:").grid(row=1, column=0, sticky="nw", padx=5, pady=5)
        self.txt_plaintext_out = tk.Text(dec_frame, font=("Courier", 10), height=4, relief="solid", borderwidth=1, state="disabled")
        self.txt_plaintext_out.grid(row=1, column=1, columnspan=2, sticky="nsew", padx=5, pady=5)
        dec_frame.rowconfigure(1, weight=1)

        self.lbl_dec_status = ttk.Label(dec_frame, text="STATUS: READY", font=("Courier", 10, "bold"), foreground="#007acc")
        self.lbl_dec_status.grid(row=2, column=1, sticky="w", padx=5, pady=3)

    def set_key(self, hex_key: str):
        """Set key from external tab (e.g. Tab 1)."""
        self.entry_key.delete(0, tk.END)
        self.entry_key.insert(0, hex_key)

    def load_report_params(self):
        """Placeholder for loading report parameters."""
        pass

    def validate_key(self):
        """Placeholder for key validation."""
        pass

    def generate_random_iv(self):
        """Placeholder for random IV generation."""
        pass

    def encrypt_message(self):
        """Placeholder for encryption."""
        pass

    def copy_to_decrypt(self):
        """Placeholder for copying ciphertext to decrypt entry."""
        pass

    def decrypt_message(self):
        """Placeholder for decryption."""
        pass

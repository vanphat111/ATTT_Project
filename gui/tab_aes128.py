import base64
import secrets
import tkinter as tk
from tkinter import ttk

from algorithms.aes128 import (
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    pkcs7_pad,
)


class TabAES128(ttk.Frame):
    """Tab 2: AES-128 Symmetric Encryption & Decryption (CBC Mode)."""

    REPORT_KEY = "6be3b21d232d57beb433d20736a4761b"
    REPORT_IV = "101112131415161718191a1b1c1d1e1f"
    REPORT_PLAINTEXT = "Hồ Văn Phát"

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._build_ui()
        self.load_report_params()

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

    def _set_entry_text(self, entry: ttk.Entry, text: str):
        """Helper to modify a readonly entry widget."""
        entry.config(state="normal")
        entry.delete(0, tk.END)
        entry.insert(0, text)
        entry.config(state="readonly")

    def set_key(self, hex_key: str):
        """Set key from external tab (e.g. Tab 1)."""
        self.entry_key.delete(0, tk.END)
        self.entry_key.insert(0, hex_key)
        self.validate_key()

    def load_report_params(self):
        """Load fixed benchmark/report parameters from Table 3.9."""
        self.entry_key.delete(0, tk.END)
        self.entry_key.insert(0, self.REPORT_KEY)

        self.entry_iv.delete(0, tk.END)
        self.entry_iv.insert(0, self.REPORT_IV)

        self.txt_plaintext_in.delete("1.0", tk.END)
        self.txt_plaintext_in.insert("1.0", self.REPORT_PLAINTEXT)

        self._set_entry_text(self.entry_padded_hex, "")
        self._set_entry_text(self.entry_ciphertext_hex, "")
        self._set_entry_text(self.entry_ciphertext_b64, "")

        self.entry_decrypt_in.delete(0, tk.END)
        self.txt_plaintext_out.config(state="normal")
        self.txt_plaintext_out.delete("1.0", tk.END)
        self.txt_plaintext_out.config(state="disabled")

        self.lbl_dec_status.config(text="STATUS: READY (REPORT PARAMETERS LOADED)", foreground="#007acc")
        self.app.set_status("Loaded report example parameters (Table 3.9).", "#0f172a")

    def validate_key(self):
        """Validate whether the current key is 16 bytes (32 hex characters)."""
        raw_key = self.entry_key.get().strip()
        try:
            k_bytes = bytes.fromhex(raw_key)
            if len(k_bytes) == 16:
                self.app.set_status("Key valid: exactly 16 bytes (128 bits).", "#16a34a")
                return True
            else:
                self.app.set_status(f"Invalid key length: {len(k_bytes)} bytes (must be 16 bytes / 32 hex chars).", "#dc2626")
                return False
        except ValueError:
            self.app.set_status("Invalid key: must be a valid hexadecimal string.", "#dc2626")
            return False

    def generate_random_iv(self):
        """Generate a cryptographically secure 16-byte random IV."""
        iv_hex = secrets.token_hex(16)
        self.entry_iv.delete(0, tk.END)
        self.entry_iv.insert(0, iv_hex)
        self.app.set_status("Generated new 16-byte random IV.", "#0f172a")

    def encrypt_message(self):
        """Encrypt plaintext using AES-128 in CBC mode."""
        key_hex = self.entry_key.get().strip()
        iv_hex = self.entry_iv.get().strip()

        try:
            key_bytes = bytes.fromhex(key_hex)
            if len(key_bytes) != 16:
                raise ValueError("Key must be 16 bytes (32 hex chars)")
        except ValueError as e:
            self.app.set_status(f"Key error: {e}", "#dc2626")
            return

        try:
            iv_bytes = bytes.fromhex(iv_hex)
            if len(iv_bytes) != 16:
                raise ValueError("IV must be 16 bytes (32 hex chars)")
        except ValueError as e:
            self.app.set_status(f"IV error: {e}", "#dc2626")
            return

        plaintext_str = self.txt_plaintext_in.get("1.0", tk.END).rstrip("\r\n")
        plaintext_bytes = plaintext_str.encode("utf-8")

        padded_bytes = pkcs7_pad(plaintext_bytes, 16)
        self._set_entry_text(self.entry_padded_hex, padded_bytes.hex())

        ciphertext_bytes = aes_cbc_encrypt(plaintext_bytes, key_bytes, iv_bytes)
        ct_hex = ciphertext_bytes.hex()
        ct_b64 = base64.b64encode(ciphertext_bytes).decode("ascii")

        self._set_entry_text(self.entry_ciphertext_hex, ct_hex)
        self._set_entry_text(self.entry_ciphertext_b64, ct_b64)

        self.app.set_status(f"Encryption completed: {len(ciphertext_bytes)} bytes ciphertext generated.", "#16a34a")

    def copy_to_decrypt(self):
        """Copy ciphertext from encryption panel to decryption panel."""
        ct_hex = self.entry_ciphertext_hex.get()
        if not ct_hex:
            self.app.set_status("No ciphertext to copy. Please encrypt first.", "#dc2626")
            return
        self.entry_decrypt_in.delete(0, tk.END)
        self.entry_decrypt_in.insert(0, ct_hex)
        self.app.set_status("Ciphertext copied to decryption panel.", "#0f172a")

    def decrypt_message(self):
        """Decrypt ciphertext using AES-128 in CBC mode."""
        key_hex = self.entry_key.get().strip()
        iv_hex = self.entry_iv.get().strip()
        ct_hex = self.entry_decrypt_in.get().strip()

        try:
            key_bytes = bytes.fromhex(key_hex)
            if len(key_bytes) != 16:
                raise ValueError("Key must be 16 bytes (32 hex chars)")
        except ValueError as e:
            self.lbl_dec_status.config(text=f"STATUS: KEY ERROR ({e})", foreground="#dc2626")
            self.app.set_status(f"Key error: {e}", "#dc2626")
            return

        try:
            iv_bytes = bytes.fromhex(iv_hex)
            if len(iv_bytes) != 16:
                raise ValueError("IV must be 16 bytes (32 hex chars)")
        except ValueError as e:
            self.lbl_dec_status.config(text=f"STATUS: IV ERROR ({e})", foreground="#dc2626")
            self.app.set_status(f"IV error: {e}", "#dc2626")
            return

        try:
            ct_bytes = bytes.fromhex(ct_hex)
            if len(ct_bytes) == 0 or len(ct_bytes) % 16 != 0:
                raise ValueError("Ciphertext must be a non-zero multiple of 16 bytes")
        except ValueError as e:
            self.lbl_dec_status.config(text=f"STATUS: CIPHERTEXT ERROR ({e})", foreground="#dc2626")
            self.app.set_status(f"Ciphertext error: {e}", "#dc2626")
            return

        try:
            decrypted_bytes = aes_cbc_decrypt(ct_bytes, key_bytes, iv_bytes)
            recovered_text = decrypted_bytes.decode("utf-8", errors="replace")

            self.txt_plaintext_out.config(state="normal")
            self.txt_plaintext_out.delete("1.0", tk.END)
            self.txt_plaintext_out.insert("1.0", recovered_text)
            self.txt_plaintext_out.config(state="disabled")

            self.lbl_dec_status.config(text="STATUS: DECRYPTION SUCCESS (VALID PKCS#7 PADDING)", foreground="#16a34a")
            self.app.set_status("AES-128 CBC Decryption succeeded.", "#16a34a")
        except Exception as e:
            self.txt_plaintext_out.config(state="normal")
            self.txt_plaintext_out.delete("1.0", tk.END)
            self.txt_plaintext_out.config(state="disabled")

            self.lbl_dec_status.config(text=f"STATUS: DECRYPTION FAILED ({e})", foreground="#dc2626")
            self.app.set_status(f"Decryption failed: {e}", "#dc2626")

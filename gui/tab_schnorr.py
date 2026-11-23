import re
import secrets
import tkinter as tk
from tkinter import ttk

from algorithms.ecc import CURVE_F17, Point
from algorithms.schnorr import (
    SchnorrSignature,
    derive_public_key,
    generate_keypair,
    compute_challenge,
    sign,
    verify,
)


class TabSchnorr(ttk.Frame):
    """Tab 3: Schnorr Digital Signature Scheme over Elliptic Curve F_17."""

    REPORT_D = 5
    REPORT_K = 7
    REPORT_MSG = "Schnorr signature example"

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._build_ui()
        self.load_report_params()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)

        # 1. Elliptic Curve Specification & Keypair Setup
        key_frame = ttk.LabelFrame(self, text=" 1. Elliptic Curve Domain Parameters & Keypair Setup ", padding=10)
        key_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        key_frame.columnconfigure(1, weight=1)

        # Fixed Research Curve Info from Chapter 4 & 5
        ttk.Label(key_frame, text="Elliptic Curve:").grid(row=0, column=0, sticky="w", padx=5, pady=4)
        lbl_curve_spec = ttk.Label(
            key_frame,
            text="E(F_17): y^2 = x^3 + 2x + 2 (mod 17) | Base Point G = (5, 1) | Subgroup Order n = 19",
            font=("Courier", 9, "bold"),
            foreground="#1e3a8a",
        )
        lbl_curve_spec.grid(row=0, column=1, sticky="w", padx=5, pady=4)

        btn_box_keys = ttk.Frame(key_frame)
        btn_box_keys.grid(row=0, column=2, padx=5, pady=4)

        self.btn_load_report_keys = ttk.Button(btn_box_keys, text="Load Report Keys (d=5)", command=self.load_report_params)
        self.btn_load_report_keys.pack(side="left", padx=3)

        self.btn_gen_keys = ttk.Button(btn_box_keys, text="Generate Random Keypair", command=self.generate_keypair)
        self.btn_gen_keys.pack(side="left", padx=3)

        ttk.Label(key_frame, text="Private Key (d in [1, 18]):").grid(row=1, column=0, sticky="w", padx=5, pady=3)
        self.entry_priv_key = ttk.Entry(key_frame, font=("Courier", 10))
        self.entry_priv_key.grid(row=1, column=1, sticky="ew", padx=5, pady=3)
        self.btn_derive_pub = ttk.Button(key_frame, text="Update Public Key", command=self.update_public_key)
        self.btn_derive_pub.grid(row=1, column=2, padx=5, pady=3)

        ttk.Label(key_frame, text="Public Key P = d*G:").grid(row=2, column=0, sticky="w", padx=5, pady=3)
        self.entry_pub_key = ttk.Entry(key_frame, font=("Courier", 10), state="readonly")
        self.entry_pub_key.grid(row=2, column=1, columnspan=2, sticky="ew", padx=5, pady=3)

        # 2. Signing Process Frame
        sign_frame = ttk.LabelFrame(self, text=" 2. Digital Signature Generation (Signing) ", padding=10)
        sign_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
        sign_frame.columnconfigure(1, weight=1)

        ttk.Label(sign_frame, text="Message to Sign:").grid(row=0, column=0, sticky="w", padx=5, pady=4)
        self.entry_sign_msg = ttk.Entry(sign_frame, font=("Courier", 10))
        self.entry_sign_msg.grid(row=0, column=1, sticky="ew", padx=5, pady=4)

        btn_box_sign = ttk.Frame(sign_frame)
        btn_box_sign.grid(row=0, column=2, padx=5, pady=4)

        self.btn_sign = ttk.Button(btn_box_sign, text="Sign (Deterministic k=7)", command=self.sign_report_example)
        self.btn_sign.pack(side="left", padx=3)

        self.btn_sign_rand = ttk.Button(btn_box_sign, text="Sign (Random Nonce)", command=self.sign_random)
        self.btn_sign_rand.pack(side="left", padx=3)

        ttk.Label(sign_frame, text="Per-signature Nonce (k):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.entry_nonce = ttk.Entry(sign_frame, font=("Courier", 9), state="readonly")
        self.entry_nonce.grid(row=1, column=1, columnspan=2, sticky="ew", padx=5, pady=2)

        ttk.Label(sign_frame, text="Commitment Point R = k*G:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.entry_r_point = ttk.Entry(sign_frame, font=("Courier", 9), state="readonly")
        self.entry_r_point.grid(row=2, column=1, columnspan=2, sticky="ew", padx=5, pady=2)

        ttk.Label(sign_frame, text="Challenge e = H(m || R) mod n:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.entry_challenge = ttk.Entry(sign_frame, font=("Courier", 9), state="readonly")
        self.entry_challenge.grid(row=3, column=1, columnspan=2, sticky="ew", padx=5, pady=2)

        ttk.Label(sign_frame, text="Response s = (k + e*d) mod n:").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        self.entry_response = ttk.Entry(sign_frame, font=("Courier", 9), state="readonly")
        self.entry_response.grid(row=4, column=1, columnspan=2, sticky="ew", padx=5, pady=2)

        ttk.Label(sign_frame, text="Signature sigma = (R, s):").grid(row=5, column=0, sticky="w", padx=5, pady=3)
        self.entry_sig_output = ttk.Entry(sign_frame, font=("Courier", 9, "bold"), state="readonly")
        self.entry_sig_output.grid(row=5, column=1, sticky="ew", padx=5, pady=3)

        self.btn_copy_sig = ttk.Button(sign_frame, text="Copy to Verify Panel", command=self.copy_to_verify)
        self.btn_copy_sig.grid(row=5, column=2, padx=5, pady=3)

        # 3. Verification & Tamper Testing Frame
        verify_frame = ttk.LabelFrame(self, text=" 3. Signature Verification & Tamper Resistance ", padding=10)
        verify_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(5, 10))
        verify_frame.columnconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)

        ttk.Label(verify_frame, text="Verify Message:").grid(row=0, column=0, sticky="w", padx=5, pady=3)
        self.entry_verify_msg = ttk.Entry(verify_frame, font=("Courier", 10))
        self.entry_verify_msg.grid(row=0, column=1, columnspan=2, sticky="ew", padx=5, pady=3)

        ttk.Label(verify_frame, text="Verify Signature (R, s):").grid(row=1, column=0, sticky="w", padx=5, pady=3)
        self.entry_verify_sig = ttk.Entry(verify_frame, font=("Courier", 10))
        self.entry_verify_sig.grid(row=1, column=1, columnspan=2, sticky="ew", padx=5, pady=3)

        action_box = ttk.Frame(verify_frame)
        action_box.grid(row=2, column=0, columnspan=3, sticky="ew", padx=5, pady=8)

        self.btn_verify = ttk.Button(action_box, text="Verify Signature", command=self.verify_signature)
        self.btn_verify.pack(side="left", padx=5)

        self.btn_tamper_msg = ttk.Button(action_box, text="Tamper Message (+1 char)", command=self.tamper_message)
        self.btn_tamper_msg.pack(side="left", padx=5)

        self.btn_tamper_sig = ttk.Button(action_box, text="Tamper Signature (+1 val)", command=self.tamper_signature)
        self.btn_tamper_sig.pack(side="left", padx=5)

        # Status badge (pure text, no icons)
        self.lbl_verify_status = ttk.Label(
            verify_frame,
            text="STATUS: READY",
            font=("Courier", 11, "bold"),
            foreground="#007acc",
        )
        self.lbl_verify_status.grid(row=3, column=0, columnspan=3, sticky="w", padx=10, pady=5)

    def _set_entry_text(self, entry: ttk.Entry, text: str):
        """Helper to modify a readonly entry widget."""
        entry.config(state="normal")
        entry.delete(0, tk.END)
        entry.insert(0, text)
        entry.config(state="readonly")

    def _parse_point(self, s: str) -> Point:
        """Parse point coordinates from string e.g. '(9, 16)'."""
        nums = re.findall(r"-?\d+", s)
        if len(nums) != 2:
            raise ValueError(f"Invalid point format '{s}', expected (x, y)")
        pt = Point(int(nums[0]), int(nums[1]))
        if not CURVE_F17.is_on_curve(pt):
            raise ValueError(f"Point {pt} is not on curve E(F_17)")
        return pt

    def _parse_signature(self, s: str) -> SchnorrSignature:
        """Parse Schnorr signature from string e.g. '((0, 6), 11)' or 'R=(0, 6), s=11'."""
        nums = re.findall(r"-?\d+", s)
        if len(nums) != 3:
            raise ValueError(f"Invalid signature format '{s}', expected ((x, y), s)")
        r_point = Point(int(nums[0]), int(nums[1]))
        s_val = int(nums[2])
        return SchnorrSignature(r_point, s_val)

    def load_report_params(self):
        """Load fixed report parameters from Section 5.8 (Table 5.2)."""
        self.entry_priv_key.delete(0, tk.END)
        self.entry_priv_key.insert(0, str(self.REPORT_D))

        pub_p = derive_public_key(self.REPORT_D, CURVE_F17)
        self._set_entry_text(self.entry_pub_key, str(pub_p))

        self.entry_sign_msg.delete(0, tk.END)
        self.entry_sign_msg.insert(0, self.REPORT_MSG)

        # Clear sign intermediate outputs
        self._set_entry_text(self.entry_nonce, "")
        self._set_entry_text(self.entry_r_point, "")
        self._set_entry_text(self.entry_challenge, "")
        self._set_entry_text(self.entry_response, "")
        self._set_entry_text(self.entry_sig_output, "")

        self.entry_verify_msg.delete(0, tk.END)
        self.entry_verify_sig.delete(0, tk.END)
        self.lbl_verify_status.config(text="STATUS: READY (REPORT PARAMETERS LOADED)", foreground="#007acc")
        self.app.set_status("Loaded Section 5.8 report parameters (d=5, P=(9,16)).", "#0f172a")

    def generate_keypair(self):
        """Generate a new random keypair on CURVE_F17."""
        d, pub_p = generate_keypair(CURVE_F17)
        self.entry_priv_key.delete(0, tk.END)
        self.entry_priv_key.insert(0, str(d))
        self._set_entry_text(self.entry_pub_key, str(pub_p))
        self.app.set_status(f"Generated new keypair: d={d}, P={pub_p}", "#0f172a")

    def update_public_key(self):
        """Update public key if user modifies the private key entry."""
        raw_d = self.entry_priv_key.get().strip()
        try:
            d = int(raw_d)
            if not (1 <= d < CURVE_F17.n):
                raise ValueError("Private key must satisfy 1 <= d < 19")
            pub_p = derive_public_key(d, CURVE_F17)
            self._set_entry_text(self.entry_pub_key, str(pub_p))
            self.app.set_status(f"Public key updated: P = {pub_p}", "#16a34a")
        except ValueError as e:
            self.app.set_status(f"Key error: {e}", "#dc2626")

    def _execute_signing(self, nonce: int):
        """Helper to compute Schnorr signature with given nonce and populate UI."""
        raw_d = self.entry_priv_key.get().strip()
        try:
            d = int(raw_d)
            if not (1 <= d < CURVE_F17.n):
                raise ValueError("Private key must satisfy 1 <= d < 19")
        except ValueError as e:
            self.app.set_status(f"Signing aborted: {e}", "#dc2626")
            return

        msg_str = self.entry_sign_msg.get()
        msg_bytes = msg_str.encode("utf-8")

        # Step 3: Commitment R = k*G
        r_point = CURVE_F17.scalar_mult(nonce, CURVE_F17.g)
        # Step 4: Challenge e = H(m || R) mod n
        e_val = compute_challenge(msg_bytes, r_point, CURVE_F17)
        # Step 5: Response s = (k + e*d) mod n
        s_val = (nonce + e_val * d) % CURVE_F17.n

        # Populate UI
        self._set_entry_text(self.entry_nonce, str(nonce))
        self._set_entry_text(self.entry_r_point, str(r_point))
        self._set_entry_text(self.entry_challenge, str(e_val))
        self._set_entry_text(self.entry_response, str(s_val))

        sig_str = f"({r_point}, {s_val})"
        self._set_entry_text(self.entry_sig_output, sig_str)
        self.app.set_status(f"Schnorr signature generated: R={r_point}, s={s_val}", "#16a34a")

    def sign_report_example(self):
        """Sign message using deterministic nonce k=7 from Section 5.8."""
        self._execute_signing(self.REPORT_K)

    def sign_random(self):
        """Sign message using a fresh cryptographically secure random nonce."""
        rand_k = secrets.randbelow(CURVE_F17.n - 1) + 1
        self._execute_signing(rand_k)

    def copy_to_verify(self):
        """Copy generated signature and message to the verification panel."""
        sig_str = self.entry_sig_output.get()
        if not sig_str:
            self.app.set_status("No signature to copy. Please sign first.", "#dc2626")
            return

        self.entry_verify_msg.delete(0, tk.END)
        self.entry_verify_msg.insert(0, self.entry_sign_msg.get())

        self.entry_verify_sig.delete(0, tk.END)
        self.entry_verify_sig.insert(0, sig_str)

        self.lbl_verify_status.config(text="STATUS: READY TO VERIFY", foreground="#007acc")
        self.app.set_status("Signature copied to verification panel.", "#0f172a")

    def verify_signature(self):
        """Verify the signature against the message and public key."""
        msg_str = self.entry_verify_msg.get()
        sig_raw = self.entry_verify_sig.get().strip()
        pub_raw = self.entry_pub_key.get().strip()

        try:
            public_key = self._parse_point(pub_raw)
        except ValueError as e:
            self.lbl_verify_status.config(text=f"STATUS: PUBLIC KEY ERROR ({e})", foreground="#dc2626")
            self.app.set_status(f"Public key error: {e}", "#dc2626")
            return

        try:
            signature = self._parse_signature(sig_raw)
        except ValueError as e:
            self.lbl_verify_status.config(text=f"STATUS: SIGNATURE PARSE ERROR ({e})", foreground="#dc2626")
            self.app.set_status(f"Signature parse error: {e}", "#dc2626")
            return

        is_valid = verify(msg_str, signature, public_key, CURVE_F17)

        if is_valid:
            self.lbl_verify_status.config(text="STATUS: VALID SIGNATURE", foreground="#16a34a")
            self.app.set_status("Signature verification PASSED: signature is mathematically valid.", "#16a34a")
        else:
            self.lbl_verify_status.config(text="STATUS: INVALID SIGNATURE (VERIFICATION FAILED)", foreground="#dc2626")
            self.app.set_status("Signature verification FAILED: signature does not match message or key.", "#dc2626")

    def tamper_message(self):
        """Modify one character of the message to demonstrate tamper detection."""
        current_msg = self.entry_verify_msg.get()
        if not current_msg:
            current_msg = "Test"
        tampered = current_msg + "!"
        self.entry_verify_msg.delete(0, tk.END)
        self.entry_verify_msg.insert(0, tampered)

        self.lbl_verify_status.config(text="STATUS: MESSAGE TAMPERED (CLICK VERIFY TO TEST)", foreground="#b45309")
        self.app.set_status("Message altered. Click 'Verify Signature' to verify rejection.", "#b45309")

    def tamper_signature(self):
        """Modify response scalar s of the signature to demonstrate forgery rejection."""
        sig_raw = self.entry_verify_sig.get().strip()
        try:
            sig = self._parse_signature(sig_raw)
            # Alter s modulo n
            altered_s = (sig.s + 1) % CURVE_F17.n
            tampered_sig_str = f"({sig.r}, {altered_s})"
            self.entry_verify_sig.delete(0, tk.END)
            self.entry_verify_sig.insert(0, tampered_sig_str)

            self.lbl_verify_status.config(text="STATUS: SIGNATURE TAMPERED (CLICK VERIFY TO TEST)", foreground="#b45309")
            self.app.set_status("Signature value altered. Click 'Verify Signature' to verify rejection.", "#b45309")
        except ValueError as e:
            self.app.set_status(f"Cannot tamper: {e}", "#dc2626")

import tkinter as tk
from tkinter import ttk


class TabSchnorr(ttk.Frame):
    """Tab 3: Schnorr Digital Signature Scheme over Elliptic Curve F_17."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._build_ui()

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
        self.entry_priv_key.insert(0, "5")
        self.entry_priv_key.grid(row=1, column=1, columnspan=2, sticky="ew", padx=5, pady=3)

        ttk.Label(key_frame, text="Public Key P = d*G:").grid(row=2, column=0, sticky="w", padx=5, pady=3)
        self.entry_pub_key = ttk.Entry(key_frame, font=("Courier", 10), state="readonly")
        self.entry_pub_key.grid(row=2, column=1, columnspan=2, sticky="ew", padx=5, pady=3)

        # 2. Signing Process Frame
        sign_frame = ttk.LabelFrame(self, text=" 2. Digital Signature Generation (Signing) ", padding=10)
        sign_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
        sign_frame.columnconfigure(1, weight=1)

        ttk.Label(sign_frame, text="Message to Sign:").grid(row=0, column=0, sticky="w", padx=5, pady=4)
        self.entry_sign_msg = ttk.Entry(sign_frame, font=("Courier", 10))
        self.entry_sign_msg.insert(0, "Schnorr signature example")
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
            font=("Courier", 12, "bold"),
            foreground="#007acc",
        )
        self.lbl_verify_status.grid(row=3, column=0, columnspan=3, sticky="w", padx=10, pady=5)

    def load_report_params(self):
        """Placeholder for loading report parameters."""
        pass

    def generate_keypair(self):
        """Placeholder for keypair generation."""
        pass

    def sign_report_example(self):
        """Placeholder for deterministic signing."""
        pass

    def sign_random(self):
        """Placeholder for random signing."""
        pass

    def copy_to_verify(self):
        """Placeholder for copying signature to verify entry."""
        pass

    def verify_signature(self):
        """Placeholder for verification."""
        pass

    def tamper_message(self):
        """Placeholder for tampering message."""
        pass

    def tamper_signature(self):
        """Placeholder for tampering signature."""
        pass

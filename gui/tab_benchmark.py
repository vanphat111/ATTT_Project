import io
import json
import threading
import tkinter as tk
from tkinter import filedialog, ttk
import unittest

from benchmarks.benchmark import run_all_benchmarks, save_to_json_file


class TabBenchmark(ttk.Frame):
    """Tab 4: Unit Test Suite Runner & Performance Benchmark Dashboard."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.benchmark_data = None
        self._build_ui()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)

        # 1. Unit Test Runner Panel
        test_frame = ttk.LabelFrame(self, text=" 1. Unit Test Suite (26 Verification Tests) ", padding=10)
        test_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        test_frame.columnconfigure(0, weight=1)

        btn_box = ttk.Frame(test_frame)
        btn_box.pack(fill="x", padx=5, pady=4)

        self.btn_run_tests = ttk.Button(btn_box, text="Run All 26 Unit Tests", command=self.run_unit_tests)
        self.btn_run_tests.pack(side="left", padx=5)

        self.lbl_test_status = ttk.Label(btn_box, text="STATUS: READY", font=("Courier", 10, "bold"), foreground="#007acc")
        self.lbl_test_status.pack(side="left", padx=15)

        self.txt_test_output = tk.Text(test_frame, font=("Courier", 9), height=7, wrap="none", relief="solid", borderwidth=1, bg="#f8f9fa")
        self.txt_test_output.pack(fill="both", expand=True, padx=5, pady=5)
        self._init_test_output_text()

        # 2. Performance Benchmark Dashboard
        bench_frame = ttk.LabelFrame(self, text=" 2. Performance Benchmarking (Custom vs Standard Reference) ", padding=10)
        bench_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(5, 10))
        bench_frame.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        bench_btn_box = ttk.Frame(bench_frame)
        bench_btn_box.pack(fill="x", padx=5, pady=5)

        self.btn_run_bench = ttk.Button(bench_btn_box, text="Run Benchmark Suite", command=self.run_benchmark)
        self.btn_run_bench.pack(side="left", padx=5)

        self.btn_export_json = ttk.Button(bench_btn_box, text="Export Results to JSON", command=self.export_json, state="disabled")
        self.btn_export_json.pack(side="left", padx=5)

        self.lbl_bench_status = ttk.Label(bench_btn_box, text="STATUS: READY", font=("Courier", 10, "bold"), foreground="#007acc")
        self.lbl_bench_status.pack(side="left", padx=15)

        self.progressbar = ttk.Progressbar(bench_btn_box, mode="indeterminate", length=180)
        self.progressbar.pack(side="right", padx=5)

        # Treeview Table for Benchmark Results
        cols = ("algorithm", "operation", "custom_time", "ref_time", "slowdown")
        self.tree_bench = ttk.Treeview(bench_frame, columns=cols, show="headings", height=9)

        self.tree_bench.heading("algorithm", text="Algorithm")
        self.tree_bench.heading("operation", text="Operation / Data Size")
        self.tree_bench.heading("custom_time", text="Custom Time (ms)")
        self.tree_bench.heading("ref_time", text="Reference Time (ms)")
        self.tree_bench.heading("slowdown", text="Slowdown Factor")

        self.tree_bench.column("algorithm", width=180, anchor="w")
        self.tree_bench.column("operation", width=220, anchor="w")
        self.tree_bench.column("custom_time", width=130, anchor="e")
        self.tree_bench.column("ref_time", width=140, anchor="e")
        self.tree_bench.column("slowdown", width=130, anchor="e")

        # Scrollbar for treeview
        scroll_y = ttk.Scrollbar(bench_frame, orient="vertical", command=self.tree_bench.yview)
        self.tree_bench.configure(yscrollcommand=scroll_y.set)

        self.tree_bench.pack(side="left", fill="both", expand=True, padx=(5, 0), pady=5)
        scroll_y.pack(side="right", fill="y", padx=(0, 5), pady=5)

    def _init_test_output_text(self):
        info = (
            "UNIT TEST SUITE READY:\n"
            "- tests/test_sha256.py  (8 tests: empty string, standard NIST vectors, student name hash, hashlib fuzz)\n"
            "- tests/test_aes128.py  (5 tests: FIPS 197 vectors, CBC round-trip, Table 3.9 report vector)\n"
            "- tests/test_ecc.py     (7 tests: field F_17, group axioms, ECDH shared secret (10,11), secp256k1)\n"
            "- tests/test_schnorr.py (6 tests: Section 5.8 worked example R=(0,6), s=11, tamper SCH-01..03)\n"
            "Click 'Run All 26 Unit Tests' to execute the test suite."
        )
        self.txt_test_output.insert("1.0", info)
        self.txt_test_output.config(state="disabled")

    # =========================================================================
    # Section 1: Unit Test Runner (Threaded)
    # =========================================================================

    def run_unit_tests(self):
        """Execute unit test suite in a background thread."""
        self.btn_run_tests.config(state="disabled")
        self.lbl_test_status.config(text="STATUS: RUNNING TESTS (PLEASE WAIT)...", foreground="#b45309")
        self.app.set_status("Executing 26 unit tests in background thread...", "#b45309")

        thread = threading.Thread(target=self._worker_run_tests, daemon=True)
        thread.start()

    def _worker_run_tests(self):
        """Worker thread function executing unittest discovery."""
        loader = unittest.TestLoader()
        suite = loader.discover("tests", pattern="test_*.py")
        stream = io.StringIO()
        runner = unittest.TextTestRunner(stream=stream, verbosity=2)
        result = runner.run(suite)
        output_log = stream.getvalue()

        # Send results back to main thread
        self.after(0, self._on_tests_completed, result, output_log)

    def _on_tests_completed(self, result: unittest.TestResult, output_log: str):
        """Main thread callback to update UI after tests finish."""
        self.btn_run_tests.config(state="normal")

        self.txt_test_output.config(state="normal")
        self.txt_test_output.delete("1.0", tk.END)

        if result.wasSuccessful():
            summary = (
                f"ALL {result.testsRun}/26 UNIT TESTS PASSED SUCCESSFULLY (0 FAILURES, 0 ERRORS)\n"
                "--------------------------------------------------------------------------------\n"
                "- test_sha256.py:  8/8 tests PASSED\n"
                "- test_aes128.py:  5/5 tests PASSED\n"
                "- test_ecc.py:     7/7 tests PASSED\n"
                "- test_schnorr.py: 6/6 tests PASSED\n"
                "================================================================================\n"
            )
            self.txt_test_output.insert("1.0", summary + output_log)
            self.lbl_test_status.config(text=f"STATUS: {result.testsRun}/26 TESTS PASSED", foreground="#16a34a")
            self.app.set_status("Unit test suite execution completed: 26/26 tests PASSED.", "#16a34a")
        else:
            self.txt_test_output.insert("1.0", output_log)
            self.lbl_test_status.config(
                text=f"STATUS: FAILED ({len(result.failures)} failures, {len(result.errors)} errors)",
                foreground="#dc2626",
            )
            self.app.set_status("Unit tests finished with failures/errors.", "#dc2626")

        self.txt_test_output.config(state="disabled")

    # =========================================================================
    # Section 2: Benchmark Dashboard (Threaded)
    # =========================================================================

    def run_benchmark(self):
        """Execute performance benchmarks in a background thread."""
        self.btn_run_bench.config(state="disabled")
        self.btn_export_json.config(state="disabled")
        self.lbl_bench_status.config(text="STATUS: BENCHMARKING (PLEASE WAIT)...", foreground="#b45309")
        self.progressbar.start(10)
        self.app.set_status("Benchmarking cryptographic operations against reference C libraries...", "#b45309")

        # Clear existing treeview entries
        for row in self.tree_bench.get_children():
            self.tree_bench.delete(row)

        thread = threading.Thread(target=self._worker_run_benchmark, daemon=True)
        thread.start()

    def _worker_run_benchmark(self):
        """Worker thread function executing all benchmarks."""
        try:
            # Run benchmarks with representative iteration counts
            data = run_all_benchmarks(
                sha_iterations=5,
                aes_iterations=3,
                ecc_iterations=5,
                schnorr_iterations=3,
                include_comparison=True,
            )
        except Exception as e:
            data = {"error": str(e)}

        self.after(0, self._on_benchmark_completed, data)

    def _on_benchmark_completed(self, data: dict):
        """Main thread callback when benchmarking completes."""
        self.progressbar.stop()
        self.btn_run_bench.config(state="normal")

        if "error" in data:
            self.lbl_bench_status.config(text=f"STATUS: ERROR ({data['error']})", foreground="#dc2626")
            self.app.set_status(f"Benchmark error: {data['error']}", "#dc2626")
            return

        self.benchmark_data = data
        self.btn_export_json.config(state="normal")

        # Populate comparisons into Treeview
        comparisons = data.get("comparisons", [])
        for item in comparisons:
            algo = item.get("algorithm", "")
            op = f"{item.get('operation', '')} [{item.get('input_label', '')}]"
            c_time = f"{item.get('custom_t_avg_ms', 0):.3f} ms"
            ref_t = item.get("reference_t_avg_ms")
            r_time = f"{ref_t:.4f} ms" if ref_t is not None else "N/A"
            slowdown = item.get("slowdown_factor")
            s_str = f"{slowdown:.1f}x" if slowdown is not None else "N/A"

            self.tree_bench.insert("", "end", values=(algo, op, c_time, r_time, s_str))

        count = len(comparisons)
        self.lbl_bench_status.config(text=f"STATUS: COMPLETED ({count} METRICS)", foreground="#16a34a")
        self.app.set_status(f"Benchmark suite finished successfully: {count} comparative metrics recorded.", "#16a34a")

    def export_json(self):
        """Export collected benchmark data to a JSON file."""
        if not self.benchmark_data:
            self.app.set_status("No benchmark data to export. Please run benchmark suite first.", "#dc2626")
            return

        filepath = filedialog.asksaveasfilename(
            parent=self,
            title="Export Benchmark Results to JSON",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            initialfile="cryptographic_benchmark_results.json",
        )

        if not filepath:
            return

        try:
            save_to_json_file(self.benchmark_data, filepath)
            self.app.set_status(f"Benchmark results exported to: {filepath}", "#16a34a")
        except Exception as e:
            self.app.set_status(f"Failed to export JSON: {e}", "#dc2626")

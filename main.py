import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cipher_core import combined_encrypt, combined_decrypt
import attack_tools
import efficiency_analysis
import threading

class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Combined Cipher Tool — Vigenere + Affine")
        self.geometry("1000x720")
        self.create_widgets()

    def create_widgets(self):
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # --- Tab 1: Encrypt / Decrypt ---
        tab1 = ttk.Frame(nb)
        nb.add(tab1, text="Encrypt / Decrypt")

        top = ttk.Frame(tab1, padding=6)
        top.pack(fill=tk.BOTH, expand=True)

        ttk.Label(top, text="Plaintext / Ciphertext:").pack(anchor=tk.W)
        self.input_text = tk.Text(top, height=12, wrap=tk.WORD)
        self.input_text.pack(fill=tk.X)

        key_row = ttk.Frame(top)
        key_row.pack(fill=tk.X, pady=(6,0))
        ttk.Label(key_row, text="Key (min 10 chars):").pack(side=tk.LEFT)
        self.key_var = tk.StringVar(value="THISISASAMPLEKEY")
        ttk.Entry(key_row, textvariable=self.key_var, width=40).pack(side=tk.LEFT, padx=6)
        self.keep_nonletters = tk.BooleanVar(value=False)
        ttk.Checkbutton(key_row, text="Keep non-letters", variable=self.keep_nonletters).pack(side=tk.LEFT, padx=8)

        btn_row = ttk.Frame(top)
        btn_row.pack(fill=tk.X, pady=8)
        ttk.Button(btn_row, text="Encrypt →", command=self.on_encrypt).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Decrypt ←", command=self.on_decrypt).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Load file...", command=self.on_load).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Save result...", command=self.on_save).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Clear", command=self.on_clear).pack(side=tk.RIGHT)

        ttk.Label(top, text="Result:").pack(anchor=tk.W)
        self.result_text = tk.Text(top, height=12, wrap=tk.WORD)
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # --- Tab 2: Attack tools ---
        tab2 = ttk.Frame(nb)
        nb.add(tab2, text="Attack / Analysis")

        atk_frame = ttk.Frame(tab2, padding=6)
        atk_frame.pack(fill=tk.BOTH, expand=True)

        # Ciphertext input
        ttk.Label(atk_frame, text="Ciphertext for analysis:").pack(anchor=tk.W)
        self.atk_cipher_text = tk.Text(atk_frame, height=6, wrap=tk.WORD)
        self.atk_cipher_text.pack(fill=tk.X, pady=(0, 10))

        # Attack methods frame
        methods_frame = ttk.LabelFrame(atk_frame, text="Attack Methods", padding=10)
        methods_frame.pack(fill=tk.X, pady=5)

        # Known plaintext attack
        kp_frame = ttk.Frame(methods_frame)
        kp_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(kp_frame, text="Known Plaintext Attack (Most Effective):").pack(anchor=tk.W)
        kp_input_frame = ttk.Frame(kp_frame)
        kp_input_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(kp_input_frame, text="Known plaintext:").pack(side=tk.LEFT)
        self.known_plain_entry = ttk.Entry(kp_input_frame, width=40)
        self.known_plain_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(kp_input_frame, text="Run Known-Plaintext Attack", 
                  command=self.run_known_plain).pack(side=tk.LEFT, padx=5)

        # Other attacks
        other_attacks_frame = ttk.Frame(methods_frame)
        other_attacks_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(other_attacks_frame, text="Frequency Analysis", 
                  command=self.run_freq_analysis).pack(side=tk.LEFT, padx=2)
        ttk.Button(other_attacks_frame, text="Brute Force Affine Only", 
                  command=self.run_brute_force_affine).pack(side=tk.LEFT, padx=2)
        ttk.Button(other_attacks_frame, text="Advanced Frequency Attack", 
                  command=self.run_break_combined).pack(side=tk.LEFT, padx=2)

        # Output
        ttk.Label(atk_frame, text="Attack Output:").pack(anchor=tk.W, pady=(10,0))
        self.atk_output = tk.Text(atk_frame, height=15, wrap=tk.WORD)
        self.atk_output.pack(fill=tk.BOTH, expand=True)

        # Progress bar
        self.progress = ttk.Progressbar(atk_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)

        # --- Tab 3: Efficiency tests ---
        tab3 = ttk.Frame(nb)
        nb.add(tab3, text="Efficiency")

        eff_frame = ttk.Frame(tab3, padding=6)
        eff_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(eff_frame, text="Performance tests compare Combined vs Vigenere alone.").pack(anchor=tk.W)
        eff_opts = ttk.Frame(eff_frame)
        eff_opts.pack(fill=tk.X, pady=6)

        ttk.Label(eff_opts, text="Key for tests:").pack(side=tk.LEFT)
        self.eff_key_var = tk.StringVar(value="THISISASAMPLEKEY")
        ttk.Entry(eff_opts, textvariable=self.eff_key_var, width=40).pack(side=tk.LEFT, padx=6)
        ttk.Button(eff_opts, text="Run Efficiency Tests", command=self.run_eff_tests).pack(side=tk.LEFT, padx=8)

        ttk.Label(eff_frame, text="Efficiency Output:").pack(anchor=tk.W, pady=(8,0))
        self.eff_output = tk.Text(eff_frame, height=18, wrap=tk.WORD)
        self.eff_output.pack(fill=tk.BOTH, expand=True)

    # ---- Tab 1 handlers ----
    def validate_key(self, key):
        if len(key) < 10:
            messagebox.showerror("Key Error", "Key must be at least 10 characters long.")
            return False
        return True

    def on_encrypt(self):
        text = self.input_text.get(1.0, tk.END).rstrip('\n')
        key = self.key_var.get()
        if not self.validate_key(key): return
        try:
            res = combined_encrypt(text, key, self.keep_nonletters.get())
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            return
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, res)

    def on_decrypt(self):
        text = self.input_text.get(1.0, tk.END).rstrip('\n')
        key = self.key_var.get()
        if not self.validate_key(key): return
        try:
            res = combined_decrypt(text, key, self.keep_nonletters.get())
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            return
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, res)

    def on_load(self):
        path = filedialog.askopenfilename(title="Open text file", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not path: return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror("Open file error", str(e))
            return
        self.input_text.delete(1.0, tk.END)
        self.input_text.insert(tk.END, data)

    def on_save(self):
        path = filedialog.asksaveasfilename(title="Save result", defaultextension='*.txt', filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not path: return
        try:
            data = self.result_text.get(1.0, tk.END)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(data)
        except Exception as e:
            messagebox.showerror("Save error", str(e))

    def on_clear(self):
        self.input_text.delete(1.0, tk.END)
        self.result_text.delete(1.0, tk.END)

    # ---- Tab 2 handlers ----
    def run_attack_in_thread(self, attack_function, *args):
        """Run attack in separate thread to avoid GUI freezing"""
        self.progress.start()
        self.atk_output.delete(1.0, tk.END)
        self.atk_output.insert(tk.END, "Running attack... Please wait...")
        
        def attack_wrapper():
            try:
                result = attack_function(*args)
                self.after(0, self.attack_complete, result)
            except Exception as e:
                self.after(0, self.attack_error, str(e))
        
        thread = threading.Thread(target=attack_wrapper)
        thread.daemon = True
        thread.start()

    def attack_complete(self, result):
        self.progress.stop()
        self.atk_output.delete(1.0, tk.END)
        self.atk_output.insert(tk.END, result)

    def attack_error(self, error_msg):
        self.progress.stop()
        self.atk_output.delete(1.0, tk.END)
        self.atk_output.insert(tk.END, f"Error during attack: {error_msg}")

    def run_freq_analysis(self):
        cipher = self.atk_cipher_text.get(1.0, tk.END).strip()
        if not cipher:
            messagebox.showinfo("Input required", "Please paste ciphertext into the field above.")
            return
        res = attack_tools.frequency_analysis(cipher)
        self.atk_output.delete(1.0, tk.END)
        self.atk_output.insert(tk.END, res)

    def run_known_plain(self):
        cipher = self.atk_cipher_text.get(1.0, tk.END).strip()
        known = self.known_plain_entry.get().strip()
        if not cipher:
            messagebox.showinfo("Input required", "Please provide ciphertext.")
            return
        if len(known) < 4:
            messagebox.showinfo("Input required", "Known plaintext should be at least 4 characters.")
            return
        
        self.run_attack_in_thread(attack_tools.known_plaintext_attack, cipher, known)

    def run_brute_force_affine(self):
        cipher = self.atk_cipher_text.get(1.0, tk.END).strip()
        if not cipher:
            messagebox.showinfo("Input required", "Please paste ciphertext into the field above.")
            return
        self.run_attack_in_thread(attack_tools.brute_force_affine_only, cipher)

    def run_break_combined(self):
        cipher = self.atk_cipher_text.get(1.0, tk.END).strip()
        if not cipher:
            messagebox.showinfo("Input required", "Please paste ciphertext into the field above.")
            return
        self.run_attack_in_thread(attack_tools.break_combined_frequency, cipher)

    # ---- Tab 3 handlers ----
    def run_eff_tests(self):
        key = self.eff_key_var.get()
        if not self.validate_key(key):
            return
        
        self.eff_output.delete(1.0, tk.END)
        self.eff_output.insert(tk.END, "Running efficiency tests...")
        self.update_idletasks()
        
        res = efficiency_analysis.run_efficiency_tests(key, sizes=(500, 2000, 5000))
        self.eff_output.delete(1.0, tk.END)
        self.eff_output.insert(tk.END, res)

if __name__ == "__main__":
    app = MainApp()
    app.mainloop()
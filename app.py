import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import hashlib
import requests
import secrets
import string


# ==========================================
# Password Checker Backend

# ==========================================
class PasswordChecker:
    def __init__(self):
        # Small built-in list of common passwords (you can load rockyou.txt later)
        self.common_passwords = {
            "123456", "password", "123456789", "12345678", "qwerty",
            "abc123", "password1", "admin", "iloveyou", "welcome",
            "monkey", "letmein", "football", "dragon", "sunshine", 
            "Thokozani", ""
        }

    def is_common_password(self, password: str):
        """Check if password is in a common list"""
        if password.lower() in self.common_passwords:
            return True, "This password is commonly used by many people."
        return False, "This password is not among the top common passwords."

    def check_password_strength(self, password: str):
        """Score password strength (0–100) with feedback."""
        score = 0
        feedback = []

        # Basic checks
        length = len(password)
        if length == 0:
            return False, "Please enter a password.", 0

        # Length scoring
        if length < 6:
            feedback.append("Too short! Use at least 8–12 characters.")
            score += 10
        elif 6 <= length < 8:
            feedback.append("Short password. Add more characters for better security.")
            score += 30
        elif 8 <= length < 12:
            feedback.append("Good length. Try to make it 12+ for stronger protection.")
            score += 50
        else:
            feedback.append("Great length! 👍")
            score += 70

        # Character variety
        if any(c.islower() for c in password):
            score += 10
        else:
            feedback.append("Add lowercase letters.")

        if any(c.isupper() for c in password):
            score += 10
        else:
            feedback.append("Add uppercase letters.")

        if any(c.isdigit() for c in password):
            score += 10
        else:
            feedback.append("Add digits (0–9).")

        if any(c in string.punctuation for c in password):
            score += 10
        else:
            feedback.append("Add special symbols (!, @, #, etc).")

        # Penalty for patterns
        lowers = password.lower()
        if any(x in lowers for x in ["password", "admin", "qwerty", "letmein", "iloveyou"]):
            score -= 20
            feedback.append("Avoid using common patterns or words.")

        score = max(0, min(score, 100))

        # Build feedback text
        feedback_text = "• " + "\n• ".join(feedback)
        is_strong = score >= 80

        return is_strong, feedback_text, score

    def generate_strong_password(self, length: int = 16):
        """Generate cryptographically strong password"""
        chars = string.ascii_letters + string.digits + string.punctuation
        while True:
            pwd = ''.join(secrets.choice(chars) for _ in range(length))
            if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in string.punctuation for c in pwd)):
                return pwd

    def check_password_breach(self, password: str):
        """
        Check if the password has been found in known data breaches
        using the Have I Been Pwned API (k-Anonymity method).
        """
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        try:
            res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
            if res.status_code != 200:
                return False, 0

            hashes = (line.split(":") for line in res.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return True, int(count)
            return False, 0
        except requests.RequestException:
            return False, 0


# ==========================================
# GUI
# ==========================================
class PasswordCheckerGUI:
    def __init__(self, root, password_checker: PasswordChecker):
        self.root = root
        self.checker = password_checker

        # Configure main window
        self.root.title("🔐 Common Password Detector")
        self.root.geometry("600x700")
        self.root.resizable(True, True)

        # Set CustomTkinter theme
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.create_widgets()

    def create_widgets(self):
        # Main container
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        title_label = ctk.CTkLabel(
            main_frame,
            text="Password Security Analyzer",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(pady=(0, 20))

        # Password entry
        entry_frame = ctk.CTkFrame(main_frame)
        entry_frame.pack(fill="x", pady=(0, 20))

        password_label = ctk.CTkLabel(
            entry_frame, text="Enter your password:",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        password_label.pack(anchor="w", pady=(10, 5))

        self.password_entry = ctk.CTkEntry(
            entry_frame, placeholder_text="Type your password here...",
            show="•", width=400, height=35
        )
        self.password_entry.pack(fill="x", pady=(0, 10))
        self.password_entry.bind("<KeyRelease>", self.on_password_change)

        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        show_password_cb = ctk.CTkCheckBox(
            entry_frame, text="Show password",
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        show_password_cb.pack(anchor="w", pady=(0, 10))

        # Buttons
        button_frame = ctk.CTkFrame(main_frame)
        button_frame.pack(fill="x", pady=(0, 20))

        check_btn = ctk.CTkButton(
            button_frame, text="Check Password Security",
            command=self.check_password,
            height=35, font=ctk.CTkFont(size=14, weight="bold")
        )
        check_btn.pack(side="left", padx=(0, 10))

        generate_btn = ctk.CTkButton(
            button_frame, text="Generate Strong Password",
            command=self.generate_password, height=35,
            fg_color="green", hover_color="dark green"
        )
        generate_btn.pack(side="left", padx=(0, 10))

        clear_btn = ctk.CTkButton(
            button_frame, text="Clear",
            command=self.clear_all, height=35,
            fg_color="gray", hover_color="dark gray"
        )
        clear_btn.pack(side="left")

        # Results frame
        results_frame = ctk.CTkFrame(main_frame)
        results_frame.pack(fill="both", expand=True)

        strength_label = ctk.CTkLabel(
            results_frame, text="Password Strength:",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        strength_label.pack(anchor="w", pady=(10, 5))

        self.strength_meter = ctk.CTkProgressBar(results_frame, height=20)
        self.strength_meter.pack(fill="x", pady=(0, 10))
        self.strength_meter.set(0)

        self.strength_text = ctk.CTkLabel(
            results_frame, text="Enter a password to check",
            font=ctk.CTkFont(size=14)
        )
        self.strength_text.pack(anchor="w", pady=(0, 10))

        # Feedback textbox
        feedback_label = ctk.CTkLabel(
            results_frame, text="Security Analysis:",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        feedback_label.pack(anchor="w", pady=(10, 5))

        self.feedback_text = ctk.CTkTextbox(
            results_frame, height=150,
            font=ctk.CTkFont(size=12)
        )
        self.feedback_text.pack(fill="both", expand=True, pady=(0, 10))

        # Breach check
        breach_frame = ctk.CTkFrame(main_frame)
        breach_frame.pack(fill="x", pady=(10, 0))

        breach_check_btn = ctk.CTkButton(
            breach_frame, text="Check Data Breaches",
            command=self.check_breaches, height=35
        )
        breach_check_btn.pack(side="left", padx=(0, 10))

        self.breach_result = ctk.CTkLabel(
            breach_frame,
            text="Check if your password appears in known data breaches",
            font=ctk.CTkFont(size=12)
        )
        self.breach_result.pack(side="left")

    # ----------------------------------
    # Functional methods
    # ----------------------------------
    def toggle_password_visibility(self):
        self.password_entry.configure(show="" if self.show_password_var.get() else "•")

    def on_password_change(self, event=None):
        password = self.password_entry.get()
        if len(password) > 0:
            self.check_password(real_time=True)

    def check_password(self, real_time=False):
        password = self.password_entry.get()

        if not password:
            if not real_time:
                messagebox.showwarning("Warning", "Please enter a password to check.")
            return

        is_strong, feedback, score = self.checker.check_password_strength(password)

        # Progress bar update
        self.strength_meter.set(score / 100)
        if score >= 80:
            self.strength_meter.configure(progress_color="green")
            strength_msg = "Strong Password ✓"
        elif score >= 60:
            self.strength_meter.configure(progress_color="orange")
            strength_msg = "Moderate Password"
        else:
            self.strength_meter.configure(progress_color="red")
            strength_msg = "Weak Password ✗"

        self.strength_text.configure(text=f"{strength_msg} (Score: {score}/100)")

        # Feedback text
        self.feedback_text.delete("1.0", tk.END)
        self.feedback_text.insert("1.0", feedback)

        # Common password warning
        is_common, msg = self.checker.is_common_password(password)
        if is_common:
            self.feedback_text.insert(tk.END, f"\n\n⚠️ SECURITY WARNING:\n{msg}")

    def generate_password(self):
        strong_password = self.checker.generate_strong_password()

        result = messagebox.askyesno(
            "Generated Strong Password",
            f"Generated password:\n\n{strong_password}\n\nWould you like to use this password?"
        )

        if result:
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, strong_password)
            self.show_password_var.set(True)
            self.toggle_password_visibility()
            self.check_password()

    def check_breaches(self):
        password = self.password_entry.get()

        if not password:
            messagebox.showwarning("Warning", "Please enter a password to check.")
            return

        self.breach_result.configure(text="Checking breaches...")
        self.root.update()

        breached, count = self.checker.check_password_breach(password)

        if breached:
            self.breach_result.configure(
                text=f"⚠️ Found in {count:,} data breaches!",
                text_color="red"
            )
            messagebox.showwarning(
                "Security Alert",
                f"This password was found in {count:,} known data breaches!\n"
                "It is unsafe to use this password."
            )
        else:
            self.breach_result.configure(
                text="✓ No known data breaches found.",
                text_color="green"
            )

    def clear_all(self):
        self.password_entry.delete(0, tk.END)
        self.strength_meter.set(0)
        self.strength_text.configure(text="Enter a password to check")
        self.feedback_text.delete("1.0", tk.END)
        self.breach_result.configure(
            text="Check if your password appears in known data breaches",
            text_color="white"
        )
        self.show_password_var.set(False)
        self.toggle_password_visibility()


# ==========================================
# Main
# ==========================================
if __name__ == "__main__":
    root = ctk.CTk()
    checker = PasswordChecker()
    app = PasswordCheckerGUI(root, checker)
    root.mainloop()

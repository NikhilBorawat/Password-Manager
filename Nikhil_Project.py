import tkinter as tk
from tkinter import ttk
import math
import re
import random
import string
import pandas as pd
from ttkbootstrap import Style

# Load the common passwords from a CSV file
def load_common_passwords():
    try:
        df = pd.read_csv('users.csv', header=None)
        return set(df[0].astype(str).str.strip().tolist())
    except FileNotFoundError:
        print("Error: common_passwords.csv not found. Please check the file path.")
        return set()

COMMON_PASSWORDS = load_common_passwords()

# Function to calculate entropy
def calculate_entropy(password):
    charset_size = 0
    if any(char.islower() for char in password):
        charset_size += 26
    if any(char.isupper() for char in password):
        charset_size += 26
    if any(char.isdigit() for char in password):
        charset_size += 10
    if any(char in "!@#$%^&*()-_=+[{]};:'\",<.>/?\\|`~" for char in password):
        charset_size += 32
    return len(password) * math.log2(charset_size) if charset_size > 0 else 0

# Function to check for keyboard patterns
def has_keyboard_pattern(password):
    keyboard_patterns = [r'1234', r'2345', r'3456', r'abcd', r'bcde']
    for pattern in keyboard_patterns:
        if re.search(pattern, password):
            return True
    return False

# Function to check password strength and give feedback
def check_password_strength(password):
    if password in COMMON_PASSWORDS:
        return "Weak", "This password is too common and easily guessable."

    entropy = calculate_entropy(password)
    feedback = []
    if len(password) < 8:
        feedback.append("Password should be at least 8 characters long.")
    if not any(char.isupper() for char in password):
        feedback.append("Add uppercase letters for more strength.")
    if not any(char.isdigit() for char in password):
        feedback.append("Include numbers for better security.")
    if not any(char in "!@#$%^&*()-_=+[{]};:'\",<.>/?\\|`~" for char in password):
        feedback.append("Include special characters for extra security.")
    if has_keyboard_pattern(password):
        feedback.append("Avoid sequential patterns like '1234' or 'abcd'.")

    if entropy < 28:
        return "Weak", "\n".join(feedback) if feedback else "Very low entropy. Password is weak."
    elif 28 <= entropy < 40:
        return "Medium", "\n".join(feedback) if feedback else "Moderate entropy. Consider improving it."
    else:
        return "Strong", "Good password! It's strong and has high entropy."

# Function to generate a strong password
def generate_strong_password(length=12):
    if length < 8:
        length = 8

    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special_chars = "!@#$%^&*()-_=+[{]};:'\",<.>/?\\|`~"

    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(special_chars)
    ]
    all_chars = lowercase + uppercase + digits + special_chars
    password += random.choices(all_chars, k=length - 4)

    random.shuffle(password)
    return ''.join(password)

# GUI functions
def check_password():
    password = entry.get()
    strength, suggestion = check_password_strength(password)
    result_label.config(text=f"Password Strength: {strength}", 
                        foreground=("green" if strength == "Strong" else "orange" if strength == "Medium" else "red"))
    suggestion_label.config(text=suggestion)

def generate_password():
    generated_password = generate_strong_password()
    entry.delete(0, tk.END)
    entry.insert(0, generated_password)
    check_password()

def toggle_password():
    if show_var.get():
        entry.config(show="")  # Show password
    else:
        entry.config(show="*")  # Hide password

# Enhanced GUI using ttkbootstrap
def run_gui():
    global root, entry, result_label, suggestion_label, show_var

    style = Style(theme="darkly")  # Using a modern dark theme
    root = style.master
    root.title("Password Strength Checker with Generator")
    root.geometry("600x450")
    root.resizable(False, False)

    main_frame = ttk.Frame(root, padding=20, relief="groove", style="TFrame")
    main_frame.pack(fill="both", expand=True, padx=15, pady=15)

    # Title Label with a custom font
    ttk.Label(main_frame, text="Password Strength Checker", font=("Helvetica", 18, "bold"), anchor="center", 
              foreground="cyan").grid(row=0, column=0, columnspan=2, pady=10)

    # Password Entry
    ttk.Label(main_frame, text="Enter Password:", font=("Helvetica", 12)).grid(row=1, column=0, sticky="w", pady=10)
    entry = ttk.Entry(main_frame, width=35, font=("Helvetica", 12), show="*")
    entry.grid(row=1, column=1, pady=10, padx=5)

    # Show Password Checkbox
    show_var = tk.BooleanVar()
    ttk.Checkbutton(main_frame, text="Show Password", variable=show_var, command=toggle_password).grid(row=2, column=1, sticky="w", pady=5)

    # Buttons
    ttk.Button(main_frame, text="Check Strength", command=check_password, style="TButton").grid(row=3, column=0, columnspan=2, pady=15)
    ttk.Button(main_frame, text="Generate Strong Password", command=generate_password, style="TButton").grid(row=4, column=0, columnspan=2, pady=5)

    # Result and Suggestions
    result_label = ttk.Label(main_frame, text="", font=("Helvetica", 14, "bold"), anchor="center")
    result_label.grid(row=5, column=0, columnspan=2, pady=10)

    suggestion_label = ttk.Label(main_frame, text="", font=("Helvetica", 11), wraplength=500, justify="left", foreground="light gray")
    suggestion_label.grid(row=6, column=0, columnspan=2, pady=10)

    root.mainloop()

# Run the GUI
run_gui()

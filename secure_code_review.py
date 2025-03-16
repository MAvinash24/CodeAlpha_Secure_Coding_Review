import re
import tkinter as tk
from tkinter import filedialog, scrolledtext, font

# Function to check for hardcoded credentials
def check_hardcoded_credentials(code):
    pattern = re.compile(r'password\s*=\s*[\"\'].*[\"\']', re.IGNORECASE)
    return pattern.findall(code)

# Function to check for SQL Injection
def check_sql_injection(code):
    sql_patterns = [
        r"SELECT .* FROM .* WHERE .*?['\"]\s*\+",
        r"EXEC\s*\(.*?['\"]\s*\+"  
    ]
    return any(re.search(pattern, code, re.IGNORECASE) for pattern in sql_patterns)

# Function to check for insecure functions
def check_insecure_functions(code):
    insecure_functions = ['eval', 'exec', 'system', 'popen', 'pickle.load', 'subprocess.Popen']
    for func in insecure_functions:
        if re.search(fr'\b{func}\b\s*\(', code):
            return func
    return None

# Function to check for weak encryption
def check_weak_encryption(code):
    weak_encryption_patterns = [r"DES.new", r"MD5\("]
    for pattern in weak_encryption_patterns:
        if re.search(pattern, code, re.IGNORECASE):
            return pattern
    return None

# Function to check improper error handling
def check_improper_error_handling(code):
    return "except:" in code

# Function to check unsafe file operations
def check_unsafe_file_operations(code):
    return bool(re.search(r"open\s*\(.*[\"\']w[\"\']", code))

# Secure recommendations
SECURE_RECOMMENDATIONS = {
    "Hardcoded Credentials": "❌ Use environment variables or a credential vault instead.",
    "SQL Injection": "❌ Use parameterized queries instead of string concatenation.",
    "Insecure Functions": "❌ Avoid `eval()`, `exec()`, or `system()`. Use safer alternatives.",
    "Weak Encryption": "❌ Use AES instead of DES/MD5.",
    "Improper Error Handling": "❌ Catch specific exceptions instead of a generic `except:` block.",
    "Unsafe File Operations": "❌ Validate file paths and avoid arbitrary file writes."
}

# Main function to perform secure code review
def secure_code_review(code):
    issues = []
    
    if check_hardcoded_credentials(code):
        issues.append(("🚨 Hardcoded Credentials", "Hardcoded credentials found.", SECURE_RECOMMENDATIONS["Hardcoded Credentials"]))
    
    if check_sql_injection(code):
        issues.append(("🚨 SQL Injection", "Potential SQL Injection vulnerability detected.", SECURE_RECOMMENDATIONS["SQL Injection"]))
    
    insecure_func = check_insecure_functions(code)
    if insecure_func:
        issues.append(("⚠️ Insecure Function", f"Usage of insecure function '{insecure_func}' detected.", SECURE_RECOMMENDATIONS["Insecure Functions"]))
    
    weak_crypto = check_weak_encryption(code)
    if weak_crypto:
        issues.append(("⚠️ Weak Encryption", f"Weak encryption detected: {weak_crypto}", SECURE_RECOMMENDATIONS["Weak Encryption"]))
    
    if check_improper_error_handling(code):
        issues.append(("⚠️ Improper Error Handling", "Generic `except:` detected.", SECURE_RECOMMENDATIONS["Improper Error Handling"]))
    
    if check_unsafe_file_operations(code):
        issues.append(("⚠️ Unsafe File Operation", "Potential unsafe file operation detected.", SECURE_RECOMMENDATIONS["Unsafe File Operations"]))
    
    return issues if issues else [("✅ No Issues Found", "Your code appears secure!", "✅ Keep following secure coding practices.")]

# Function to browse and load a file
def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("Python Files", "*.py")])
    if file_path:
        with open(file_path, "r") as file:
            source_code = file.read()
            review_results = secure_code_review(source_code)
            display_results(review_results, file_path)

# Function to display results in the output text box
def display_results(results, file_path):
    result_text.config(state=tk.NORMAL)
    result_text.delete("1.0", tk.END)
    
    result_text.insert(tk.END, f"📂 Scanning File: {file_path}\n\n", "header")
    
    for issue in results:
        issue_type, issue_description, recommendation = issue
        result_text.insert(tk.END, issue_type + "\n", "issue")
        result_text.insert(tk.END, issue_description + "\n", "desc")
        result_text.insert(tk.END, "💡 Fix: " + recommendation + "\n\n", "recommendation")

    result_text.config(state=tk.DISABLED)

# GUI setup
root = tk.Tk()
root.title("🔍 Secure Code Review Tool")
root.geometry("800x500")
root.configure(bg="#E8EAF6")  # Softer background color

# Custom Fonts
header_font = font.Font(family="Arial", size=16, weight="bold")
button_font = font.Font(family="Arial", size=12, weight="bold")
output_font = font.Font(family="Consolas", size=11)

# Title Label
title_label = tk.Label(root, text="🔍 Secure Code Review Tool", font=header_font, bg="#E8EAF6", fg="#1A237E")
title_label.pack(pady=10)

# Browse Button
browse_button = tk.Button(root, text="📂 Browse Python File", command=browse_file, font=button_font, bg="#3949AB", fg="white", padx=10, pady=5)
browse_button.pack(pady=10)

# Output Text Box (Scrollable)
result_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=90, height=20, font=output_font, bg="white", fg="#212121")
result_text.pack(pady=10, padx=10)
result_text.config(state=tk.DISABLED)

# Custom Text Tags
result_text.tag_config("header", foreground="#0D47A1", font=("Arial", 12, "bold"))
result_text.tag_config("issue", foreground="#D32F2F", font=("Arial", 12, "bold"))  # Dark red
result_text.tag_config("desc", foreground="#000000", font=("Consolas", 10))  # Black for normal text
result_text.tag_config("recommendation", foreground="#388E3C", font=("Consolas", 10, "italic"))  # Green for recommendations

# Run the GUI
root.mainloop()

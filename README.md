# CodeAlpha

# Secure Code Review Tool

## 📌 Overview
Secure Code Review Tool is a Python-based GUI application designed to analyze Python source code for potential security vulnerabilities. The tool scans for hardcoded credentials, SQL injection risks, insecure functions, weak encryption methods, improper error handling, and unsafe file operations. It provides recommendations to help developers write secure code.

## 🚀 Features
- ✅ Detects **hardcoded credentials**
- ✅ Identifies **SQL injection vulnerabilities**
- ✅ Flags **insecure functions** (e.g., `eval()`, `exec()`)
- ✅ Checks for **weak encryption methods** (e.g., `DES`, `MD5`)
- ✅ Warns against **improper error handling** (generic `except:` blocks)
- ✅ Detects **unsafe file operations** (e.g., writing files insecurely)
- ✅ User-friendly **GUI** built with Tkinter
- ✅ Provides **secure coding recommendations**

## 📂 Installation
### Prerequisites
Ensure you have **Python 3.x** installed on your system.

### Install Required Libraries
Run the following command to install dependencies:
```sh
pip install tk
```

## 🛠 Usage
1. To use this repository locally:

**Clone the repository**:
  ```sh
  git clone https://github.com/MAvinash24/CodeAlpha_Secure_Coding_Review.git
  ```

2.Navigate to the project folder
```sh
cd CodeAlpha_Secure_Coding_Review
```

3. **Run the tool**:
   ```sh
   python secure_code_review.py
   ```
4. Click **📂 Browse Python File** to select a script for analysis.

### Note:
For this, I included some test scripts in this repository. You can use them as test cases.

5. The tool scans the file and displays **security issues** with recommendations.

## 📜 Example Output
```
📂 Scanning File: example.py

🚨 Hardcoded Credentials
Hardcoded credentials found.
💡 Fix: ❌ Use environment variables or a credential vault instead.

⚠️ Insecure Function
Usage of insecure function 'eval' detected.
💡 Fix: ❌ Avoid `eval()`, `exec()`, or `system()`. Use safer alternatives.

✅ No Issues Found
Your code appears secure!
✅ Keep following secure coding practices.
```
---

## Screenshot of GUI

![image](https://github.com/user-attachments/assets/51aa3f53-02b7-4e55-98a3-723d0d4d08ab)

---

## 🔒 Secure Coding Recommendations
- **Use Environment Variables**: Avoid storing sensitive data in source code.
- **Parameterized Queries**: Prevent SQL injection by using parameterized queries.
- **Avoid `eval()` and `exec()`**: These functions can execute arbitrary code.
- **Use Strong Encryption**: Prefer AES over DES and SHA-256 over MD5.
- **Handle Exceptions Properly**: Avoid using generic `except:` blocks.
- **Validate File Operations**: Prevent unintended file modifications.

## 🏗 Future Enhancements
- 🔹 Add support for **additional insecure coding patterns**
- 🔹 Improve **UI/UX with more customization options**
- 🔹 Extend compatibility to **other programming languages**

## 📜 License
This project is licensed under the **MIT License**.

## 📬 Contact
For any queries, reach out via:
GitHub Issues: Open an issue for discussions or bug reports.

# Network Automation Web Console (AI + Multi-Device Edition)

A localized, single-purpose web application designed to streamline enterprise IT workflows by executing network automation checks against multiple devices. Built to serve as a self-contained HTML/JavaScript frontend powered by a Flask backend, this tool bypasses complex container or virtual environment setups. Dependencies are automatically managed, making it highly portable for network and server infrastructure administration.

## 🚀 Key Features

*   **Multi-Device Execution:** Run ICMP ping, TCP port verification, and SSH commands against one or many network devices simultaneously.
*   **Sequential or Parallel Processing:** Choose to run tasks across multiple workers or sequentially, complete with live log streaming to the browser. 
*   **Built-In Vendor Command Library:** Includes one-click autocomplete for common Cisco, Juniper, Arista, Aruba, and generic Linux commands.
*   **Advanced Config Mode:** Safely push configuration changes with support for before/after config diffs and true dry-run capabilities (specifically for Junos)[cite: 1].
*   **Optional AI Assistant:** Generate task-specific command suggestions or analyze execution output using OpenRouter, NVIDIA NIM, or a local Ollama instance[cite: 1]. AI integrations utilize the Python standard library, requiring no additional PIP packages[cite: 1].
*   **Local Persistence Layer:** Utilizes a local SQLite database (`automation_console.db`) to store device inventories, schedule recurring tasks, and maintain run histories[cite: 1].
*   **Credential Encryption:** Passwords and SSH keys are encrypted at rest using the `cryptography` package (Fernet/AES-128-CBC)[cite: 1].
*   **Zero-Friction Setup:** The script auto-installs missing dependencies (like Flask and Paramiko) on the first run, allowing instant use without manual package management[cite: 1].

## 🛠️ Architecture & Tech Stack

Developed by Fowroz, this application merges backend platform configuration with intuitive client-side interface design. 

*   **Backend:** Python 3, Flask[cite: 1].
*   **Frontend:** Vanilla HTML, CSS, and JavaScript (No Node.js or heavy frameworks required)[cite: 1].
*   **Networking:** Paramiko (for persistent interactive SSH shells, jump-host tunneling, and key-based auth)[cite: 1].
*   **Database:** SQLite3 (Local file-based storage)[cite: 1].

## 📦 How to Run

1. Clone the repository.
2. Ensure you have Python installed.
3. Install the Libraries (Netmiko,Paramiko,Flask)
4. Run the application:
   ```bash
   python app.py
   

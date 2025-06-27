# 🔐 PyPassVault

**PyPassVault** is a simple, secure, and offline password manager built with **Python** and **Tkinter**, featuring dark/light mode, encryption, and AppImage packaging for Linux.


---

## ✨ Features

- 🔐 AES encryption (via `cryptography.fernet`) for all saved passwords
- 💡 Light/Dark theme toggle
- 📋 Clipboard copy for quick password access
- 🎲 Random password generator (8–32 characters)
- 🧹 Delete individual saved entries
- 💻 Linux AppImage support for portable execution

---

## 📸 Screenshot

1. Dark Mode --

- a) Main Window:

![main(black)](https://github.com/user-attachments/assets/35a545c9-a9aa-4a08-9013-8d555839033a)


- b) Saved Passwords Window:

![save(black)](https://github.com/user-attachments/assets/0e80d21a-fc01-448d-9b9f-5c8193806963)


2. Light Mode -- 

- a) Main Window:

![main(white)](https://github.com/user-attachments/assets/b90f0eaa-acaa-4f89-8540-7bc985626f1c)


- b) Saved Passwords Window:

![save(white)](https://github.com/user-attachments/assets/4cb21a03-25fc-4f83-a62a-24c588044c9b)



---

## 🛠 Requirements

- Python 3.7+
- Tkinter (GUI)
- cryptography (for encryption)
- PyInstaller (for binary build)

Install with:
```bash
pip install cryptography
```

---

## 🚀 Installation
1. Windows:
   Download pypassvault from the latest release

2. Linux:
   Download PyPassVault-x86_64.AppImage from the latest release
   ```bash
    chmod +x PyPassVault-x86_64.AppImage
   ./PyPassVault-x86_64.AppImage
   ```
3. Via Python:
- Clone the repository
  ```bash
  git clone https://github.com/DevManoj96/PyPassVault.git
  cd PyPassVault
  ```
- Run the program
  ```bash
  python3 pypassvault.py
  ```


---


## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 👨‍💻 Contact

- Created by Manoj Meghwal.
- Feel free to open issues or submit pull requests.

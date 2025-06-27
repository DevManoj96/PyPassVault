import tkinter as tk
from tkinter import  Listbox, Menu, messagebox
from cryptography.fernet import Fernet
import json

import os
import random
import string

KEYFILE = ".secret.key"

if not os.path.exists(KEYFILE):
    key = Fernet.generate_key()
    with open(KEYFILE, "wb") as f:
        f.write(key)


FILENAME = ".passwords.json"
default_font = ("Segoe UI", 12)
heading_font = ("Segoe UI", 18, "bold")


class PyPassVault:
    def __init__(self, root):
        
        self.root = root
        self.root.title("--- PyPassVault ---")
        self.root.geometry('640x480')

        self.current_theme = "dark"

        self.light_theme = {
            "bg": "#f7f7f8",
            "fg": "#1c1c1e",
            "entry_bg": "#ffffff",
            "entry_fg": "#000000",
            "button_bg": "#d0d3d4",
            "button_fg": "#000000",
            "highlight": "#007aff"
        }

        self.dark_theme = {
            "bg": "#1e1e2e",
            "fg": "#f8f8f2",
            "entry_bg": "#2c2c3c",
            "entry_fg": "#ffffff",
            "button_bg": "#44475a",
            "button_fg": "#ffffff",
            "highlight": "#8be9fd"
        }

        

        self.menubar = tk.Menu(self.root)
        self.root.config(menu=self.menubar)

        self.filemenu = tk.Menu(self.menubar, tearoff=0)

        self.menubar.add_cascade(label="Options", menu=self.filemenu)

        self.filemenu.add_command(label="Saved Passwords", command=self.saved_passwords)
        self.filemenu.add_command(label="Toggle theme", command=self.toggle_theme)
        self.filemenu.add_command(label="About", command=self.show_about)

        self.top_heading = tk.Label(self.root, text="PyPassVault", font=heading_font)
        self.top_heading.pack(pady=10)

        self.label1 = tk.Label(self.root, text="Enter site here :", font=default_font)
        self.label1.pack()
        
        self.site_entry = tk.Entry(self.root, font=default_font, width=20)
        self.site_entry.pack(pady=5)

        self.label2 = tk.Label(self.root, text="Enter Email or Username here: ", font=default_font)
        self.label2.pack()

        self.username_entry = tk.Entry(self.root, font=default_font, width=20)
        self.username_entry.pack(pady=5)


        self.label3 = tk.Label(self.root, text="Enter password here: ", font=default_font)
        self.label3.pack()

        self.pass_entry = tk.Entry(self.root, font=default_font, width=20, show="*")
        self.pass_entry.pack(pady=5)

        self.add_btn = tk.Button(self.root, text="Add", command=self.add_password, font=default_font, width=20, height=2)
        self.add_btn.pack(pady=5)

        self.generate_btn = tk.Button(self.root, text="Generate", command=self.generate_password, font=default_font, width=20, height=2)
        self.generate_btn.pack(pady=5)
        
        self.exit_btn = tk.Button(self.root, text="Exit", command=self.root.quit, font=default_font, width=20, height=2)
        self.exit_btn.pack(pady=5)

        self.root.bind('<Return>', lambda event: self.add_password())
        self.root.bind('<Control-q>', lambda event: self.root.quit)        

        self.apply_theme()

    def load_key(self):
        return open(KEYFILE, "rb").read()

    def encrypt_data(self, data: dict) -> str:
        key = self.load_key()
        f = Fernet(key)
        json_str = json.dumps(data)
        return f.encrypt(json_str.encode()).decode()

    def decrypt_data(self, encrypted_str: str) -> dict:
        key = self.load_key()
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_str.encode()).decode()
        return json.loads(decrypted)


    def load_data(self):
        if os.path.exists(FILENAME):
            with open(FILENAME, "r") as file:
                return json.load(file)

        else:
            return {}

    def save_data(self, data):
        with open(FILENAME, "w") as file:
            json.dump(data, file, indent=4)

    def add_password(self):
        site = self.site_entry.get().strip()
        email_or_username = self.username_entry.get().strip()
        password = self.pass_entry.get().strip()

        if not email_or_username or not password or not site:
            messagebox.showerror("Error", "All fields are required!", parent=self.root)
            return

        data = self.load_data()
        entry = {"site": site, "email_or_username": email_or_username, "password": password}
        encrypted_entry = self.encrypt_data(entry)
        data[site] = encrypted_entry
        self.save_data(data)

        self.site_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.pass_entry.delete(0, tk.END)

        messagebox.showinfo("Saved", f"Password for {site} saved successfully!", parent=self.root)

    def delete_selected_pass(self):
        site = self.get_selected_site()

        if not site:
            messagebox.showwarning("Invalid", "Please select a valid password entry to delete.", parent=self.save_passwds_popup)
            return
        data = self.load_data()

        if site in data:
            confirm = messagebox.askyesno("Confirm Delete", f"Delete entry for '{site}'?", parent=self.save_passwds_popup)
            if confirm:
                del data[site]

                self.save_data(data)
                self.populate_listbox()
                messagebox.showinfo("Deleted", f"Entry for '{site}' deleted.", parent=self.save_passwds_popup)
        
        else:
            messagebox.showerror("Error", "Could not find entry in data.", parent=self.save_passwds_popup)       


    def populate_listbox(self):

        self.listbox.delete(0, tk.END)
        data = self.load_data()

        if not data:
            self.listbox.insert(tk.END, "No passwords saved yet.")
            self.copy_pass_btn.config(state='disabled')
            self.delete_pass_btn.config(state='disabled')
            return

        header = f"{'Site':<25} | {'Email/Username':<20} | {'Password'}"
        self.listbox.insert(tk.END, header)
        self.listbox.insert(tk.END, "-" * 80)

        self.save_passwds_popup.bind('<Delete>', lambda event: self.delete_selected_pass())

        for site, encrypted_str in data.items():
            try:
                entry = self.decrypt_data(encrypted_str)
            except:
                continue  

            username = entry.get("email_or_username", "N/A")
            password = entry.get("password", "N/A")

            line = f"{site:<25} | {username:<20} | {password}"
            self.listbox.insert(tk.END, line)

    def get_selected_site(self):
        selected = self.listbox.curselection()

        if not selected or selected[0] < 2:
            return None

        line = self.listbox.get(selected[0])
        site = line.split('|')[0].strip()

        return site


    def saved_passwords(self):
        self.save_passwds_popup = tk.Toplevel(self.root)
        self.save_passwds_popup.title("Saved Passwords")
        self.save_passwds_popup.geometry('750x600')
        self.save_passwds_popup.resizable(False, False)
        
        scrollbar = tk.Scrollbar(self.save_passwds_popup)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)


        self.listbox = tk.Listbox(self.save_passwds_popup, width=100, height=20, font=default_font, yscrollcommand=scrollbar.set)
        self.listbox.pack(pady=5)
        scrollbar.config(command=self.listbox.yview)

        self.copy_pass_btn = tk.Button(self.save_passwds_popup, text="Copy", command=self.copy_password, font=default_font, width=10, height=1)
        self.copy_pass_btn.pack(pady=5)

        self.delete_pass_btn = tk.Button(self.save_passwds_popup, text="Delete", command=self.delete_selected_pass, font=default_font, width=10, height=1)
        self.delete_pass_btn.pack(pady=5)


        self.done_btn = tk.Button(self.save_passwds_popup, text="Done", command=self.save_passwds_popup.destroy, font=default_font, width=10, height=1)
        self.done_btn.pack(pady=5)

        self.save_passwds_popup.bind('<Return>', lambda event: self.save_passwds_popup.destroy())

        

        self.populate_listbox()

        self.apply_theme_to_popup(self.save_passwds_popup, listbox_name="listbox")


    def generate_password(self):
        self.gen_pass_popup = tk.Toplevel(self.root)
        self.gen_pass_popup.title("Random Password")
        self.gen_pass_popup.geometry('320x150')
        
        

        length = random.randint(8, 32)
        letters = string.ascii_letters
        digits = string.digits
        punctuation = string.punctuation

        all_characters = letters + digits + punctuation

        password = ''.join(random.choice(all_characters) for i in range(length))

        def copy_pass_win():
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied successfully.", parent=self.gen_pass_popup)

        self.pass_label = tk.Label(self.gen_pass_popup, text=f"Random Password :\n{password}", font=default_font)
        self.pass_label.pack(pady=5)

        self.copy_btn = tk.Button(self.gen_pass_popup, text="Copy", command=copy_pass_win, font=default_font, width=10, height=1)
        self.copy_btn.pack(pady=5)

        self.win_done_btn = tk.Button(self.gen_pass_popup, text="Done", command=self.gen_pass_popup.destroy, font=default_font, width=10, height=1)
        self.win_done_btn.pack(pady=5)
        
        self.gen_pass_popup.bind('<Return>', lambda event: self.gen_pass_popup.destroy())

        self.apply_theme_to_popup(self.gen_pass_popup)

    def copy_password(self):
        site = self.get_selected_site()
        if not site:
            messagebox.showwarning("Invalid", "Please select a valid entry to copy password.", parent=self.save_passwds_popup)
            return

        data = self.load_data()

        if site in data:
            entry = self.decrypt_data(data[site])
            password = entry.get("password", "")

            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", f"Password for '{site}' copied to clipboard.", parent=self.save_passwds_popup)

        else:
            messagebox.showerror("Error", "Password not found in data.")

    def toggle_theme(self):
        self.current_theme = "dark" if self.current_theme == "light" else "light"
        self.apply_theme()

        if hasattr(self, "save_passwds_popup") and self.save_passwds_popup.winfo_exists():
            self.apply_theme_to_popup(self.save_passwds_popup, "listbox")

        if hasattr(self, "gen_pass_popup") and self.gen_pass_popup.winfo_exists():
            self.apply_theme_to_popup(self.gen_pass_popup)



    def apply_theme(self):
        

        theme = self.light_theme if self.current_theme == "light" else self.dark_theme

        self.root.configure(bg=theme["bg"])

        widgets = [self.top_heading, self.label1, self.label2, self.label3, self.site_entry, self.username_entry, self.pass_entry, self.add_btn, self.generate_btn, self.exit_btn]

        for widget in widgets:
            try:
                widget.configure(bg=theme["bg"], fg=theme["fg"])
            except:
                pass

        for entry in [self.site_entry, self.username_entry, self.pass_entry]:
            entry.configure(bg=theme["entry_bg"], fg=theme["entry_fg"], insertbackground=theme["entry_fg"])

        for btn in [self.add_btn, self.generate_btn, self.exit_btn]:
            btn.configure(bg=theme["button_bg"], fg=theme["button_fg"], activebackground=theme["highlight"])

        self.top_heading.configure(fg=theme["highlight"], font=heading_font)

    def apply_theme_to_popup(self, popup, listbox_name=None):
        theme = self.light_theme if self.current_theme == "light" else self.dark_theme
        popup.configure(bg=theme["bg"])


        for widget in popup.winfo_children():
            if isinstance(widget, tk.Label):
                widget.configure(bg=theme["bg"], fg=theme["fg"])

            elif isinstance(widget, tk.Button):
                widget.configure(bg=theme["button_bg"], fg=theme["button_fg"], activebackground=theme["highlight"])

            elif isinstance(widget, tk.Entry):
                widget.configure(bg=theme["entry_bg"], fg=theme["entry_fg"], insertbackground=theme["entry_fg"])
            
            elif isinstance(widget, tk.Listbox) and listbox_name == "listbox":
                widget.configure(bg=theme["entry_bg"], fg=theme["entry_fg"], selectbackground=theme["highlight"])
            
            elif isinstance(widget, tk.Scrollbar):
                continue

    def show_about(self):
        messagebox.showinfo("About PyPassVault", 
                        "PyPassVault v1.0\n\n"
                        "A simple offline password manager\n"
                        "Built with Python & Tkinter\n\n"
                        "Features:\n"
                        "• Store and manage passwords\n"
                        "• Generate random passwords\n"
                        "• Light/Dark theme support\n"
                        "• Copy passwords to clipboard\n\n"
                        "Keyboard Shortcuts:\n"
                        "• Enter - Add password / Close dialogs\n"
                        "• Delete - Delete selected password\n\n"
                        "© 2025 DevManoj96", 
                        parent=self.root)
    
        
if __name__ == '__main__':
    root = tk.Tk()
    app = PyPassVault(root)
    root.mainloop()

    
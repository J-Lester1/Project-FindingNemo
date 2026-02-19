import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import pandas as pd
import base64
import os
import random

# ---------------- CONFIGURATION ----------------
CSV_FILE = "Nemo's.Memory.csv"
KEY_FILE = "MemoryKey.txt"
MASTER_PASSWORD = "Nemoishere"

BG_COLOR = "#1e1e1e"       
SECONDARY_BG = "#2d2d2d"   
FG_COLOR = "#ffffff"       
ACCENT_BLUE = "#007acc"    
ACCENT_GREEN = "#28a745"   
ACCENT_RED = "#dc3545"     
HOVER_COLOR = "#444444"     

# ---------------- INITIALIZATION ----------------
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(b"nexus_vault_secure_key_2024") 

key = open(KEY_FILE, "rb").read()

# ---------------- ENCRYPTION ENGINE ----------------
def xor_data(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def shift_bytes(data, shift=3):
    return bytes([(b + shift) % 256 for b in data])

def unshift_bytes(data, shift=3):
    return bytes([(b - shift) % 256 for b in data])

def reverse_bytes(data):
    return data[::-1]

def encrypt_type(password, enc_type):
    data = password.encode('utf-8')
    if enc_type == 1: data = xor_data(data, key)
    elif enc_type == 2: data = reverse_bytes(xor_data(data, key))
    elif enc_type == 3: data = shift_bytes(xor_data(data, key))
    elif enc_type == 4: data = xor_data(xor_data(data, key), key[::-1])
    else: data = xor_data(data, key) 
    return base64.urlsafe_b64encode(data).decode('utf-8')

def decrypt_type(enc_text, enc_type):
    try:
        data = base64.urlsafe_b64decode(enc_text.encode('utf-8'))
        if enc_type == 1: data = xor_data(data, key)
        elif enc_type == 2: data = xor_data(reverse_bytes(data), key)
        elif enc_type == 3: data = xor_data(unshift_bytes(data), key) 
        elif enc_type == 4: data = xor_data(xor_data(data, key[::-1]), key)
        else: data = xor_data(data, key)
        return data.decode('utf-8')
    except Exception:
        return "DECRYPTION_ERROR: Likely wrong key or enc type."

# ---------------- DATA PERSISTENCE ----------------
def load_data():
    if os.path.exists(CSV_FILE):
        return pd.read_csv(CSV_FILE)
    return pd.DataFrame(columns=["name","url","username","password","encryption_type"])

def save_data(df):
    df.to_csv(CSV_FILE, index=False)

# ---------------- UI HELPERS ----------------
class HoverButton(tk.Button):
    def __init__(self, master, **kw):
        tk.Button.__init__(self, master=master, **kw)
        self.defaultBackground = self["background"]
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def on_enter(self, e):
        self['background'] = self['activebackground']

    def on_leave(self, e):
        self['background'] = self.defaultBackground

def create_button(master, text, command, bg_color, width=15):
    active_bg = HOVER_COLOR 
    if bg_color == ACCENT_BLUE: active_bg = "#3399ff"
    if bg_color == ACCENT_GREEN: active_bg = "#4cd964"
    if bg_color == ACCENT_RED: active_bg = "#ff6666"

    btn = HoverButton(master, text=text, command=command, bg=bg_color, fg="white", 
                      font=("Arial", 10, "bold"), width=width, pady=8, relief="flat",
                      activebackground=active_bg, activeforeground="white", cursor="hand2")
    return btn

# ---------------- GUI LOGIC ----------------
# ---------------- AUTHORIZATION ----------------
try:
    from face_auth import FaceAuthenticator
    FACE_AUTH_AVAILABLE = True
except ImportError:
    FACE_AUTH_AVAILABLE = False

def verify_identity(parent=None):
    """
    Verifies identity using Face Recognition (if available) or Master Password.
    Returns True if verified, False otherwise.
    """
    if FACE_AUTH_AVAILABLE:
        # Prompt user to choose method or auto-start face auth
        if messagebox.askyesno("Identity Verification", "Use Face Recognition?", parent=parent):
            authenticator = FaceAuthenticator()
            success, msg = authenticator.verify_user()
            if success:
                 return True
            else:
                messagebox.showerror("Authentication Failed", f"{msg}\nSwitching to password.", parent=parent)
    
    # Fallback to Password
    pw = simpledialog.askstring("Master Password", "Enter Master Password:", show="*", parent=parent)
    return pw == MASTER_PASSWORD

def refresh_table():
    try:
        for row in tree.get_children():
            tree.delete(row)
        df = load_data()
        search_val = search_var.get()
        query = "" if search_val == "Search accounts..." else search_val.lower()
        for i, r in df.iterrows():
            if query in str(r.get("name", "")).lower():
                tree.insert("", "end", iid=i, values=(r["name"], r["url"], r["username"], "EDIT ✏️", "DELETE 🗑️"))
    except NameError:
        pass

def on_search_focus_in(event):
    if search_entry.get() == "Search accounts...":
        search_entry.delete(0, tk.END)
        search_entry.config(fg="white")

def on_search_focus_out(event):
    if search_entry.get() == "":
        search_entry.insert(0, "Search accounts...")
        search_entry.config(fg="grey")

# ---------------- ACTIONS ----------------
def open_account_window(mode="add", index=None):
    # Hide main window
    root.withdraw()

    def restore_main_window():
        top.destroy()
        root.deiconify()

    def validate_number(char):
        if char.isdigit() and int(char) in [1,2,3,4]:
            # Simple check for single digit 1-4, but allows logic for entry
            return True
        if char == "": return True # Allow delete
        return char.isdigit() # Basic digit check for the entry field restrictions

    def randomize_enc():
        e_type.delete(0, tk.END)
        e_type.insert(0, str(random.randint(1, 4)))

    def save():
        try:
            df = load_data()
            etype_val = e_type.get()
            if not etype_val: etype_val = "1"
            etype = int(etype_val)
            
            enc_pass = encrypt_type(e_pass.get(), etype)
            new_row = {"name": e_name.get(), "url": e_url.get(), "username": e_user.get(), "password": enc_pass, "encryption_type": etype}
            
            if mode == "add":
                df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
            else:
                df.iloc[index] = new_row
            
            save_data(df)
            refresh_table()
            messagebox.showinfo("Success", "Account saved successfully!")
            restore_main_window()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")

    top = tk.Toplevel(root)
    top.title("Secure Entry" if mode == "add" else "Edit Entry")
    top.geometry("380x500")
    top.configure(bg=SECONDARY_BG, padx=20, pady=20)
    top.protocol("WM_DELETE_WINDOW", restore_main_window) # Handle X click
    
    lbl_cfg = {"bg": SECONDARY_BG, "fg": FG_COLOR, "font": ("Arial", 9, "bold")}
    
    tk.Label(top, text="ACCOUNT NAME", **lbl_cfg).pack(pady=(5,0))
    e_name = tk.Entry(top, width=30); e_name.pack(pady=5)
    
    tk.Label(top, text="URL", **lbl_cfg).pack(pady=(5,0))
    e_url = tk.Entry(top, width=30); e_url.pack(pady=5)
    
    tk.Label(top, text="USERNAME", **lbl_cfg).pack(pady=(5,0))
    e_user = tk.Entry(top, width=30); e_user.pack(pady=5)
    
    tk.Label(top, text="PASSWORD", **lbl_cfg).pack(pady=(5,0))
    e_pass = tk.Entry(top, show="*", width=30); e_pass.pack(pady=5)
    
    tk.Label(top, text="ENC TYPE (1-4)", **lbl_cfg).pack(pady=(5,0))
    
    # Frame for Enc Type and Random Button
    enc_frame = tk.Frame(top, bg=SECONDARY_BG)
    enc_frame.pack(pady=5)
    
    vcmd = (top.register(validate_number), '%S')
    e_type = tk.Entry(enc_frame, width=20, validate="key", validatecommand=vcmd)
    e_type.pack(side="left", padx=(0, 5))
    
    tk.Button(enc_frame, text="🎲", command=randomize_enc, bg=ACCENT_BLUE, fg="white", font=("Arial", 8), width=3, cursor="hand2").pack(side="left")

    if mode == "edit" and index is not None:
        df = load_data()
        row = df.iloc[index]
        e_name.insert(0, row["name"])
        e_url.insert(0, row["url"])
        e_user.insert(0, row["username"])
        try:
            pwd = decrypt_type(row["password"], int(row["encryption_type"]))
            e_pass.insert(0, pwd)
        except:
            pass 
        e_type.insert(0, str(row["encryption_type"]))
    else:
        e_type.insert(0, "1")

    # Buttons Frame
    action_frame = tk.Frame(top, bg=SECONDARY_BG)
    action_frame.pack(pady=20)

    create_button(action_frame, "SAVE", save, ACCENT_GREEN, width=12).pack(side="left", padx=5)
    create_button(action_frame, "CANCEL", restore_main_window, ACCENT_RED, width=12).pack(side="left", padx=5)

def decrypt_selected(index=None):
    if index is None:
        sel = tree.selection()
        if not sel:
            messagebox.showwarning("Selection", "Please select an account first.")
            return
        index = int(sel[0])

    if not verify_identity(parent=root):
        return
    try:
        df = load_data()
        row = df.iloc[index]
        pwd = decrypt_type(row["password"], int(row["encryption_type"]))
        
        if "DECRYPTION_ERROR" in pwd:
            messagebox.showerror("Error", "Could not decrypt. Data may be corrupted or encrypted with a different key.")
        else:
            root.clipboard_clear()
            root.clipboard_append(pwd)
            messagebox.showinfo("Nemo's PM", f"Password for {row['name']}:\n\nCopied to Clipboard!\n\n(Clipboard will clear in 30 seconds)")
            # Security: Auto clear clipboard
            root.after(30000, lambda: root.clipboard_clear())
    except Exception as e:
        messagebox.showerror("Error", f"System Error: {e}")

def delete_selected(index=None):
    if index is None:
        sel = tree.selection()
        if not sel: return
        index = int(sel[0])

    if not verify_identity(parent=root): return
    if messagebox.askyesno("Confirm", "Delete record permanently?"):
        df = load_data()
        df.drop(index, inplace=True)
        df.reset_index(drop=True, inplace=True)
        save_data(df)
        refresh_table()

def on_tree_click(event):
    region = tree.identify("region", event.x, event.y)
    if region == "cell":
        col = tree.identify_column(event.x)
        item_id = tree.identify_row(event.y)
        if not item_id: return
        
        index = int(item_id)
        
        if col == "#4": # Edit
            open_account_window(mode="edit", index=index)
        elif col == "#5": # Delete
            delete_selected(index)

def startup_login():
    root.withdraw()

    # Attempt Face Authentication First
    if FACE_AUTH_AVAILABLE:
        try:
            auth = FaceAuthenticator()
            success, msg = auth.verify_user()
            if success:
                root.deiconify()
                messagebox.showinfo("Welcome", f"Identity Verified!\n{msg}")
                return
            else:
                # If it failed because no owner is registered, tell the user
                if "No owner registered" in msg:
                    messagebox.showwarning("Setup Required", f"Face ID not ready: {msg}\nPlease run 'register_face.py' first.")
                else:
                    messagebox.showwarning("Authentication Failed", f"{msg}")
        except Exception as e:
            messagebox.showerror("Face ID Error", f"Could not start Face ID: {e}")
    else:
        # Debug message to see if the module was bundled
        # messagebox.showinfo("Debug", "Face authentication module not detected in this build.")
        pass

    login_win = tk.Toplevel(root)
    login_win.title("Security Check")
    login_win.geometry("400x300")
    login_win.configure(bg=BG_COLOR)
    login_win.protocol("WM_DELETE_WINDOW", lambda: root.destroy()) 
    
    # Center the login window
    screen_width = login_win.winfo_screenwidth()
    screen_height = login_win.winfo_screenheight()
    x = (screen_width/2) - (400/2)
    y = (screen_height/2) - (300/2)
    login_win.geometry('+%d+%d' % (x, y))

    tk.Label(login_win, text="LOCKED", font=("Impact", 30), fg=ACCENT_RED, bg=BG_COLOR).pack(pady=(40, 10))
    tk.Label(login_win, text="Enter Master Password", font=("Arial", 10), fg="grey", bg=BG_COLOR).pack(pady=(0, 10))

    e_pass = tk.Entry(login_win, show="•", font=("Arial", 14), width=25, justify="center", bg=SECONDARY_BG, fg="white", insertbackground="white", bd=0)
    e_pass.pack(ipady=5, pady=5)
    e_pass.focus()

    def check(event=None):
        if e_pass.get() == MASTER_PASSWORD:
            login_win.destroy()
            root.deiconify()
        else:
            e_pass.delete(0, tk.END)
            messagebox.showerror("Access Denied", "Incorrect Password.", parent=login_win)

    e_pass.bind("<Return>", check)
    
    create_button(login_win, "UNLOCK", check, ACCENT_BLUE, width=20).pack(pady=20)

# ---------------- MAIN UI SETUP ----------------
root = tk.Tk()
root.title("NEMO'S PASSWORD MANAGER")
root.geometry("900x700") 
root.configure(bg=BG_COLOR)

style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background=SECONDARY_BG, foreground=FG_COLOR, fieldbackground=SECONDARY_BG, rowheight=30)
style.configure("Treeview.Heading", background=BG_COLOR, foreground=FG_COLOR, font=("Arial", 10, "bold"))
style.map("Treeview", background=[('selected', ACCENT_BLUE)])

tk.Label(root, text="NEMO'S PASSWORD MANAGER", font=("Impact", 35), bg=BG_COLOR, fg=FG_COLOR).pack(pady=(20, 10))

search_var = tk.StringVar()
search_frame = tk.Frame(root, bg=BG_COLOR)
search_frame.pack(pady=10)

search_entry = tk.Entry(search_frame, textvariable=search_var, font=("Segoe UI", 12), width=68, fg="grey", bg=SECONDARY_BG, insertbackground="white", bd=0)
search_entry.insert(0, "Search accounts...")
search_entry.bind("<FocusIn>", on_search_focus_in)
search_entry.bind("<FocusOut>", on_search_focus_out)
search_entry.pack(ipady=8)

table_frame = tk.Frame(root, bg=BG_COLOR)
table_frame.pack(expand=True, fill="both", padx=20)

tree = ttk.Treeview(table_frame, columns=("Name","URL","Username", "Edit", "Delete"), show="headings", height=12)
tree.heading("Name", text="ACCOUNT")
tree.heading("URL", text="URL")
tree.heading("Username", text="USERNAME")
tree.heading("Edit", text="EDIT")
tree.heading("Delete", text="DELETE")

tree.column("Name", width=200, anchor="center")
tree.column("URL", width=250, anchor="center")
tree.column("Username", width=200, anchor="center")
tree.column("Edit", width=80, anchor="center")
tree.column("Delete", width=80, anchor="center")

tree_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=tree_scroll.set)
tree.pack(side="left", expand=True, fill="both")
tree_scroll.pack(side="right", fill="y")

tree.bind("<ButtonRelease-1>", on_tree_click)

btn_frame = tk.Frame(root, bg=BG_COLOR)
btn_frame.pack(pady=20) 

create_button(btn_frame, "+ ADD ACCOUNT", lambda: open_account_window(mode="add"), ACCENT_BLUE).pack(side="left", padx=10)
create_button(btn_frame, "🔑 VIEW / COPY", decrypt_selected, ACCENT_GREEN).pack(side="left", padx=10)

search_var.trace_add("write", lambda *args: refresh_table())

# Run initialization
root.after(100, lambda: refresh_table())
root.after(0, startup_login) # Schedule login after root is created
root.mainloop()
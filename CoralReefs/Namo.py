import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import pandas as pd
import base64
import os
import random

# ---------------- CONFIGURATION ----------------
CSV_FILE = "Nemo's.Memory.csv"
KEY_FILE = "MemoryKey.txt"
Marlins_Secret = "Nemoishere"

BG_COLOR = "#1e1e1e"       
SECONDARY_BG = "#2d2d2d"   
FG_COLOR = "#ffffff"       
ACCENT_BLUE = "#007acc"    
ACCENT_GREEN = "#28a745"   
ACCENT_RED = "#dc3545"     
HOVER_COLOR = "#444444"
FORM_BG = "#252525"

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

# ---------------- AUTHORIZATION ----------------
try:
    from face_auth import FaceAuthenticator
    FACE_AUTH_AVAILABLE = True
except ImportError:
    FACE_AUTH_AVAILABLE = False

def verify_identity(parent=None):
    """
    Verifies identity using Face Recognition (if available) or Marlin's Secret(master password).
    Returns True if verified, False otherwise.
    """
    if FACE_AUTH_AVAILABLE:
        if messagebox.askyesno("Identity Verification", "Use Face Recognition?", parent=parent):
            authenticator = FaceAuthenticator()
            success, msg = authenticator.verify_user()
            if success:
                 return True
            else:
                messagebox.showerror("Authentication Failed", f"{msg}\nSwitching to password.", parent=parent)
    
    # Fallback to Password
    pw = simpledialog.askstring("Master Password", "Enter Marlin's Secret:", show="*", parent=parent)
    return pw == Marlins_Secret

# ============================================================
#                    MAIN APPLICATION
# ============================================================
root = tk.Tk()
root.title("NEMO'S PASSWORD MANAGER")
root.configure(bg=BG_COLOR)

# ---------- FULL-SCREEN MODE ----------
root.attributes('-fullscreen', True)
is_fullscreen = True

def toggle_fullscreen(event=None):
    global is_fullscreen
    is_fullscreen = not is_fullscreen
    root.attributes('-fullscreen', is_fullscreen)

root.bind("<Escape>", toggle_fullscreen)
root.bind("<F11>", toggle_fullscreen)

# ---------- TREEVIEW STYLE ----------
style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background=SECONDARY_BG, foreground=FG_COLOR, fieldbackground=SECONDARY_BG, rowheight=35, font=("Segoe UI", 11))
style.configure("Treeview.Heading", background=BG_COLOR, foreground=FG_COLOR, font=("Segoe UI", 11, "bold"))
style.map("Treeview", background=[('selected', ACCENT_BLUE)])

# ============================================================
#                    PANEL SYSTEM
# ============================================================
panels = {}
current_panel = None

def show_panel(name):
    """Hide all panels, then show the requested one."""
    global current_panel
    for pname, panel in panels.items():
        panel.pack_forget()
    panels[name].pack(expand=True, fill="both")
    current_panel = name

# ---- Global form state ----
form_mode = "add"
form_index = None

# ============================================================
#    FORWARD-DECLARED FUNCTIONS (used by UI widgets below)
# ============================================================

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

def clear_form():
    """Clear all form entries."""
    e_name.delete(0, tk.END)
    e_url.delete(0, tk.END)
    e_user.delete(0, tk.END)
    e_pass.delete(0, tk.END)
    e_type.delete(0, tk.END)

def show_form_panel(mode="add", index=None):
    """Prepare and show the form panel."""
    global form_mode, form_index
    form_mode = mode
    form_index = index
    clear_form()
    
    if mode == "add":
        form_title_label.config(text="➕ ADD NEW ACCOUNT")
        e_type.insert(0, "1")
    elif mode == "edit" and index is not None:
        form_title_label.config(text="✏️ EDIT ACCOUNT")
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
    
    show_panel("form")

def save_form():
    global form_mode, form_index
    try:
        df = load_data()
        etype_val = e_type.get()
        if not etype_val: etype_val = "1"
        etype = int(etype_val)
        
        enc_pass = encrypt_type(e_pass.get(), etype)
        new_row = {"name": e_name.get(), "url": e_url.get(), "username": e_user.get(), "password": enc_pass, "encryption_type": etype}
        
        if form_mode == "add":
            df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
        else:
            df.iloc[form_index] = new_row
        
        save_data(df)
        refresh_table()
        messagebox.showinfo("Success", "Account saved successfully!")
        show_panel("main")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save: {e}")

def cancel_form():
    show_panel("main")

def decrypt_selected_main():
    """Decrypt and copy password for the selected row."""
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
        
        if col == "#4":  # Edit — requires identity verification
            if not verify_identity(parent=root):
                return
            show_form_panel(mode="edit", index=index)
        elif col == "#5":  # Delete
            delete_selected(index)

def login_check(event=None):
    if login_pass_entry.get() == Marlins_Secret:
        login_pass_entry.delete(0, tk.END)
        login_error_label.config(text="")
        show_panel("main")
        refresh_table()
    else:
        login_pass_entry.delete(0, tk.END)
        login_error_label.config(text="🐠 Swam the wrong way!")

def startup_login():
    """Handle startup: try Face Auth, then show login panel."""
    if FACE_AUTH_AVAILABLE:
        try:
            auth = FaceAuthenticator()
            success, msg = auth.verify_user()
            if success:
                messagebox.showinfo("Welcome", f"Identity Verified!\n{msg}\nJust keep swimming!")
                show_panel("main")
                refresh_table()
                return
            else:
                if "No owner registered" in msg:
                    messagebox.showwarning("Setup Required", f"Face ID not ready: {msg}\nPlease run 'register_face.py' first.")
                else:
                    messagebox.showwarning("Oops, Swam the wrong way!", f"{msg}")
        except Exception as e:
            messagebox.showerror("Face ID Error", f"Could not start Face ID: {e}")
    
    # Show login panel
    show_panel("login")
    login_pass_entry.focus_set()

# ============================================================
#               PANEL 1 — LOGIN SCREEN
# ============================================================
login_panel = tk.Frame(root, bg=BG_COLOR)
panels["login"] = login_panel

login_center = tk.Frame(login_panel, bg=BG_COLOR)
login_center.place(relx=0.5, rely=0.5, anchor="center")

tk.Label(login_center, text="🔒", font=("Segoe UI Emoji", 60), bg=BG_COLOR, fg=ACCENT_RED).pack(pady=(0, 5))
tk.Label(login_center, text="LOCKED", font=("Impact", 40), fg=ACCENT_RED, bg=BG_COLOR).pack(pady=(0, 5))
tk.Label(login_center, text="Enter Marlin's Secret", font=("Segoe UI", 12), fg="grey", bg=BG_COLOR).pack(pady=(0, 15))

login_pass_entry = tk.Entry(login_center, show="•", font=("Segoe UI", 16), width=30, justify="center",
                            bg=SECONDARY_BG, fg="white", insertbackground="white", bd=0)
login_pass_entry.pack(ipady=8, pady=5)

login_error_label = tk.Label(login_center, text="", font=("Segoe UI", 9), fg=ACCENT_RED, bg=BG_COLOR)
login_error_label.pack(pady=(2, 5))

login_pass_entry.bind("<Return>", login_check)
create_button(login_center, "UNLOCK", login_check, ACCENT_BLUE, width=25).pack(pady=20)

tk.Label(login_center, text="Press Escape to toggle fullscreen  •  F11 to toggle", font=("Segoe UI", 9), fg="#555555", bg=BG_COLOR).pack(pady=(20, 0))

# ============================================================
#              PANEL 2 — MAIN TABLE VIEW
# ============================================================
main_panel = tk.Frame(root, bg=BG_COLOR)
panels["main"] = main_panel

# Header
header_frame = tk.Frame(main_panel, bg=BG_COLOR)
header_frame.pack(fill="x", padx=40, pady=(30, 10))

tk.Label(header_frame, text="🐠 NEMO'S PASSWORD MANAGER", font=("Impact", 36), bg=BG_COLOR, fg=FG_COLOR).pack(side="left")
tk.Label(header_frame, text="[Esc] Toggle Fullscreen", font=("Segoe UI", 9), fg="#555555", bg=BG_COLOR).pack(side="right")

# Search bar
search_frame = tk.Frame(main_panel, bg=BG_COLOR)
search_frame.pack(fill="x", padx=40, pady=(5, 10))

search_var = tk.StringVar()
search_entry = tk.Entry(search_frame, textvariable=search_var, font=("Segoe UI", 13), fg="grey",
                        bg=SECONDARY_BG, insertbackground="white", bd=0)
search_entry.insert(0, "Search accounts...")
search_entry.pack(fill="x", ipady=10)

def on_search_focus_in(event):
    if search_entry.get() == "Search accounts...":
        search_entry.delete(0, tk.END)
        search_entry.config(fg="white")

def on_search_focus_out(event):
    if search_entry.get() == "":
        search_entry.insert(0, "Search accounts...")
        search_entry.config(fg="grey")

search_entry.bind("<FocusIn>", on_search_focus_in)
search_entry.bind("<FocusOut>", on_search_focus_out)

# Table
table_frame = tk.Frame(main_panel, bg=BG_COLOR)
table_frame.pack(expand=True, fill="both", padx=40, pady=(0, 10))

tree = ttk.Treeview(table_frame, columns=("Name","URL","Username", "Edit", "Delete"), show="headings")
tree.heading("Name", text="ACCOUNT")
tree.heading("URL", text="URL")
tree.heading("Username", text="USERNAME")
tree.heading("Edit", text="EDIT")
tree.heading("Delete", text="DELETE")

tree.column("Name", width=250, anchor="center", stretch=True)
tree.column("URL", width=300, anchor="center", stretch=True)
tree.column("Username", width=250, anchor="center", stretch=True)
tree.column("Edit", width=100, anchor="center", stretch=False)
tree.column("Delete", width=100, anchor="center", stretch=False)

tree_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=tree_scroll.set)
tree.pack(side="left", expand=True, fill="both")
tree_scroll.pack(side="right", fill="y")

tree.bind("<ButtonRelease-1>", on_tree_click)

# Bottom buttons
btn_frame = tk.Frame(main_panel, bg=BG_COLOR)
btn_frame.pack(pady=(10, 30))

create_button(btn_frame, "+ ADD ACCOUNT", lambda: show_form_panel(mode="add"), ACCENT_BLUE, width=20).pack(side="left", padx=10)
create_button(btn_frame, "🔑 VIEW / COPY", decrypt_selected_main, ACCENT_GREEN, width=20).pack(side="left", padx=10)

# ============================================================
#              PANEL 3 — ADD / EDIT FORM
# ============================================================
form_panel = tk.Frame(root, bg=BG_COLOR)
panels["form"] = form_panel

form_center = tk.Frame(form_panel, bg=FORM_BG, padx=40, pady=30)
form_center.place(relx=0.5, rely=0.5, anchor="center")

form_title_label = tk.Label(form_center, text="ADD NEW ACCOUNT", font=("Impact", 28), bg=FORM_BG, fg=FG_COLOR)
form_title_label.pack(pady=(0, 20))

lbl_cfg = {"bg": FORM_BG, "fg": "#aaaaaa", "font": ("Segoe UI", 10, "bold")}
entry_cfg = {"font": ("Segoe UI", 13), "bg": SECONDARY_BG, "fg": "white", "insertbackground": "white", "bd": 0, "width": 40}

tk.Label(form_center, text="ACCOUNT NAME", **lbl_cfg).pack(anchor="w", pady=(5, 0))
e_name = tk.Entry(form_center, **entry_cfg)
e_name.pack(fill="x", ipady=7, pady=(2, 8))

tk.Label(form_center, text="URL", **lbl_cfg).pack(anchor="w", pady=(5, 0))
e_url = tk.Entry(form_center, **entry_cfg)
e_url.pack(fill="x", ipady=7, pady=(2, 8))

tk.Label(form_center, text="USERNAME", **lbl_cfg).pack(anchor="w", pady=(5, 0))
e_user = tk.Entry(form_center, **entry_cfg)
e_user.pack(fill="x", ipady=7, pady=(2, 8))

tk.Label(form_center, text="PASSWORD", **lbl_cfg).pack(anchor="w", pady=(5, 0))
e_pass = tk.Entry(form_center, show="*", **entry_cfg)
e_pass.pack(fill="x", ipady=7, pady=(2, 8))

tk.Label(form_center, text="ENCRYPTION TYPE (1-4)", **lbl_cfg).pack(anchor="w", pady=(5, 0))

enc_frame = tk.Frame(form_center, bg=FORM_BG)
enc_frame.pack(fill="x", pady=(2, 15))

def validate_number(char):
    if char.isdigit() and int(char) in [1,2,3,4]:
        return True
    if char == "": return True
    return char.isdigit()

def randomize_enc():
    e_type.delete(0, tk.END)
    e_type.insert(0, str(random.randint(1, 4)))

vcmd = (root.register(validate_number), '%S')
e_type = tk.Entry(enc_frame, validate="key", validatecommand=vcmd, font=("Segoe UI", 13),
                  bg=SECONDARY_BG, fg="white", insertbackground="white", bd=0, width=10)
e_type.pack(side="left", ipady=7, padx=(0, 8))

tk.Button(enc_frame, text="🎲 Random", command=randomize_enc, bg=ACCENT_BLUE, fg="white",
          font=("Segoe UI", 10, "bold"), width=10, cursor="hand2", relief="flat").pack(side="left")

# Form action buttons
form_btn_frame = tk.Frame(form_center, bg=FORM_BG)
form_btn_frame.pack(pady=(10, 0))

create_button(form_btn_frame, "💾 SAVE", save_form, ACCENT_GREEN, width=15).pack(side="left", padx=8)
create_button(form_btn_frame, "✖ CANCEL", cancel_form, ACCENT_RED, width=15).pack(side="left", padx=8)

# ============================================================
#                     STARTUP
# ============================================================
search_var.trace_add("write", lambda *args: refresh_table())

root.after(100, startup_login)
root.mainloop()
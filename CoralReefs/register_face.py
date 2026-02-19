
from face_auth import FaceAuthenticator
import tkinter as tk
from tkinter import messagebox

def start_registration():
    try:
        authenticator = FaceAuthenticator()
        success, message = authenticator.register_owner()
        
        root = tk.Tk()
        root.withdraw() # Hide main window
        
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Registration Failed", message)
            
        root.destroy()
    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to close...")

if __name__ == "__main__":
    start_registration()

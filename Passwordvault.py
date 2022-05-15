from tkinter import messagebox

# Sign out of password vault
def signOut(screen):
    if messagebox.askyesno("Sign out confirmation", "Are you sure you want to sign out?"):
        screen()

# Additional Information
def infor():
    messagebox.showinfo("Copy entries",
                        "You can copy values from you password vault to your clipboard by clicking on them.")
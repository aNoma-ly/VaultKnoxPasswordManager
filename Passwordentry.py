from tkinter import messagebox
from Encryption import encrypt


# Password entry class
class PasswordEntry:
    # Init Password entry object
    def __init__(self, service, username, password, date, key):
        self.service = service
        self.username = username
        self.password = password
        self.date = date
        self.encservice = ""
        self.encusername = ""
        self.encpassword = ""
        self.encdate = ""
        # Validation and remediation of password entry object
        if self.service == "":
            messagebox.showerror("No service name", "Please enter a valid service name.")
            return
        elif len(self.service) > 64:
            messagebox.showerror("Service name too long",
                                 "The service name is too long, please enter a valid service name.")
            return
        elif self.username == "":
            messagebox.showerror("No username", "Please enter a valid username.")
            return
        elif len(self.username) > 64:
            messagebox.showerror("Username too long",
                                 "Your username is too long, please enter a valid username.")
            return
        elif self.password == "":
            messagebox.showerror("No password", "Please enter a valid password.")
            return
        elif len(self.password) > 64:
            messagebox.showerror("Password too long",
                                 "The password is too long, please enter a valid password.")
            return
        else:
            # Password entries encrypted for storage in database
            self.encservice = encrypt(self.service.encode(), key)
            self.encusername = encrypt(self.username.encode(), key)
            self.encpassword = encrypt(self.password.encode(), key)
            self.encdate = encrypt(self.date.encode(), key)


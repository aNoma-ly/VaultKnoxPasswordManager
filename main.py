# Imports
import os
import time
import sqlite3
import sys
import uuid
import pyperclip
import base64
import threading
import requests
from datetime import datetime, timedelta

from tkinter import messagebox, simpledialog
from random import randint
from tkinter import *
from functools import partial
from cryptography.hazmat.primitives import hashes
from KDF import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from PIL import Image, ImageTk
from zxcvbn import zxcvbn
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager


from Encryption import decrypt, encrypt
from Inactivity import active
from Hashing import hashPassword
from Quit import on_closing
from Passwordvault import signOut, infor
from Masterpassword import MasterPassword
from Passwordentry import PasswordEntry
from Settings import UserSettings
from IP import IPDetails
from Bruteforce import bruteforceCheck


# Init main
def main():
    # Init GUI

    window = Tk()
    window.title("VaultKnox")

    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    app_width = 600
    app_height = 590
    x = (screen_width / 2) - (app_width / 2)
    y = (screen_height / 2) - (app_height / 2)
    window.geometry(f'{app_width}x{app_height}+{int(x)}+{int(y)}')

    frame = Frame(window)
    frame.pack()

    def resource_path0(relative_path):

        base_path = getattr(
            sys,
            '_MEIPASS',
            os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_path, relative_path)

    canvas = Canvas(window, width=600, height=590)
    canvas.pack()
    path = resource_path0("vaultKnox.png")
    img = ImageTk.PhotoImage(Image.open(path))
    canvas.create_image(0, 0, anchor=NW, image=img)

    def initIPObj():
        global ipdetails
        ipdetails = IPDetails()

    initThread = threading.Thread(name='initThread', target=initIPObj,
                         daemon=True)
    initThread.start()

    # Init key derivation function

    backend = default_backend()
    salt = b'2444'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )

    encryptionKey = 0

    # Init Sqlite3 database

    with sqlite3.connect("vaultKnox_passwords.db") as db:
        cursor = db.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS masterpassword(
    id INTEGER PRIMARY KEY,
    password TEXT NOT NULL,
    recoveryKey TEXT NOT NULL);
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS passwordVault(
    id INTEGER PRIMARY KEY,
    service TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    date TIMESTAMP NOT NULL,
    use INTEGER NOT NULL);
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usersettings(
    id INTEGER PRIMARY KEY,
    timeframe INTEGER NOT NULL,
    inactivity INTEGER NOT NULL,
    IP TEXT);
    """)

    # Inactivity thread
    cursor.execute("SELECT * FROM userSettings")
    settings = cursor.fetchall()

    if settings == []:
        userSettings = UserSettings(1, 300)
        cursor.execute("INSERT INTO usersettings(timeframe, inactivity) VALUES (?, ?)", (1, 5))
        db.commit()

    else:
        userSettings = UserSettings(settings[0][1], settings[0][2])

    b = threading.Thread(name='background', target=partial(active, window, userSettings.inactivity),
                         daemon=True)
    b.start()

    window.protocol("WM_DELETE_WINDOW", partial(on_closing, window))

    # First load
    def firstScreen():
        for widget in window.winfo_children():
            widget.destroy()

        topframe = Frame(window)
        topframe.pack(side=TOP)

        app_width = int(screen_width / 2)
        app_height = int(screen_height)
        xCor = (screen_width / 2) - (app_width / 2)
        yCor = (screen_height / 2) - (app_height / 2)
        window.geometry(f'{app_width}x{app_height}+{int(xCor)}+{int(yCor)}')

        window.title("Create your master password")

        lbl = Label(topframe, text="Enter your master password")
        lbl.config(anchor=CENTER)
        lbl.pack()

        txt = Entry(topframe, width=20)
        txt.focus()
        txt.pack(side=LEFT)

        global userpw
        userpw = txt.get()

        # Hide/show master password

        def hideT():
            txt.config(show="*")
            txt1.config(show="*")

        def showT():
            txt.config(show="")
            txt1.config(show="")

        def checkT():
            global x
            x += 1
            if x % 2 == 1:
                btn3['text'] = "Show"
                hideT()
            else:
                btn3['text'] = "Hide"
                showT()

        global x
        x = 0
        btn3 = Button(topframe, text="Hide", command=checkT)
        btn3.pack(side=RIGHT)

        lbl = Label(window, text="Repeat your master password")
        lbl.config(anchor=CENTER)
        lbl.pack()

        txt1 = Entry(window, width=20)
        txt1.pack()

        # Validation of registered master password

        def checkMasterPW():
            passing = True
            for widget in window.winfo_children():
                if isinstance(widget, Label):
                    if passing:
                        passing = False
                    else:
                        widget.destroy()
            if txt.get() == txt1.get():

                entPW = MasterPassword(txt.get(), [])

                # Password remediation zxcvbn package

                if len(entPW.WASP) == 0:
                    results = zxcvbn(txt.get())
                    suggestions = results['feedback']['suggestions']

                    if suggestions == []:
                        val = txt.get()
                        txt.delete(0, "end")
                        txt.config(fg="light green")
                        txt.insert(0, val)
                        val1 = txt.get()
                        txt1.delete(0, "end")
                        txt1.config(fg="light green")
                        txt1.insert(0, val1)
                        savePW = messagebox.askyesno("Password OK",
                                                     f"Are you sure you want to set your master password to:\n\n{entPW.value}\n\n"
                                                     f"Your password will be copied to your clipboard if you wish to "
                                                     f"securely save it locally.")

                        # Save hashed master password

                        if savePW:

                            sql = "DELETE FROM masterpassword WHERE id = 1"

                            cursor.execute(sql)

                            hashedPassword = hashPassword(txt.get().encode('utf-8'))

                            key = str(uuid.uuid4().hex)
                            recoveryKey = hashPassword(key.encode('utf-8'))

                            global encryptionKey
                            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))

                            insert_password = """INSERT INTO masterpassword(password, recoveryKey)
                                                                    VALUES(?, ?)"""
                            cursor.execute(insert_password, ((hashedPassword), (recoveryKey)))
                            db.commit()

                            btn2.config(text="Success")
                            btn2.after(500, partial(recoveryScreen, key))

                            pyperclip.copy(entPW.value)

                        else:
                            txt.focus()
                    else:
                        lbl3 = Label(window,
                                     text=f"Please choose a stronger master password.\nFollow these suggestions:")
                        lbl3.pack()
                        val = txt.get()
                        txt.delete(0, "end")
                        txt.config(fg="orange")
                        txt.insert(0, val)
                        val1 = txt.get()
                        txt1.delete(0, "end")
                        txt1.config(fg="orange")
                        txt1.insert(0, val1)
                        for i in suggestions:
                            lbl3 = Label(window, text=f"· {i}")
                            lbl3.pack()
                else:
                    val = txt.get()
                    txt.delete(0, "end")
                    txt.config(fg="red")
                    txt.insert(0, val)
                    val1 = txt.get()
                    txt1.delete(0, "end")
                    txt1.config(fg="red")
                    txt1.insert(0, val1)
                    txt.focus()
                    for i in entPW.WASP:
                        lbl = Label(window, text=i)
                        lbl.pack()

            else:
                txt.focus()
                lbl2 = Label(window, text="· Password do not match.")
                lbl2.pack()
                txt.focus()

        btn2 = Button(window, text="Submit", command=checkMasterPW)
        btn2.pack(pady=5)

        lbl = Label(window,
                    text="· Password should not be shorter than 8 characters\nand not longer than 64 characters.")
        lbl.pack()

        lbl = Label(window, text="· Password should contain at least one uppercase,\nlower case and special character.")
        lbl.pack()

    # Creation of recoveryKey

    def recoveryScreen(key):
        for widget in window.winfo_children():
            widget.destroy()

        topframe = Frame(window)
        topframe.pack(side=TOP)

        app_width = int(screen_width / 2)
        app_height = int(screen_height)
        xCor = (screen_width / 2) - (app_width / 2)
        yCor = (screen_height / 2) - (app_height / 2)
        window.geometry(f'{app_width}x{app_height}+{int(xCor)}+{int(yCor)}')

        window.title("Save this key to recover your account")

        lbl = Label(topframe, text="Your recovery key:")
        lbl.config(anchor=CENTER)
        lbl.pack()

        lbl1 = Label(topframe, text=key)
        lbl1.config(anchor=CENTER)
        lbl1.pack()

        def resetB():
            btn2.config(text="Copy")

        def copyKeyR():
            pyperclip.copy(lbl1.cget("text"))
            btn2.config(command=copyKeyR, text="Copied")
            btn2.after(500, resetB)

        def copyKey():
            pyperclip.copy(lbl1.cget("text"))

            def done():
                passwordVault()

            btn3 = Button(topframe, text="Done", command=done)
            btn3.pack()

            btn2.config(command=copyKeyR, text="Copied")
            btn2.after(500, resetB)

        lbl3 = Label(topframe,
                     text="Copy and save this key securely.\nYou will not be able to reset your master password "
                          "without this key.")
        lbl3.config(anchor=CENTER)
        lbl3.pack()

        btn2 = Button(topframe, text="Copy Key", command=copyKey)
        btn2.pack(pady=5)

    # Recovery of passwordVault using recoveryKey

    def resetScreen():
        for widget in window.winfo_children():
            widget.destroy()

        topframe = Frame(window)
        topframe.pack(side=TOP)

        app_width = int(screen_width / 2)
        app_height = int(screen_height)
        xCor = (screen_width / 2) - (app_width / 2)
        yCor = (screen_height / 2) - (app_height / 2)
        window.geometry(f'{app_width}x{app_height}+{int(xCor)}+{int(yCor)}')

        window.title("Enter Recovery Key:")

        lbl = Label(topframe, text="Enter Recovery Key")
        lbl.config(anchor=CENTER)
        lbl.pack()

        txt = Entry(topframe, width=20)  # hide entry , show="*"
        txt.pack(side=LEFT)
        txt.focus()

        lbl1 = Label(window)
        lbl1.config(anchor=CENTER)
        lbl1.pack()

        resetObj = bruteforceCheck(2)

        def getRecoveryKey():
            recoveryKeyCheck = hashPassword(str(txt.get()).encode('utf-8'))
            cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?", [(recoveryKeyCheck)])
            return cursor.fetchall()

        def checkRecoveryKey():
            checked = getRecoveryKey()

            resetObj.enum()

            if resetObj.attempts == 1:
                resetObj.initTimer()

            if not resetObj.passAttempt:
                lbl1.config(text="Recovery request blocked. You are permitted 2 recovery attempts per minute.")

            elif resetObj.blocked:
                    lbl1.config(text="You have exceeded recovery attempts.\nUser account and data will self destruct.")

                    def delData():
                        if os.path.exists("vaultKnox_passwords.db"):
                            os.remove("vaultKnox_passwords.db")
                        window.destroy()
                        main()
                    lbl1.after(2000, delData)
            else:
                if checked:
                    resetObj.match()
                    sql = "DELETE FROM masterpassword WHERE id = 1"
                    cursor.execute(sql)
                    db.commit()
                    btn2.config(text="Success")
                    txt.after(500, firstScreen)

                else:
                    txt.delete(0, 'end')
                    lbl1.config(text='Wrong key')

        btn2 = Button(window, text="Check Key", command=checkRecoveryKey)
        btn2.pack(pady=5)

        btn4 = Button(window, text="Back", command=loginScreen)
        btn4.pack(pady=5)

    # Subsequent loads
    # Log into passwordVault

    def loginScreen():
        for widget in window.winfo_children():
            widget.destroy()

        topframe = Frame(window)
        topframe.pack(side=TOP)

        app_width = int(screen_width / 2)
        app_height = int(screen_height)
        xCor = (screen_width / 2) - (app_width / 2)
        yCor = (screen_height / 2) - (app_height / 2)
        window.geometry(f'{app_width}x{app_height}+{int(xCor)}+{int(yCor)}')

        window.title("VaultKnox Login")

        lbl = Label(topframe, text="Please enter your master password:")
        lbl.config(anchor=CENTER)
        lbl.pack()

        txt = Entry(topframe, width=20)  # hide entry , show="*"
        txt.pack(side=LEFT)
        txt.focus()  # focus cursor at field
        global userpw
        userpw = txt.get()

        lbl1 = Label(window)
        lbl1.pack()

        loginObj = bruteforceCheck(5)

        # Check match with masterpassword

        def getMasterPassword():
            checkHashedPW = hashPassword(txt.get().encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))

            cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPW)])

            return cursor.fetchall()

        def checkPassword():
            match = getMasterPassword()

            loginObj.enum()

            if loginObj.attempts == 1:
                loginObj.initTimer()

            if not loginObj.passAttempt:
                val = txt.get()
                txt.delete(0, "end")
                txt.config(fg="red")
                txt.insert(0, val)
                lbl1.config(text="Login request blocked. You are permitted 5 login attempts per minute.")
            elif loginObj.blocked:
                val = txt.get()
                txt.delete(0, "end")
                txt.config(fg="red")
                txt.insert(0, val)
                lbl1.config(text="You have exceeded login attempts.\nEnter your recovery key to unlock your account.")
                lbl.config(text="Please enter your recovery key:")
                lbl.after(2000, resetScreen)
            else:
                if match:
                    val = txt.get()
                    txt.delete(0, "end")
                    txt.config(fg="light green")
                    txt.insert(0, val)
                    loginObj.match()
                    lbl1.config(text="")
                    btn.config(text="Success")
                    btn.after(500, passwordVault)

                else:
                    txt.delete(0, 'end')
                    lbl1.config(text="Password is not valid.")

        # Hide/show password

        def hideT():
            txt.config(show="*")

        def showT():
            txt.config(show="")

        def checkT():
            global x
            x += 1
            if x % 2 == 1:
                btn2['text'] = "Show"
                hideT()
            else:
                btn2['text'] = "Hide"
                showT()

        global x
        x = 0
        btn2 = Button(topframe, text="Hide", command=checkT)
        btn2.pack(side=RIGHT)

        def resetPassword():
            resetScreen()

        btn = Button(window, text="Submit", command=checkPassword)
        btn.pack()  # pady to add padding padx - left,right

        btn3 = Button(window, text="Reset Password", command=resetPassword)
        btn3.pack(pady=5)

        global ipdetails

        try:
            lblIP = Label(window, text=f"\n{ipdetails.hostname} ({ipdetails.localIP}) details:\n\n IP: {ipdetails.IP} \nCity: {ipdetails.city} \nRegion: {ipdetails.region} \nCountry: {ipdetails.country} \nOrg: {ipdetails.org}\n\n"
                                  "Please consider trying out a VPN service\n   to protect your internet connection and privacy online.   \n", borderwidth=2, relief="ridge")
        except:
            pass

        cursor.execute("SELECT IP FROM userSettings")
        IP = cursor.fetchall()[0][0]

        if IP == None:
            if not ipdetails.IP == "Unknown":
                cursor.execute("UPDATE usersettings SET IP = ? WHERE id = ?",
                               (hashPassword(ipdetails.IP.encode('utf-8')), 1))
                db.commit()
        else:
            if not ipdetails.IP == "Unknown":
                encIP = hashPassword(ipdetails.IP.encode('utf-8'))
                if not IP == encIP:
                    while True:
                        userRecovery = simpledialog.askstring("Logging in from a different IP address.", "The system IP address does not "
                                                                                         "match the configured IP of the password vault.\n\n"
                                                                                         "Please enter your recovery key to continue with the login process.\n")
                        if userRecovery == None:
                            continue
                        else:

                            def getRecoveryKey():
                                recoveryKeyCheck = hashPassword(userRecovery.encode('utf-8'))
                                cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?",
                                               [(recoveryKeyCheck)])
                                return cursor.fetchall()

                            def checkRecoveryKey():
                                checked = getRecoveryKey()
                                return checked

                            if checkRecoveryKey():
                                cursor.execute("UPDATE usersettings SET IP = ? WHERE id = ?",
                                               (hashPassword(ipdetails.IP.encode('utf-8')), 1))
                                db.commit()
                                break

        lblIP.pack(pady=10)

        btnNord = Button(window, text="NordVPN")
        btnNord.pack()

    global showing
    showing = True

    # Access user password vault

    def passwordVault():
        for widget in window.winfo_children():
            widget.destroy()

        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(userpw.encode()))

        def removeEntry(i):
            userAns = messagebox.askyesno("Confirmation", f"Are you sure you want to delete the entry for service: \n\n{decrypt(array[i][1], encryptionKey).decode('utf-8')}")

            if userAns:
                cursor.execute("DELETE FROM passwordVault WHERE id = ?", (array[i][0],))

                db.commit()

                passwordVault()

        app_width = int(screen_width)
        app_height = int(screen_height)
        xCor = (screen_width / 2) - (app_width / 2)
        yCor = (screen_height / 2) - (app_height / 2)
        window.geometry(f'{app_width}x{app_height}+{int(xCor)}+{int(yCor)}')

        window.title("VaultKnox Passwords")  # add name variable to title

        btn = Button(window, text="?", command=infor)
        btn.grid(column=0, row=0, pady=10)

        lbl = Label(window, text="Your Password Vault")
        lbl.grid(column=1, row=0)

        btn = Button(window, text="Sign Out", command=partial(signOut, loginScreen))
        btn.grid(column=2, row=0, pady=10)

        def passwordFeedback():
            for widget in window.winfo_children():
                if ".!toplevel" in str(widget):
                    exists = True
                    if exists:
                        widget.destroy()

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(userpw.encode()))

            reportScreen = Toplevel(window)
            reportTopFrame = Frame(reportScreen)
            reportTopFrame.pack()
            reportMidFrame = Frame(reportScreen)
            reportMidFrame.pack()
            reportMidLFrame = Frame(reportMidFrame, width=300)
            reportMidLFrame.pack(side=LEFT)
            reportMidMFrame = Frame(reportMidFrame, width=300)
            reportMidMFrame.pack(side=LEFT)
            reportMidRFrame = Frame(reportMidFrame, width=300)
            reportMidRFrame.pack(side=LEFT)
            reportBotFrame = Frame(reportScreen)
            reportBotFrame.pack()

            app_width = int(screen_width / 1.5)
            app_height = int(screen_height)
            xCor = (screen_width / 2) - (app_width / 2)
            yCor = (screen_height / 2) - (app_height / 2)
            reportScreen.geometry(f'{app_width}x{app_height}+{int(xCor)}+{int(yCor)}')

            reportScreen.title("Password Feedback:")

            lblToday = Label(reportTopFrame, text="VaultKnox Passwords - Report Feedback")
            lblToday.pack(pady=5, padx=10, side=TOP)

            lblSer = Label(reportMidLFrame, text="Service:")
            lblSer.pack(pady=5, padx=30, side=TOP)

            lblUser = Label(reportMidMFrame, text="Username:")
            lblUser.pack(pady=5, padx=30, side=TOP)

            lblPW = Label(reportMidRFrame, text="Password:")
            lblPW.pack(pady=5, padx=30, side=TOP)

            lblSerS = Label(reportMidLFrame, text="<None>")
            lblSerS.pack(pady=5, padx=30, side=TOP)

            lblUserS = Label(reportMidMFrame, text="<None>")
            lblUserS.pack(pady=5, padx=30, side=TOP)

            lblPWS = Label(reportMidRFrame, text="<None>")
            lblPWS.pack(pady=5, padx=30, side=TOP)

            lblDOC = Label(reportMidLFrame, text="Created:")
            lblDOC.pack(pady=5, padx=30, side=TOP)

            lblDOCS = Label(reportMidLFrame, text="<None>")
            lblDOCS.pack(pady=5, padx=30, side=TOP)

            lblDOE = Label(reportMidMFrame, text="Expiring:")
            lblDOE.pack(pady=5, padx=30, side=TOP)

            lblDOES = Label(reportMidMFrame, text="<None>")
            lblDOES.pack(pady=5, padx=30, side=TOP)

            lblUse = Label(reportMidRFrame, text="Number of uses:")
            lblUse.pack(pady=5, padx=30, side=TOP)

            lblUseS = Label(reportMidRFrame, text="<None>")
            lblUseS.pack(pady=5, padx=30, side=TOP)

            def selectPassword():
                for widget in reportScreen.winfo_children():
                    if ".!toplevel.!toplevel" in str(widget):
                        exists = True
                        if exists:
                            widget.destroy()

                selectPScreen = Toplevel(reportScreen)
                selectPScreen.title("Select password entry")

                app_width = 300
                app_height = 300
                x = (screen_width / 2) - (app_width / 2)
                y = (screen_height / 2) - (app_height / 2)
                selectPScreen.geometry(f'{app_width}x{app_height}+{int(x)}+{int(y)}')

                scrollBar = Scrollbar(selectPScreen, bg="grey")

                scrollBar.pack(side=RIGHT, fill=BOTH)
                entryList = Listbox(selectPScreen, selectmode=BROWSE, yscrollcommand=scrollBar.set)

                scrollBar.config(command=entryList.yview)
                entryList.pack(pady=10, padx=10, expand=TRUE, fill=BOTH, side=TOP)

                for i in range(0, len(array)):
                    entryList.insert(i, decrypt(array[i][1], encryptionKey))

                def selectedEntry():
                    cursor.execute("SELECT * FROM passwordVault")
                    array = cursor.fetchall()
                    while True:
                        if entryList.curselection() == ():
                            break
                        choice = entryList.curselection()[0]
                        if choice == ():
                            messagebox.showwarning("showwarning", "Please select a diary entry.")
                            break

                        pwHealth = 1
                        selectPScreen.destroy()
                        lblUserS.config(text=decrypt(array[choice][1], encryptionKey))
                        lblSerS.config(text=decrypt(array[choice][2], encryptionKey))
                        lblPWS.config(text=decrypt(array[choice][3], encryptionKey))
                        lblUseS.config(text=array[choice][5])
                        date = decrypt(array[choice][4], encryptionKey).decode("utf-8")
                        dateobj = datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f')
                        lblDOCS.config(text=dateobj.strftime('%Y-%m-%d %H:%M:%S'))
                        outdated = dateobj + timedelta(days=(settings[0][1] * 30))
                        DOEobj = outdated.strftime('%Y-%m-%d %H:%M:%S')
                        lblDOES.config(text=DOEobj)

                        datenow = datetime.now()
                        delta = outdated-datenow

                        feedbackPW = MasterPassword(decrypt(array[choice][3], encryptionKey).decode("utf-8"), [])

                        strFeedback = "Password remediation:\n\n"

                        results = zxcvbn(feedbackPW.value)
                        suggestions = results['feedback']['suggestions']

                        if len(suggestions) > 0:
                            for i in suggestions:
                                strFeedback += f"{i}\n"
                            pwHealth = 2

                        if len(feedbackPW.WASP) > 0:
                            for i in feedbackPW.WASP:
                                strFeedback += f"{i}\n"
                            pwHealth = 3

                        if delta.days > 0:
                            expiry = f"Password is expiring in {delta.days} days."
                            lblDOES.config(fg="light green")
                        else:
                            expiry = f"Password is vulnerable, expired {abs(delta.days)} days ago."
                            pwHealth = 3
                            lblDOES.config(fg="red")

                        if pwHealth == 1:
                            health = "Password is safe."
                            lblPWS.config(fg="light green")
                        elif pwHealth == 2:
                            health = "Password health is medium."
                            lblPWS.config(fg="orange")
                        else:
                            health = "Password health is vulnerable."
                            lblPWS.config(fg="red")

                        # Password remediation zxcvbn package
                        txtReport.delete(1.0, "end")
                        txtReport.insert(1.0, strFeedback)

                        txtReport.insert("end", f"\n{health}\n")

                        txtReport.insert("end", f"\n{expiry}")
                        break

                butOk = Button(selectPScreen, text="Select", command=selectedEntry)
                butOk.pack(side=TOP, pady=5)

            butSelectP = Button(reportTopFrame, text="Select Entry", command=selectPassword)
            butSelectP.pack(pady=5, padx=10, side=TOP)

            databaseModified = os.path.getmtime("vaultKnox_passwords.db")
            # Convert seconds since epoch to readable timestamp
            modificationTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(databaseModified))

            txtReport = Text(reportBotFrame, undo=TRUE, wrap=WORD)
            txtReport.pack(pady=5, padx=10, fill=BOTH)

            lblAccess = Label(reportBotFrame, text="Previously utilized VaultKnox at:")
            lblAccess.pack(pady=5)

            lblAccessS = Label(reportBotFrame, text=f"{modificationTime}")
            lblAccessS.pack(pady=5)

        btnReport = Button(window, text="Report Feedback", command=passwordFeedback)
        btnReport.grid(column=0, row=1, pady=10)

        btn = Button(window, text="Add New Entry +", command=addEntry)
        btn.grid(column=1, row=1, pady=10)

        def checkP():
            global showing
            showing = not(showing)
            passwordVault()

        btnHide = Button(window, text="Hide passwords", command=checkP)
        btnHide.grid(column=2, row=1, pady=10)

        lbl = Label(window, text="Service:")
        lbl.grid(column=0, row=2, padx=80)

        lbl = Label(window, text="Username:")
        lbl.grid(column=1, row=2, padx=80)

        lbl = Label(window, text="Password:")
        lbl.grid(column=2, row=2, padx=80)

        def userSetting():
            cursor.execute("SELECT * FROM userSettings")
            settings = cursor.fetchall()

            settingScreen = Toplevel(window)
            app_width = int(screen_width/2)
            app_height = int(screen_height/2)
            xCor = (screen_width / 2) - (app_width / 2)
            yCor = (screen_height / 2) - (app_height / 2)
            settingScreen.geometry(f'{app_width}x{app_height}+{int(xCor)}+{int(yCor)}')

            settingScreen.title("Vault Settings")  # add name variable to title

            lblTimeframe = Label(settingScreen, text="Update passwords after (months): ")
            lblTimeframe.pack()

            if len(settings) > 0:
                months = IntVar(value=settings[0][1])
                minutes = IntVar(value=settings[0][2])
            else:
                months = IntVar(value=1)
                minutes = IntVar(value=5)

            monthSpinbox = Spinbox(
                settingScreen,
                from_=1,
                to=12,
                textvariable=months,
                wrap=True)
            monthSpinbox.pack()

            lblIntactivity = Label(settingScreen, text="Inactivity check after (minutes): ")
            lblIntactivity.pack()


            minuteSpinbox = Spinbox(
                settingScreen,
                from_=3,
                to=60,
                textvariable=minutes,
                wrap=True)
            minuteSpinbox.pack()

            def saveSettings():
                userSettings = UserSettings(months.get(), minutes.get())
                cursor.execute("UPDATE usersettings SET timeframe = ?, inactivity = ? WHERE id = ?", (userSettings.timeframe, userSettings.inactivity, 1))
                db.commit()

                settingScreen.destroy()

            butSetSave = Button(settingScreen, text="Save", command=saveSettings)
            butSetSave.pack()

            def delData():
                deletedData = messagebox.askyesno("Delete all user data.", "Are you sure you want to delete all application data?\n\nYour user account and data will be deleted.")
                if deletedData:
                    if os.path.exists("vaultKnox_passwords.db"):
                        os.remove("vaultKnox_passwords.db")
                        window.destroy()
                        main()

            butDelData = Button(settingScreen, text="Delete Data", command=delData)
            butDelData.pack(side=BOTTOM, pady=10)

        butSetting = Button(window, text="Settings", command=userSetting)
        butSetting.grid(column=3, row=0)

        updatePW = []

        def outdatedEntry(outArr, y):
            for widget in window.winfo_children():
                if ".!toplevel" in str(widget):
                    exists = True
                    if exists:
                        widget.destroy()
            oudatedFrame = Toplevel(window)

            app_width = int(screen_width / 2)
            app_height = int(screen_height)
            xCor = (screen_width / 2) - (app_width / 2)
            yCor = (screen_height / 2) - (app_height / 2)
            oudatedFrame.geometry(f'{app_width}x{app_height}+{int(xCor)}+{int(yCor)}')

            oudatedFrame.title("Update outdated password entry:")

            lbl = Label(oudatedFrame, text="Name of the service:")
            lbl.config(anchor=CENTER)
            lbl.pack(side=TOP)

            txtSer = Entry(oudatedFrame, width=20)  # hide entry , show="*"
            txtSer.pack(side=TOP)
            txtSer.insert(0, (decrypt(outArr[y][1], encryptionKey)))

            lbl = Label(oudatedFrame, text="Username for the service:")
            lbl.config(anchor=CENTER)
            lbl.pack(side=TOP)

            txtUN = Entry(oudatedFrame, width=20)  # hide entry , show="*"
            txtUN.pack(side=TOP)
            txtUN.insert(0, (decrypt(outArr[y][2], encryptionKey)))

            lbl = Label(oudatedFrame, text="Outdated password for the service:")
            lbl.config(anchor=CENTER)
            lbl.pack(side=TOP)

            txtPW = Entry(oudatedFrame, width=20)  # hide entry , show="*"
            txtPW.pack(side=TOP)
            txtPW.insert(0, (decrypt(outArr[y][3], encryptionKey)))
            defPW = decrypt(outArr[y][3], encryptionKey).decode("utf-8")

            # Validation of updated password entry

            def checkPWEntry(y):
                currentDateTime = datetime.now()
                ser = txtSer.get()
                user = txtUN.get()
                passw = txtPW.get()

                passwordEntry = PasswordEntry(txtSer.get(), txtUN.get(), txtPW.get(), str(currentDateTime),
                                              encryptionKey)

                if ser == "":
                    messagebox.showerror("No service name", "Please enter a valid service name.")
                    return
                elif len(ser) > 64:
                    messagebox.showerror("Service name too long",
                                         "The service name is too long, please enter a valid service name.")
                    return
                elif user == "":
                    messagebox.showerror("No username", "Please enter a valid username.")
                    return
                elif len(user) > 64:
                    messagebox.showerror("Username too long",
                                         "Your username is too long, please enter a valid username.")
                    return
                elif passw == "":
                    messagebox.showerror("No password", "Please enter a valid password.")
                    return
                elif len(passw) > 64:
                    messagebox.showerror("Password too long",
                                         "The password is too long, please enter a valid password.")
                    return
                elif passw == defPW:

                    messagebox.showerror("Password matches original value",
                                         "The password has not changed, please update the password field.")
                    return

                else:
                    sql = "UPDATE passwordVault SET service = ?, username = ?, password = ?, date = ?, use = ? WHERE id = ?"

                    cursor.execute(sql, (passwordEntry.encservice, passwordEntry.encusername, passwordEntry.encpassword,
                                         passwordEntry.encdate, 0, (outArr[y][0]),))

                    db.commit()
                    oudatedFrame.destroy()
                    pyperclip.copy(decrypt(passwordEntry.encpassword, encryptionKey).decode("utf-8"))
                    messagebox.showwarning("Passwords updated",
                                           "Your updated password has been copied to you clipboard.\n\n"
                                           f"Please update the password in service: {decrypt(outArr[y][1], encryptionKey).decode('utf-8')}")

                    global driver
                    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))

                    def serviceTab():
                        try:
                            driver.get(f"https://{decrypt(outArr[y][1], encryptionKey).decode('utf-8')}")
                            while True:
                                pass
                        except:
                            pass

                    t = threading.Thread(name='serviceTab', target=serviceTab, daemon=True)
                    t.start()

                    y += 1
                    if len(updatePW) > y:
                        outdatedEntry(updatePW, y)

            # Generate a new password in update method

            def genPWScreen():
                genScreen = Toplevel(oudatedFrame)
                app_width = int(screen_width / 2)
                app_height = int(screen_height)
                xCor = (screen_width / 2) - (app_width / 2)
                yCor = (screen_height / 2) - (app_height / 2)
                genScreen.geometry(f'{app_width}x{app_height}+{int(xCor)}+{int(yCor)}')

                genScreen.title("Generate new password entry:")

                lblCharacter = Label(genScreen, text="Character length:")
                lblCharacter.pack(side=TOP)

                # Generate password specifications

                characters = IntVar(value=8)
                characterSpinbox = Spinbox(
                    genScreen,
                    from_=4,
                    to=64,
                    textvariable=characters,
                    wrap=True)
                characterSpinbox.pack()

                upperCase = IntVar()
                digits = IntVar()
                specialCharacter = IntVar()

                upperCase.set(0)
                digits.set(0)
                specialCharacter.set(0)

                c1 = Checkbutton(genScreen, text='Include Upper Case Characters', variable=upperCase, onvalue=1,
                                 offvalue=0)
                c1.pack()
                c2 = Checkbutton(genScreen, text='Include Digits', variable=digits, onvalue=1, offvalue=0)
                c2.pack()
                c3 = Checkbutton(genScreen, text='Include Special Characters', variable=specialCharacter,
                                 onvalue=1,
                                 offvalue=0)
                c3.pack()

                txtRanPW = Entry(genScreen)
                txtRanPW.pack()

                # Create random values

                def randomize():
                    pwLength = characters.get()

                    upperCaseV = int(upperCase.get())
                    digitsV = int(digits.get())
                    specialCharacterV = int(specialCharacter.get())

                    ranPW = ''

                    if upperCaseV == 1 and digitsV == 1 and specialCharacterV == 1:
                        for x in range(pwLength):
                            ran = randint(1, 3)
                            if ran == 1:
                                ranPW += chr(randint(33, 64))
                            elif ran == 2:
                                charac = randint(97, 122)
                                ranPW += chr(charac)
                            else:
                                ranPW += chr(randint(33, 126))
                    elif upperCaseV == 0 and digitsV == 1 and specialCharacterV == 1:
                        for x in range(pwLength):
                            if randint(1, 2) == 1:
                                ranPW += chr(randint(33, 64))
                            else:
                                ranPW += chr(randint(91, 126))
                    elif upperCaseV == 0 and digitsV == 0 and specialCharacterV == 1:
                        for x in range(pwLength):
                            if randint(1, 3) == 1:
                                ranPW += chr(randint(91, 126))
                            elif randint(1, 2) == 1:
                                ranPW += chr(randint(33, 47))
                            else:
                                ranPW += chr(randint(58, 64))
                    elif upperCaseV == 0 and digitsV == 0 and specialCharacterV == 0:
                        for x in range(pwLength):
                            charac = randint(97, 122)
                            ranPW += chr(charac)
                    elif upperCaseV == 1 and digitsV == 0 and specialCharacterV == 0:
                        for x in range(pwLength):
                            if randint(1, 2) == 1:
                                ranPW += chr(randint(65, 90))
                            else:
                                ranPW += chr(randint(97, 122))
                    elif upperCaseV == 1 and digitsV == 1 and specialCharacterV == 0:
                        for x in range(pwLength):
                            if randint(1, 3) == 1:
                                ranPW += chr(randint(48, 57))
                            else:
                                if randint(1, 2) == 1:
                                    ranPW += chr(randint(65, 90))
                                else:
                                    ranPW += chr(randint(97, 122))
                    elif upperCaseV == 0 and digitsV == 1 and specialCharacterV == 0:
                        for x in range(pwLength):
                            if randint(1, 2) == 1:
                                ranPW += chr(randint(48, 57))
                            else:
                                ranPW += chr(randint(97, 122))
                    else:  # c1 == 1 and c2 == 0 and c3 == 1:
                        for x in range(pwLength):
                            if randint(1, 2) == 1:
                                ranPW += chr(randint(65, 90))
                            else:
                                ranPW += chr(randint(58, 126))

                    txtRanPW.delete(0, "end")
                    txtRanPW.insert(0, ranPW)

                # Save generated password

                def saveGenPassword():
                    if txtRanPW.get() == "":
                        messagebox.showerror("No password generated", "Please generate a password first.")
                    else:
                        txtPW.delete(0, "end")
                        txtPW.insert(0, txtRanPW.get())
                        genScreen.destroy()

                btnGenPW = Button(genScreen, command=randomize, text="Generate Password")
                btnGenPW.pack()

                btnSaveGen = Button(genScreen, command=saveGenPassword, text="Ok")
                btnSaveGen.pack()

                genScreen.protocol("WM_DELETE_WINDOW", partial(on_closing, genScreen))

            btnGen = Button(oudatedFrame, text="Generate Random Password", command=genPWScreen)
            btnGen.pack(side=TOP)

            btnSave = Button(oudatedFrame, text="Save", command=partial(checkPWEntry, y))
            btnSave.pack(side=TOP)

            oudatedFrame.protocol("WM_DELETE_WINDOW", partial(on_closing, oudatedFrame))

        # Fill entries of password vault

        cursor.execute("SELECT * FROM passwordVault")
        if cursor.fetchall() != None:
            i = 0
            while True:
                cursor.execute("SELECT * FROM passwordVault")
                array = cursor.fetchall()

                if (len(array) == 0):
                    break

                def copyIn(id, btn, name):
                    cursor.execute("SELECT * FROM passwordVault")
                    array = cursor.fetchall()

                    global showing
                    def resetCopy():
                        if showing:
                            btn.config(text=decrypt(array[id][3], encryptionKey))
                        else:
                            btn.config(text="******")

                    if name == "three":
                        sql = "UPDATE passwordVault SET use = ? WHERE id = ?"

                        cursor.execute(sql, ((array[id][5] + 1), array[id][0]))

                        db.commit()

                    pyperclip.copy(decrypt(array[id][3], encryptionKey).decode("utf-8"))

                    btn.config(text="Copied")
                    btn.after(500, resetCopy)

                # Decryption of password entries during run time

                if not showing:
                    btnHide.config(text="Show Passwords")
                    btnThree = Button(window, text="******", font=("Helvetica", 12))
                else:
                    btnThree = Button(window, text=(decrypt(array[i][3], encryptionKey)), font=("Helvetica", 12))

                btnOne = Button(window, text=(decrypt(array[i][1], encryptionKey)), font=("Helvetica", 12))
                btnOne.grid(column=0, row=i + 3)
                btnOne.config(command=partial(copyIn, i, btnOne, "one"))

                btnTwo = Button(window, text=(decrypt(array[i][2], encryptionKey)), font=("Helvetica", 12))
                btnTwo.grid(column=1, row=i + 3)
                btnTwo.config(command=partial(copyIn, i, btnTwo, "two"))

                btnThree.grid(column=2, row=i + 3)
                btnThree.config(command=partial(copyIn, i, btnThree, "three"))

                btnDel = Button(window, text="Delete entry", command=partial(removeEntry, i))
                btnDel.grid(column=3, row=i + 3, pady=10)

                # Update password entry in password vault

                def updateEntry(i):
                    for widget in window.winfo_children():
                        if ".!toplevel" in str(widget):
                            exists = True
                            if exists:
                                widget.destroy()
                    pwFrame = Toplevel(window)

                    app_width = int(screen_width / 2)
                    app_height = int(screen_height)
                    xCor = (screen_width / 2) - (app_width / 2)
                    yCor = (screen_height / 2) - (app_height / 2)
                    pwFrame.geometry(f'{app_width}x{app_height}+{int(xCor)}+{int(yCor)}')

                    pwFrame.title("Update password entry:")

                    lbl = Label(pwFrame, text="Please enter the name of the service: (URL)")
                    lbl.config(anchor=CENTER)
                    lbl.pack(side=TOP)

                    txtSer = Entry(pwFrame, width=20)  # hide entry , show="*"
                    txtSer.pack(side=TOP)
                    txtSer.insert(0, (decrypt(array[i][1], encryptionKey)))

                    lbl = Label(pwFrame, text="Please enter your username for the service:")
                    lbl.config(anchor=CENTER)
                    lbl.pack(side=TOP)

                    txtUN = Entry(pwFrame, width=20)  # hide entry , show="*"
                    txtUN.pack(side=TOP)
                    txtUN.insert(0, (decrypt(array[i][2], encryptionKey)))

                    lbl = Label(pwFrame, text="Please enter a password for the service:")
                    lbl.config(anchor=CENTER)
                    lbl.pack(side=TOP)

                    txtPW = Entry(pwFrame, width=20)  # hide entry , show="*"
                    txtPW.pack(side=TOP)
                    txtPW.insert(0, (decrypt(array[i][3], encryptionKey)))
                    defPW = decrypt(array[i][3], encryptionKey).decode("utf-8")

                    # Validation of updated password entry

                    def checkPWEntry():
                        currentDateTime = datetime.now()
                        ser = txtSer.get()
                        user = txtUN.get()
                        passw = txtPW.get()

                        passwordEntry = PasswordEntry(txtSer.get(), txtUN.get(), txtPW.get(), str(currentDateTime), encryptionKey)

                        if ser == "":
                            messagebox.showerror("No service name", "Please enter a valid service name.")
                            return
                        elif len(ser) > 64:
                            messagebox.showerror("Service name too long",
                                                 "The service name is too long, please enter a valid service name.")
                            return
                        elif user == "":
                            messagebox.showerror("No username", "Please enter a valid username.")
                            return
                        elif len(user) > 64:
                            messagebox.showerror("Username too long",
                                                 "Your username is too long, please enter a valid username.")
                            return
                        elif passw == "":
                            messagebox.showerror("No password", "Please enter a valid password.")
                            return
                        elif len(passw) > 64:
                            messagebox.showerror("Password too long",
                                                 "The password is too long, please enter a valid password.")
                            return
                        elif passw == defPW:

                            messagebox.showerror("Password matches original value",
                                                 "The password has not changed, please update the password field.")
                            return
                        else:
                            url = f'https://{ser}'
                            try:
                                resp = requests.get(url)
                                if not resp.ok:
                                    if messagebox.askyesno("Service URL not found.", "Service name does not produce a "
                                                                                     "valid URL location and will not launch the service during an update.\n\n"
                                                                                     "Do you wish to enter a valid URL?"):
                                        return
                            except:
                                if messagebox.askyesno("Service URL not found.", "Service name does not produce a "
                                                                                 "valid URL location and will not launch the service during an update.\n\n"
                                                                                 "Do you wish to enter a valid URL?"):
                                    return

                            sql = "UPDATE passwordVault SET service = ?, username = ?, password = ?, date = ?, use = ? WHERE id = ?"

                            cursor.execute(sql, (passwordEntry.encservice, passwordEntry.encusername, passwordEntry.encpassword, passwordEntry.encdate, 0,  array[i][0],))

                            db.commit()
                            pwFrame.destroy()
                            passwordVault()

                    # Generate a new password in update method

                    def genPWScreen():
                        genScreen = Toplevel(pwFrame)
                        app_width = int(screen_width / 2)
                        app_height = int(screen_height)
                        xCor = (screen_width / 2) - (app_width / 2)
                        yCor = (screen_height / 2) - (app_height / 2)
                        genScreen.geometry(f'{app_width}x{app_height}+{int(xCor)}+{int(yCor)}')

                        genScreen.title("Generate new password entry:")

                        lblCharacter = Label(genScreen, text="Character length:")
                        lblCharacter.pack(side=TOP)

                        # Generate password specifications

                        characters = IntVar(value=8)
                        characterSpinbox = Spinbox(
                            genScreen,
                            from_=4,
                            to=64,
                            textvariable=characters,
                            wrap=True)
                        characterSpinbox.pack()

                        upperCase = IntVar()
                        digits = IntVar()
                        specialCharacter = IntVar()

                        upperCase.set(0)
                        digits.set(0)
                        specialCharacter.set(0)

                        c1 = Checkbutton(genScreen, text='Include Upper Case Characters', variable=upperCase, onvalue=1,
                                         offvalue=0)
                        c1.pack()
                        c2 = Checkbutton(genScreen, text='Include Digits', variable=digits, onvalue=1, offvalue=0)
                        c2.pack()
                        c3 = Checkbutton(genScreen, text='Include Special Characters', variable=specialCharacter,
                                         onvalue=1,
                                         offvalue=0)
                        c3.pack()

                        txtRanPW = Entry(genScreen)
                        txtRanPW.pack()

                        # Create random values

                        def randomize():
                            pwLength = characters.get()

                            upperCaseV = int(upperCase.get())
                            digitsV = int(digits.get())
                            specialCharacterV = int(specialCharacter.get())

                            ranPW = ''

                            if upperCaseV == 1 and digitsV == 1 and specialCharacterV == 1:
                                for x in range(pwLength):
                                    ran = randint(1, 3)
                                    if ran == 1:
                                        ranPW += chr(randint(33, 64))
                                    elif ran == 2:
                                        charac = randint(97, 122)
                                        ranPW += chr(charac)
                                    else:
                                        ranPW += chr(randint(33, 126))
                            elif upperCaseV == 0 and digitsV == 1 and specialCharacterV == 1:
                                for x in range(pwLength):
                                    if randint(1, 2) == 1:
                                        ranPW += chr(randint(33, 64))
                                    else:
                                        ranPW += chr(randint(91, 126))
                            elif upperCaseV == 0 and digitsV == 0 and specialCharacterV == 1:
                                for x in range(pwLength):
                                    if randint(1, 3) == 1:
                                        ranPW += chr(randint(91, 126))
                                    elif randint(1, 2) == 1:
                                        ranPW += chr(randint(33, 47))
                                    else:
                                        ranPW += chr(randint(58, 64))
                            elif upperCaseV == 0 and digitsV == 0 and specialCharacterV == 0:
                                for x in range(pwLength):
                                    charac = randint(97, 122)
                                    ranPW += chr(charac)
                            elif upperCaseV == 1 and digitsV == 0 and specialCharacterV == 0:
                                for x in range(pwLength):
                                    if randint(1, 2) == 1:
                                        ranPW += chr(randint(65, 90))
                                    else:
                                        ranPW += chr(randint(97, 122))
                            elif upperCaseV == 1 and digitsV == 1 and specialCharacterV == 0:
                                for x in range(pwLength):
                                    if randint(1, 3) == 1:
                                        ranPW += chr(randint(48, 57))
                                    else:
                                        if randint(1, 2) == 1:
                                            ranPW += chr(randint(65, 90))
                                        else:
                                            ranPW += chr(randint(97, 122))
                            elif upperCaseV == 0 and digitsV == 1 and specialCharacterV == 0:
                                for x in range(pwLength):
                                    if randint(1, 2) == 1:
                                        ranPW += chr(randint(48, 57))
                                    else:
                                        ranPW += chr(randint(97, 122))
                            else:  # c1 == 1 and c2 == 0 and c3 == 1:
                                for x in range(pwLength):
                                    if randint(1, 2) == 1:
                                        ranPW += chr(randint(65, 90))
                                    else:
                                        ranPW += chr(randint(58, 126))

                            txtRanPW.delete(0, "end")
                            txtRanPW.insert(0, ranPW)

                        # Save generated password

                        def saveGenPassword():
                            if txtRanPW.get() == "":
                                messagebox.showerror("No password generated", "Please generate a password first.")
                            else:
                                txtPW.delete(0, "end")
                                txtPW.insert(0, txtRanPW.get())
                                genScreen.destroy()

                        btnGenPW = Button(genScreen, command=randomize, text="Generate Password")
                        btnGenPW.pack()

                        btnSaveGen = Button(genScreen, command=saveGenPassword, text="Ok")
                        btnSaveGen.pack()

                        genScreen.protocol("WM_DELETE_WINDOW", partial(on_closing, genScreen))

                    btnGen = Button(pwFrame, text="Generate Random Password", command=genPWScreen)
                    btnGen.pack(side=TOP)

                    btnSave = Button(pwFrame, text="Save", command=checkPWEntry)
                    btnSave.pack(side=TOP)

                    pwFrame.protocol("WM_DELETE_WINDOW", partial(on_closing, pwFrame))

                btnUp = Button(window, text="Update entry", command=partial(updateEntry, i))
                btnUp.grid(column=4, row=i + 3, pady=10)

                def passwordCheck():
                    date = decrypt(array[i][4], encryptionKey).decode("utf-8")
                    dateobj = datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f')
                    outdated = dateobj + timedelta(days=(userSettings.timeframe * 30))
                    currentDateTime = datetime.now()

                    if currentDateTime > outdated:
                        updatePW.append([])
                        updatePW[len(updatePW)-1].append(array[i][0])
                        updatePW[len(updatePW)-1].append(array[i][1])
                        updatePW[len(updatePW)-1].append(array[i][2])
                        updatePW[len(updatePW)-1].append(array[i][3])

                passwordCheck()

                i += 1

                cursor.execute("SELECT * FROM passwordVault")
                if len(cursor.fetchall()) <= i:
                    break
        if len(updatePW) > 0:
            y = 0
            outdatedEntry(updatePW, y)
            messagebox.showwarning("Passwords outdated",
                                   "You have outdated passwords, please update these values and the correlating service.")


    # Create new password entry in password vault

    def addEntry():
        for widget in window.winfo_children():
            if ".!toplevel" in str(widget):
                exists = True
                if exists:
                    widget.destroy()
        pwFrame = Toplevel(window)

        app_width = int(screen_width / 2)
        app_height = int(screen_height)
        xCor = (screen_width / 2) - (app_width / 2)
        yCor = (screen_height / 2) - (app_height / 2)
        pwFrame.geometry(f'{app_width}x{app_height}+{int(xCor)}+{int(yCor)}')

        pwFrame.title("Add new password entry:")

        lbl = Label(pwFrame, text="Please enter the name of the service:")
        lbl.config(anchor=CENTER)
        lbl.pack(side=TOP)

        txtSer = Entry(pwFrame, width=20)  # hide entry , show="*"
        txtSer.pack(side=TOP)

        lbl = Label(pwFrame, text="Please enter your username for the service:")
        lbl.config(anchor=CENTER)
        lbl.pack(side=TOP)

        txtUN = Entry(pwFrame, width=20)  # hide entry , show="*"
        txtUN.pack(side=TOP)

        lbl = Label(pwFrame, text="Please enter a password for the service:")
        lbl.config(anchor=CENTER)
        lbl.pack(side=TOP)

        txtPW = Entry(pwFrame, width=20)  # hide entry , show="*"
        txtPW.pack(side=TOP)

        # Validate of created password

        def checkPWEntry():
            ser = str(txtSer.get())
            user = str(txtUN.get())
            passw = str(txtPW.get())

            global userpw

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(userpw.encode()))

            if ser == "":
                messagebox.showerror("No service name", "Please enter a valid service name.")
                return
            elif len(ser) > 64:
                messagebox.showerror("Service name too long", "The service name is too long, please enter a valid service name.")
                return
            elif user == "":
                messagebox.showerror("No username", "Please enter a valid username.")
                return
            elif len(user) > 64:
                messagebox.showerror("Username too long", "Your username is too long, please enter a valid username.")
                return
            elif passw == "":
                messagebox.showerror("No password", "Please enter a valid password.")
                return
            elif len(passw) > 64:
                messagebox.showerror("Password too long", "The password is too long, please enter a valid password.")
                return
            else:
                btnSave['state'] = 'disabled'
                url = f'https://{ser}'
                try:
                    resp = requests.get(url)
                    if not resp.ok:
                        if messagebox.askyesno("Service URL not found.", "Service name does not produce a "
                                                                         "valid URL location and will not launch the service during an update.\n\n"
                                                                         "Do you wish to enter a valid URL?"):
                            return

                except:
                    if messagebox.askyesno("Service URL not found.", "Service name does not produce a "
                                                                     "valid URL location and will not launch the service during an update.\n\n"
                                                                     "Do you wish to enter a valid URL?"):
                        return

                # Insert password entry to offline database

                service = encrypt(ser.encode(), encryptionKey)
                username = encrypt(user.encode(), encryptionKey)
                password = encrypt(passw.encode(), encryptionKey)
                currentDateTime = datetime.now()
                date = encrypt(str(currentDateTime).encode(), encryptionKey)

                insert_fields = """INSERT INTO passwordVault(service, username, password, date, use) 
                VALUES(?, ?, ?, ?, ?)"""

                cursor.execute(insert_fields, (service, username, password, date, 0))
                db.commit()
                pwFrame.destroy()
                passwordVault()

        # Generate new password

        def genPWScreen():
            genScreen = Toplevel(pwFrame)
            app_width = int(screen_width / 2)
            app_height = int(screen_height)
            xCor = (screen_width / 2) - (app_width / 2)
            yCor = (screen_height / 2) - (app_height / 2)
            genScreen.geometry(f'{app_width}x{app_height}+{int(xCor)}+{int(yCor)}')

            genScreen.title("Generate new password entry:")

            lblCharacter = Label(genScreen, text="Character length:")
            lblCharacter.pack(side=TOP)

            characters = IntVar(value=8)
            characterSpinbox = Spinbox(
                genScreen,
                from_=4,
                to=64,
                textvariable=characters,
                wrap=True)
            characterSpinbox.pack()

            upperCase = IntVar()
            digits = IntVar()
            specialCharacter = IntVar()

            upperCase.set(0)
            digits.set(0)
            specialCharacter.set(0)

            c1 = Checkbutton(genScreen, text='Include Upper Case Characters', variable=upperCase, onvalue=1, offvalue=0)
            c1.pack()
            c2 = Checkbutton(genScreen, text='Include Digits', variable=digits, onvalue=1, offvalue=0)
            c2.pack()
            c3 = Checkbutton(genScreen, text='Include Special Characters', variable=specialCharacter, onvalue=1,
                             offvalue=0)
            c3.pack()

            txtRanPW = Entry(genScreen)
            txtRanPW.pack()

            def randomize():
                pwLength = characters.get()

                upperCaseV = int(upperCase.get())
                digitsV = int(digits.get())
                specialCharacterV = int(specialCharacter.get())

                ranPW = ''

                if upperCaseV == 1 and digitsV == 1 and specialCharacterV == 1:
                    for x in range(pwLength):
                        ran = randint(1, 3)
                        if ran == 1:
                            ranPW += chr(randint(33, 64))
                        elif ran == 2:
                            charac = randint(97, 122)
                            ranPW += chr(charac)
                        else:
                            ranPW += chr(randint(33, 126))
                elif upperCaseV == 0 and digitsV == 1 and specialCharacterV == 1:
                    for x in range(pwLength):
                        if randint(1, 2) == 1:
                            ranPW += chr(randint(33, 64))
                        else:
                            ranPW += chr(randint(91, 126))
                elif upperCaseV == 0 and digitsV == 0 and specialCharacterV == 1:
                    for x in range(pwLength):
                        if randint(1, 3) == 1:
                            ranPW += chr(randint(91, 126))
                        elif randint(1, 2) == 1:
                            ranPW += chr(randint(33, 47))
                        else:
                            ranPW += chr(randint(58, 64))
                elif upperCaseV == 0 and digitsV == 0 and specialCharacterV == 0:
                    for x in range(pwLength):
                        charac = randint(97, 122)
                        ranPW += chr(charac)
                elif upperCaseV == 1 and digitsV == 0 and specialCharacterV == 0:
                    for x in range(pwLength):
                        if randint(1, 2) == 1:
                            ranPW += chr(randint(65, 90))
                        else:
                            ranPW += chr(randint(97, 122))
                elif upperCaseV == 1 and digitsV == 1 and specialCharacterV == 0:
                    for x in range(pwLength):
                        if randint(1, 3) == 1:
                            ranPW += chr(randint(48, 57))
                        else:
                            if randint(1, 2) == 1:
                                ranPW += chr(randint(65, 90))
                            else:
                                ranPW += chr(randint(97, 122))
                elif upperCaseV == 0 and digitsV == 1 and specialCharacterV == 0:
                    for x in range(pwLength):
                        if randint(1, 2) == 1:
                            ranPW += chr(randint(48, 57))
                        else:
                            ranPW += chr(randint(97, 122))
                else:  # c1 == 1 and c2 == 0 and c3 == 1:
                    for x in range(pwLength):
                        if randint(1, 2) == 1:
                            ranPW += chr(randint(65, 90))
                        else:
                            ranPW += chr(randint(58, 126))

                txtRanPW.delete(0, "end")
                txtRanPW.insert(0, ranPW)

            def saveGenPassword():
                if txtRanPW.get() == "":
                    messagebox.showerror("No password generate", "Please generate a password first.")
                else:
                    txtPW.delete(0, "end")
                    txtPW.insert(0, txtRanPW.get())
                    genScreen.destroy()

            btnGenPW = Button(genScreen, command=randomize, text="Generate Password")
            btnGenPW.pack()

            btnSaveGen = Button(genScreen, command=saveGenPassword, text="Ok")
            btnSaveGen.pack()

            genScreen.protocol("WM_DELETE_WINDOW", partial(on_closing, genScreen))

        btnGen = Button(pwFrame, text="Generate Random Password", command=genPWScreen)
        btnGen.pack(side=TOP)

        btnSave = Button(pwFrame, text="Save", command=checkPWEntry)
        btnSave.pack(side=TOP)

        pwFrame.protocol("WM_DELETE_WINDOW", partial(on_closing, pwFrame))

    cursor.execute("SELECT * FROM masterpassword")

    # Navigate to register/login screen

    def initStart():
        if cursor.fetchall():
            loginScreen()
        else:
            firstScreen()

    window.after(2000, initStart)
    window.mainloop()

# Execute main method

if __name__ == '__main__':
    main()

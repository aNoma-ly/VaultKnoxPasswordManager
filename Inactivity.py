import time
from tkinter import messagebox


# Inactivity thread
def active(window, mins):
    while True:
        secs = mins * 60
        time.sleep(secs)
        userAns = messagebox.askyesno("Inactivity notice", f"You have been using Securepass for {mins} minutes. "
                                                           "\n\n Are you still using the application?")
        if userAns == True:
            continue
        else:
            window.destroy()

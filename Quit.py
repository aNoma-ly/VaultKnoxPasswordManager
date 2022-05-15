from tkinter import messagebox


# Quit protocol

def on_closing(screen):
    if messagebox.askokcancel("Quit", "Are sure you want to quit? \n \n Unsaved changes will be lost."):
        screen.destroy()

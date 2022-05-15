import re


# Master password class
class MasterPassword:

    # Init Masterpassword object
    def __init__(self, value, WASP):
        self.value = value
        # WASP: With Advanced Secure Programming Principles
        self.WASP = WASP

        # Validation and remediation of master password
        if len(value) < 8:
            self.WASP.append("· Password should not be shorter than 8 characters.")
        if len(value) > 64:
            self.WASP.append("· Password should not be longer than 64 characters.")
        if not re.search("[a-z]", value):
            self.WASP.append("· Password should contain at least one lower case character.")
        if not re.search("[A-Z]", value):
            self.WASP.append("· Password should contain at least one upper case character.")
        if not re.search("[0-9]", value):
            self.WASP.append("· Password should contain at least one digit.")
        if not re.search("[^A-Za-z0-9]", value):
            self.WASP.append("· Password should contain at least one special character.")

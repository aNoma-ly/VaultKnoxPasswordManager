import hashlib


# specifying hashing protocol
# convert input to hexadecimal hash

def hashPassword(input):
    hash1 = hashlib.sha512(input)
    hash1 = hash1.hexdigest()

    return hash1

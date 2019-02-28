import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)


fileToEncrypt = open("testText.txt", "r+")
textToEncrypt = fileToEncrypt.read();
print(len(textToEncrypt))


pt = b"1234567890123456123456789012    "
print("Plain Text: ", pt, "\n\n")

backend = default_backend()
key = os.urandom(32)
iv = os.urandom(16)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
encryptor = cipher.encryptor()
# the buffer needs to be at least len(data) + n - 1 where n is cipher/mode block size in bytes
buf = bytearray(255)
len_encrypted = encryptor.update_into(pt, buf)
# get the ciphertext from the buffer reading only the bytes written to it (len_encrypted)
string = bytes(buf[:len_encrypted]) + encryptor.finalize()
print("Cipher Text: ", string, "\n\n")
decryptor = cipher.decryptor()
len_decrypted = decryptor.update_into(string, buf)
# get the plaintext from the buffer reading only the bytes written (len_decrypted)
string = bytes(buf[:len_decrypted]) + decryptor.finalize()

print("Decrypted: ", string)
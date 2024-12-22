import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Генерация простого ключа
def generate_key() -> bytes:
    return os.urandom(32)

# Шифрование AES (облегчённое)
def encrypt_aes(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

# Дешифрование AES (облегчённое)
def decrypt_aes(encrypted_data: bytes, key: bytes) -> bytes:
    iv, encrypted_data = encrypted_data[:16], encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# Пример использования OniOn Lite
if __name__ == "__main__":
    message = input("Введите сообщение: ").encode()
    key = generate_key()
    encrypted_message = encrypt_aes(message, key)
    print("Зашифрованное сообщение:", encrypted_message)

    decrypted_message = decrypt_aes(encrypted_message, key)
    print("Расшифрованное сообщение:", decrypted_message.decode())

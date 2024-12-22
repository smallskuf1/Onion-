import os
import hmac
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

# Генерация ключа AES
def generate_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password)

# Шифрование AES
def encrypt_aes(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

# Дешифрование AES
def decrypt_aes(encrypted_data: bytes, key: bytes) -> bytes:
    iv, encrypted_data = encrypted_data[:16], encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return unpadder.update(padded_data) + unpadder.finalize()

# Функция шифрования OniOn
def onion_encrypt(data: str, password: str):
    salt = os.urandom(16)
    key = generate_key(password.encode(), salt)
    encrypted_data = encrypt_aes(data.encode(), key)
    hmac_key = os.urandom(32)
    hmac_obj = HMAC(hmac_key, hashes.SHA256())
    hmac_obj.update(encrypted_data)
    return encrypted_data, salt, hmac_obj.finalize(), hmac_key

# Функция расшифровки OniOn
def onion_decrypt(encrypted_data: bytes, salt: bytes, hmac_tag: bytes, hmac_key: bytes, password: str):
    key = generate_key(password.encode(), salt)
    hmac_obj = HMAC(hmac_key, hashes.SHA256())
    hmac_obj.update(encrypted_data)
    hmac_obj.verify(hmac_tag)  # Проверка целостности
    return decrypt_aes(encrypted_data, key).decode()

# Пример
if __name__ == "__main__":
    original_message = input("Введите сообщение: ")
    password = "strong_password"
    encrypted_data, salt, hmac_tag, hmac_key = onion_encrypt(original_message, password)
    print("Зашифрованное сообщение:", encrypted_data)

    decrypted_message = onion_decrypt(encrypted_data, salt, hmac_tag, hmac_key, password)
    print("Расшифрованное сообщение:", decrypted_message)

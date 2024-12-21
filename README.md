# OniOn - Многослойное шифрование сообщений и файлов

OniOn — это система многослойного шифрования для защиты сообщений, файлов и голосовых данных. Система использует алгоритмы AES и HMAC для обеспечения безопасности и целостности данных. Предоставляются две версии: **Onion** для максимальной защиты и **Onion Lite** для упрощённой версии, подходящей для менее мощных устройств.

## Архитектура системы

### 1. Onion (Основной вариант)
Система использует многослойное шифрование с AES и дополнительную защиту с помощью HMAC для обеспечения целостности сообщений.

- **Шифрование**: многослойное, с использованием AES (CBC) для каждого слоя.
- **Целостность**: HMAC для проверки целостности зашифрованных данных.
- **Поддержка**: Все типы данных (сообщения, файлы, голосовые сообщения).

### 2. Onion Lite (Упрощённый вариант)
Упрощённая версия системы, оптимизированная для мобильных и легких устройств.

- **Шифрование**: одностороннее с использованием простого AES шифрования.
- **Целостность**: использование базовых проверок целостности, оптимизированных для скорости.
- **Поддержка**: ограничена текстовыми сообщениями и файлами.

### 3. Архитектура и поддержка
- **Поддержка платформ**: доступно как для десктопных, так и для мобильных устройств (Android, Windows).
- **Производительность**: использует лёгкие алгоритмы шифрования для оптимизации работы на слабых устройствах.
- **Безопасность**: за счет многослойного подхода, система может быть более безопасной по сравнению с базовыми алгоритмами.

## Примеры использования

### Пример 1: Шифрование сообщения

```python
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Генерация ключа
key = secrets.token_bytes(32)

# Функция шифрования
def encrypt_aes(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext  # Возвращаем IV и зашифрованное сообщение

# Пример использования
message = "Привет, это секретное сообщение!"
encrypted_message = encrypt_aes(message, key)
print("Зашифрованное сообщение:", encrypted_message)

Пример 2: Расшифровка сообщения

# Функция расшифровки
def decrypt_aes(data, key):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# Пример расшифровки
decrypted_message = decrypt_aes(encrypted_message, key)
print("Расшифрованное сообщение:", decrypted_message)

Пример 3: Использование в мессенджере

Пример демонстрирует использование системы шифрования для отправки защищённого сообщения между клиентами.

def send_encrypted_message(message, key):
    encrypted_message = encrypt_aes(message, key)
    # Отправка зашифрованного сообщения через API
    send_to_server(encrypted_message)

def receive_encrypted_message(encrypted_message, key):
    decrypted_message = decrypt_aes(encrypted_message, key)
    return decrypted_message

# Пример отправки и получения
message = "Это защищённое сообщение!"
key = secrets.token_bytes(32)
send_encrypted_message(message, key)

Пример 4: Защита файлов

Для защиты файлов можно использовать ту же схему шифрования с AES.

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
    with open(file_path + '.enc', 'wb') as enc_file:
        enc_file.write(cipher.iv + encrypted_data)

def decrypt_file(encrypted_file_path, key):
    with open(encrypted_file_path, 'rb') as f:
        data = f.read()
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    with open(encrypted_file_path.replace('.enc', '.dec'), 'wb') as dec_file:
        dec_file.write(decrypted_data)

# Пример шифрования и расшифровки файла
file_path = 'example.txt'
encrypt_file(file_path, key)
decrypt_file(file_path + '.enc', key)

Благодарности

pycryptodome — за предоставление мощных инструментов для шифрования.

HMAC — за обеспечение целостности данных.

Всем открытым исходным проектам, которые вдохновили на создание этой системы.


Мы также выражаем благодарность всем пользователям, которые тестируют и помогают улучшать нашу систему безопасности..

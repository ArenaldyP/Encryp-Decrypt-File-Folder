import pathlib
import os
import secrets
import base64
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import cryptography

def generate_salt(size=16):
    """Generasi salt yang digunakan untuk derivasi kunci. `Size` adalah panjang salt yang akan dihasilkan."""
    return secrets.token_bytes(size)

def derive_key(salt, password):
    """Hasilkan kunci dari `password` menggunakan `salt` yang diberikan."""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def load_salt():
    salt_file_path = "salt.salt"
    try:
        with open(salt_file_path, "rb") as salt_file:
            return salt_file.read()
    except FileNotFoundError:
        print(f"[!] File salt tidak ditemukan. Path yang diusahakan: {os.path.abspath(salt_file_path)}")
        create_salt()
        return load_salt()

def create_salt(size=16):
    salt = generate_salt(size)
    with open("salt.salt", "wb") as salt_file:
        salt_file.write(salt)
    print("[*] Salt baru dibuat dan disimpan di salt.salt")

def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    """Hasilkan kunci dari `password` dan salt.
    Jika `load_existing_salt` bernilai True, maka akan memuat salt dari file
    dalam direktori saat ini yang disebut `salt.salt`.
    Jika `save_salt` bernilai True, maka akan menghasilkan salt baru dan
    menyimpannya ke `salt.salt`"""

    if load_existing_salt:
        # Memuat salt yang sudah ada
        salt = load_salt()

        if salt is None:
            # Menangani kasus di mana salt tidak tersedia
            print("[!] Salt tidak tersedia.")
            return None

    elif save_salt:
        # Menghasilkan salt baru dan menyimpannya
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)

    if salt is not None:
        # Hasilkan kunci dari salt dan password
        derived_key = derive_key(salt, password)

        # Enkode menggunakan Base 64 dan kembalikan
        return base64.urlsafe_b64encode(derived_key)
    else:
        # Kembalikan None jika salt tidak tersedia
        return None

def encrypt(filename, key):
    """Diberikan nama file (str) dan kunci (bytes), mengenkripsi file dan menuliskannya."""
    if key is None:
        print("[!] Kunci tidak tersedia. Enkripsi gagal.")
        return

    f = Fernet(key)
    try:
        with open(filename, "rb") as file:
            # Baca semua data file
            file_data = file.read()
            # Enkripsi data
            encrypted_data = f.encrypt(file_data)
        # Tulis file terenkripsi
        with open(filename, "wb") as file:
            file.write(encrypted_data)
    except FileNotFoundError:
        print(f"[!] File tidak ditemukan: {filename}")

def decrypt(filename, key):
    """Diberikan nama file (str) dan kunci (bytes), mendekripsi file dan menuliskannya."""
    if key is None:
        print("[!] Kunci tidak tersedia. Dekripsi gagal.")
        return

    f = Fernet(key)
    try:
        with open(filename, "rb") as file:
            # Baca data terenkripsi
            encrypted_data = file.read()
            # Data terdekripsi
            decrypted_data = f.decrypt(encrypted_data)
        # Tulis file terdekripsi
        with open(filename, "wb") as file:
            file.write(decrypted_data)
    except FileNotFoundError:
        print(f"[!] File tidak ditemukan: {filename}")
    except cryptography.fernet.InvalidToken:
        print(f"[!] Token tidak valid, kemungkinan kata sandi salah: {filename}")

def encrypt_folder(foldername, key):
    """Jika itu adalah folder, enkripsi seluruh folder (yaitu semua file yang berisi)."""
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Mengenkripsi {child}")
            encrypt(child, key)
        elif child.is_dir():
            encrypt_folder(child, key)

def decrypt_folder(foldername, key):
    """Jika itu adalah folder, dekripsi seluruh folder."""
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Mendekripsi {child}")
            decrypt(child, key)
        elif child.is_dir():
            decrypt_folder(child, key)

def scan_folders(base_path):
    """Memindai seluruh struktur folder dan menampilkan daftar folder."""
    folders = [str(path) for path in pathlib.Path(base_path).rglob("*") if path.is_dir()]
    print("Folder yang tersedia:")
    for i, folder in enumerate(folders, start=1):
        print(f"{i}. {folder}")
    return folders

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Skrip Enkripsi File Dengan Kata Sandi")
    parser.add_argument("path", help="Path untuk mengenkripsi/mendekripsi, bisa berupa file atau seluruh folder")
    parser.add_argument("-s", "--salt-size", help="Jika diatur, salt baru dengan ukuran yang ditentukan dihasilkan", type=int)
    parser.add_argument("-e", "--encrypt", action="store_true", help="Apakah akan mengenkripsi file/folder, hanya -e atau -d yang dapat diatur.")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Apakah akan mendekripsi file/folder, hanya -e atau -d yang dapat diatur.")
    parser.add_argument("--scan", action="store_true", help="Memindai dan menampilkan folder yang tersedia untuk enkripsi/dekripsi.")
    args = parser.parse_args()

    salt = None
    key = None

    if args.scan:
        folders = scan_folders(args.path)
        if not folders:
            print("[!] Tidak ada folder ditemukan.")
        else:
            folder_choice = int(input("Masukkan nomor folder untuk dienkripsi/didekripsi: "))
            if 1 <= folder_choice <= len(folders):
                args.path = folders[folder_choice - 1]
            else:
                print("[!] Pilihan tidak valid. Keluar.")
                exit()

    if args.encrypt or args.decrypt:
        if args.salt_size:
            salt = generate_salt(args.salt_size)
        elif args.encrypt:
            salt = load_salt()

    if args.encrypt or args.decrypt:
        if salt:
            password = getpass("Masukkan kata sandi: ")
            key = generate_key(password=password, salt_size=len(salt), load_existing_salt=True)

    if args.encrypt:
        if key:
            if os.path.isfile(args.path):
                # Jika itu adalah file, enkripsi
                encrypt(args.path, key=key)
            elif os.path.isdir(args.path):
                encrypt_folder(args.path, key=key)

    elif args.decrypt:
        if key:
            if os.path.isfile(args.path):
                decrypt(args.path, key=key)
            elif os.path.isdir(args.path):
                decrypt_folder(args.path, key=key)

    else:
        print("Harap tentukan apakah Anda ingin mengenkripsi atau mendekripsi file atau folder.")

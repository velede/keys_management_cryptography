import mariadb
import hashlib
import subprocess
import time
import psutil
from cryptography.fernet import Fernet
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from datetime import datetime

DB_CONFIG = {
    "host": '127.0.0.1',
    "user": 'root',
    "password": 'secret',
    "database": 'proiect',
    "port": 3306,
}

def get_db_connection():
    return mariadb.connect(**DB_CONFIG)




def listKeys():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, encryption_method, key_status FROM security_keys")
    keys = cursor.fetchall()
    cursor.close()
    conn.close()
    return keys


def addKey_gui():
    method = simpledialog.askstring("Encryption Method", "Enter method (AES-256 / RSA-2048):")
    if method == "AES-256":
        key = Fernet.generate_key().decode()
    elif method == "RSA-2048":
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out",
        "private_key.pem", "-pkeyopt", "rsa_keygen_bits:2048"])
        with open("private_key.pem", "r") as f:
            key = f.read()
    else:
        messagebox.showerror("Error", "Unsupported method")
        return

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO security_keys (encryption_method, secret_key, key_status) VALUES (?, ?, 'active')", (method, key))
    conn.commit()
    messagebox.showinfo("Success", f"Key added with ID: {cursor.lastrowid}")
    cursor.close()
    conn.close()


def getKey_id(key_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT secret_key FROM security_keys WHERE id = ?", (key_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result[0] if result else None


def hashFile_computing(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def updateEncryptionStatus(file_id, status, hash_val):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE secured_files 
        SET encryption_status = ?, hash_value = ? 
        WHERE id = ?
    """, (status, hash_val, file_id))
    conn.commit()
    cursor.close()
    conn.close()


def OpenSSl_fileEncryptionu(file_path, key, output_file, stored_filename, key_id):
    openssl_path = r'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
    with open("key.bin", "wb") as kf:
        kf.write(key.encode())

    start_method_time = time.time()
    subprocess.run([
        openssl_path, "enc", "-aes-256-cbc", "-salt",
        "-in", file_path, "-out", output_file,
        "-pass", "file:./key.bin"
    ])
    encryption_duration = time.time() - start_method_time

    hash_val = hashFile_computing(output_file)
    cpu_usage = psutil.cpu_percent(interval=0.5)
    file_size = Path(output_file).stat().st_size // 1024

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO secured_files (file_title, encryption_method, key_ref_id, file_size, encryption_status, hash_value)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (stored_filename, "AES-256", key_id, file_size, 'encrypted', hash_val))
    file_ref_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO performance_metrics (file_ref_id, encryption_duration, decryption_duration, memory_usage, cpu_usage)
        VALUES (?, ?, ?, ?, ?)""",
        (file_ref_id, encryption_duration, 0.0, psutil.virtual_memory().used / (1024 * 1024), cpu_usage))

    conn.commit()
    cursor.close()
    conn.close()
    messagebox.showinfo("Success", "File encrypted successfully.")



def OpenSSl_fileDecryption(encrypted_file, key, output_file, file_ref_id):
    openssl_path = r'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
    with open("key.bin", "wb") as kf:
        kf.write(key.encode())

    start_method_time = time.time()
    subprocess.run([
        openssl_path, "enc", "-d", "-aes-256-cbc",
        "-in", encrypted_file, "-out", output_file,
        "-pass", "file:./key.bin"
    ])
    decryption_duration = time.time() - start_method_time

    hash_val = hashFile_computing(output_file)
    cpu_usage = psutil.cpu_percent(interval=0.5)

    conn = get_db_connection()
    cursor = conn.cursor()

    updateEncryptionStatus(file_ref_id, 'decrypted', hash_val)

    cursor.execute("""
        UPDATE performance_metrics 
        SET decryption_duration = ?, memory_usage = ?, cpu_usage = ?
        WHERE file_ref_id = ?
    """, (decryption_duration, psutil.virtual_memory().used / (1024 * 1024), cpu_usage, file_ref_id))

    conn.commit()
    cursor.close()
    conn.close()
    messagebox.showinfo("Success", "File decrypted successfully.")


def list_files():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, file_title FROM secured_files WHERE encryption_status = 'encrypted'")
    files = cursor.fetchall()
    cursor.close()
    conn.close()
    return files


def get_file_info(file_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT file_title, key_ref_id FROM secured_files WHERE id = ?", (file_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result if result else (None, None)

def encrypt_action():
    file_path = filedialog.askopenfilename(title="Selectati un fisier pentru criptare")
    if not file_path:
        return

    keys = listKeys()
    if not keys:
        messagebox.showerror("Error", "Nu sunt chei pentru criptare.")
        return

    key_id = simpledialog.askinteger("Key ID", f"Chei pentru criptare :\n" + "\n".join([f"{k[0]} - {k[1]}" for k in keys]) + "\nIntroduceti un ID:")
    key = getKey_id(key_id)
    if not key:
        messagebox.showerror("Error", "Id invalid")
        return

    base_dir = Path(file_path).parent
    encrypted_dir = base_dir / "encrypted_files"
    encrypted_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    original_ext = Path(file_path).suffix.lstrip('.')
    encrypted_file_name = f"{original_ext}_{Path(file_path).stem}_{timestamp}.enc"
    output_file = encrypted_dir / encrypted_file_name

    OpenSSl_fileEncryptionu(file_path, key, str(output_file), encrypted_file_name, key_id)




def decrypt_action():
    files = list_files()
    if not files:
        messagebox.showerror("Error", "Nu sunt fisiere criptate.")
        return

    file_id = simpledialog.askinteger("File ID", f"Fisiere criptate:\n" + "\n".join([f"{f[0]} - {f[1]}" for f in files]) + "\nIntroduceti id-ul fisierului pentru decriptare:")
    file_title, key_id = get_file_info(file_id)
    if not key_id:
        messagebox.showerror("Error", "Id-ul nu este valid")
        return
    key = getKey_id(key_id)
    if not key:
        messagebox.showerror("Error", "Key not found.")
        return

    encrypted_file = filedialog.askopenfilename(title="Select encrypted file")
    if not encrypted_file:
        return

    base_dir = Path(encrypted_file).parent
    decrypted_dir = base_dir / "decrypted_files"
    decrypted_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    try:
        ext_prefix = file_title.split('_')[0]
        extension = f".{ext_prefix}"
    except IndexError:
        extension = ".bin"

    decrypted_file_name = f"decrypted-{timestamp}{extension}"
    output_file = decrypted_dir / decrypted_file_name

    OpenSSl_fileDecryption(encrypted_file, key, str(output_file), file_id)



def main_gui():
    root = tk.Tk()
    root.title("File Encryption System")
    root.geometry("500x400")
    root.configure(bg="#f0f0f0")

    title_label = tk.Label(root, text="Secure File Encryption System", font=("Helvetica", 18, "bold"), bg="#f0f0f0")
    title_label.pack(pady=20)

    button_style = {
        "font": ("Helvetica", 14),
        "width": 25,
        "pady": 10,
        "bg": "#4CAF50",
        "fg": "white",
        "activebackground": "#45a049",
        "bd": 0,
    }

    tk.Button(root, text="Add Encryption Key", command=addKey_gui, **button_style).pack(pady=10)
    tk.Button(root, text="Encrypt File", command=encrypt_action, **button_style).pack(pady=10)
    tk.Button(root, text="Decrypt File", command=decrypt_action, **button_style).pack(pady=10)


    root.mainloop()



if __name__ == "__main__":
    main_gui()
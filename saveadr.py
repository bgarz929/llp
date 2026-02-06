import sqlite3
import os

DB_FILE = "valid_nonce_reuse.db"   # ganti sesuai nama database kamu
OUTPUT_FILE = "wallet.txt"

def extract_grouped_addresses(db_path, output_file):
    if not os.path.exists(db_path):
        print("[ERROR] File database tidak ditemukan.")
        return

    print("[OK] File database ditemukan.")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Ambil address unik dari tabel signatures
    query = """
        SELECT DISTINCT address
        FROM signatures
        WHERE address IS NOT NULL AND address != ''
        ORDER BY address;
    """

    cursor.execute(query)
    rows = cursor.fetchall()

    conn.close()

    if not rows:
        print("[INFO] Tidak ada address ditemukan.")
        return

    # Simpan ke file adr.txt
    with open(output_file, "w", encoding="utf-8") as f:
        for (address,) in rows:
            f.write(address + "\n")

    print(f"[OK] Total address unik: {len(rows)}")
    print(f"[OK] Disimpan ke file: {output_file}")

if __name__ == "__main__":
    extract_grouped_addresses(DB_FILE, OUTPUT_FILE)


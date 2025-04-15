#!/usr/bin/env python3

import os
import random
import string
import itertools
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from collections import defaultdict
import time
import logging

# Configuration
CONFIG = {
    "log_file": "/root/some_sees_silently_facebook.log",
    "max_attempts": 10000000,
    "brute_force_max_length": 20,
}

# Logging Setup
logging.basicConfig(filename=CONFIG["log_file"], level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Transformer-Like Model for Password Prediction
class TransformerModel:
    def __init__(self):
        self.patterns = defaultdict(lambda: defaultdict(int))
        self.start_chars = defaultdict(int)

    def train(self, passwords):
        print("[!] Training Transformer-like model for Feasible Fetch...")
        for password in passwords:
            self.start_chars[password[:2]] += 1
            for i in range(len(password) - 1):
                self.patterns[password[i]][password[i + 1]] += 1

    def generate_password_with_score(self, max_length=16):
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

# Extract Username from Email or Profile URL
def extract_username(identifier):
    if "@" in identifier:
        return identifier.split("@")[0].lower()
    elif "facebook.com" in identifier:
        parsed_url = urlparse(identifier)
        path = parsed_url.path.strip("/")
        return path.lower() if path else "unknown"
    return identifier.lower()

# Simulated Packet Sniffing (Educational)
def simulate_packet_sniffing(username):
    print("[!] Simulating packet sniffing for educational purposes...")
    sniffed_passwords = [
        username + "123",
        username + "2024",
        "fb" + username,
        username + "@fb"
    ]
    print(f"[!] Simulated sniffed passwords: {sniffed_passwords}")
    return sniffed_passwords

# Feasible Fetch: ML-Based Password Prediction
def feasible_fetch_facebook(identifier, num_passwords=10000):
    username = extract_username(identifier)
    print(f"[!] Extracted username: {username}")

    training_passwords = [
        "password123", "admin2024", "qwerty123!", "secure123",
        "myfacebook123", "fbuser2024!", "socialmedia123", "login2024",
        "abcd1234", "welcome2024", "pakistan123", "lahore2024",
        "fbsecure2024", "myfbpass123!", "facebook2024", "userpass2024",
        "fbpassword123", "securefb2024!", "myaccount123", "fb2024secure"
    ]
    model = TransformerModel()
    model.train(training_passwords)

    scored_passwords = []
    for _ in range(num_passwords):
        pwd, score = model.generate_password_with_score(max_length=random.randint(8, 16))
        scored_passwords.append((pwd, score))

    scored_passwords.extend([
        (username + "123", 0.95),
        (username + "2024!", 0.9),
        (username + "@fb", 0.85),
        ("fb" + username + "123", 0.9),
        (username + "fb2024", 0.85),
        (username.upper() + "123!", 0.8)
    ])

    sniffed_passwords = simulate_packet_sniffing(username)
    for pwd in sniffed_passwords:
        scored_passwords.append((pwd, 0.9))

    scored_passwords.sort(key=lambda x: x[1], reverse=True)
    return [pwd for pwd, _ in scored_passwords[:num_passwords]]

# Advanced Brute-Force Password Generation (At Least 1 Lakh Passwords)
def generate_advanced_brute_force_passwords(max_length=20):
    passwords = []
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special_chars = "!@#$%^&*"

    # Pattern 1: word + digits + special
    for length in range(4, 9):
        for word in itertools.product(lowercase, repeat=length):
            word = "".join(word)
            for num in itertools.product(digits, repeat=4):
                num = "".join(num)
                for spec in itertools.product(special_chars, repeat=1):
                    spec = "".join(spec)
                    passwords.append(word + num + spec)
                    if len(passwords) >= 50000:
                        break
                if len(passwords) >= 50000:
                    break
            if len(passwords) >= 50000:
                break

    # Pattern 2: Username + year + special
    for year in ["2023", "2024", "2025"]:
        for spec in special_chars:
            for word in itertools.product(lowercase, repeat=4):
                word = "".join(word)
                passwords.append(word + year + spec)
                if len(passwords) >= 100000:
                    return passwords
            if len(passwords) >= 100000:
                return passwords

    return passwords

# Simulated Password Verification (Educational)
def simulate_password_verification(identifier, password):
    print("[!] Simulating password verification (educational use only)...")
    print(f"[!] Testing password: {password}")
    user_confirmation = input("[!] Is this your correct password? (yes/no): ").lower()
    return user_confirmation == "yes"

# Scrape Profile Data Using Selenium
def scrape_profile_data(identifier, password):
    print("[!] Initiating profile data extraction...")
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    driver = webdriver.Chrome(service=Service('/usr/lib/chromium/chromedriver'), options=chrome_options)

    try:
        driver.get("https://www.facebook.com")
        time.sleep(2)
        driver.find_element(By.ID, "email").send_keys(identifier)
        driver.find_element(By.ID, "pass").send_keys(password)
        driver.find_element(By.NAME, "login").click()
        time.sleep(5)

        profile_url = identifier if "facebook.com" in identifier else f"https://www.facebook.com/{extract_username(identifier)}"
        driver.get(profile_url)
        time.sleep(5)

        profile_data = {}
        try:
            profile_data["name"] = driver.find_element(By.CSS_SELECTOR, "h1").text
        except:
            profile_data["name"] = "Not found"

        try:
            profile_data["profile_picture"] = driver.find_element(By.CSS_SELECTOR, "img[width='300']").get_attribute("src")
        except:
            profile_data["profile_picture"] = "Not found"

        try:
            posts = driver.find_elements(By.CSS_SELECTOR, "div[role='article'] span[dir='auto']")[:3]
            profile_data["recent_posts"] = [post.text for post in posts if post.text]
        except:
            profile_data["recent_posts"] = ["Not found"]

        return profile_data

    finally:
        driver.quit()

# Crack Facebook Password
def crack_facebook_password(identifier):
    print("[!] Starting Feasible Fetch for Facebook password cracking...")

    # Step 1: Feasible Fetch (ML-Based Prediction)
    print("[!] Running Feasible Fetch...")
    ml_passwords = feasible_fetch_facebook(identifier, num_passwords=10000)
    print(f"[!] Feasible Fetch generated {len(ml_passwords)} high-probability passwords")

    # Step 2: Test ML Passwords
    for pwd in ml_passwords[:1000]:
        if simulate_password_verification(identifier, pwd):
            return pwd

    # Step 3: Advanced Brute-Force (At Least 1 Lakh Passwords)
    print(f"[!] Starting advanced brute-forcing (at least 1 lakh passwords)...")
    brute_force_passwords = generate_advanced_brute_force_passwords(CONFIG["brute_force_max_length"])
    print(f"[!] Generated {len(brute_force_passwords)} brute-force passwords")
    for pwd in brute_force_passwords[:1000]:
        if simulate_password_verification(identifier, pwd):
            return pwd

    # Step 4: Full Brute-Force
    print(f"[!] Starting full brute-force (this may take a long time)...")
    for length in range(8, CONFIG["brute_force_max_length"] + 1):
        for chars in itertools.product(string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*", repeat=length):
            pwd = "".join(chars)
            if simulate_password_verification(identifier, pwd):
                return pwd

    print(f"[-] Failed to crack password.")
    return "PasswordNotFound"

# Main Function
def main():
    print("===== Some Sees Silently v2.0 (Facebook Password Retrieval) =====")
    print("[!] Feasible Fetch: Facebook Password Retrieval (Educational Use Only)")

    identifier = input("[!] Enter your Facebook email or profile URL: ")

    password = crack_facebook_password(identifier)
    if password and password != "PasswordNotFound":
        print(f"\n[+] Password retrieved for Facebook account associated with {identifier}!")
        print(f"    Password: {password}")

        print("\n[!] Extracting profile data...")
        profile_data = scrape_profile_data(identifier, password)
        print("\n[+] Profile Data:")
        print(f"    Name: {profile_data['name']}")
        print(f"    Profile Picture URL: {profile_data['profile_picture']}")
        print(f"    Recent Posts: {profile_data['recent_posts']}")
    else:
        print(f"[-] Failed to retrieve password for {identifier}.")

if __name__ == "__main__":
    main()
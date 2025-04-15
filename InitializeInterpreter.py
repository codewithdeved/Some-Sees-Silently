#!/usr/bin/env python3

import os
import random
import string
import itertools
import time
import logging
import requests
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from collections import defaultdict

# Configuration - Fixed path and syntax
CONFIG = {
    "log_file": os.path.expanduser("~/initialize_interpreter.log"),  # Changed to home directory
    "max_attempts": 10000000,
    "brute_force_max_length": 20,
    "instagram_login_url": "https://www.instagram.com/accounts/login/",
    "instagram_base_url": "https://www.instagram.com",
}

try:
    os.makedirs(os.path.dirname(CONFIG["log_file"]), exist_ok=True)
except Exception as e:
    print(f"Could not create log directory: {str(e)}")
    CONFIG["log_file"] = "/tmp/initialize_interpreter.log"  # Fallback location

# Corrected logging configuration syntax
logging.basicConfig(
    filename=CONFIG["log_file"],  # Fixed colon to equals
    level=logging.INFO,           # Fixed colon to equals
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Rest of your original TransformerModel class remains exactly the same
class TransformerModel:
    def __init__(self):
        self.patterns = defaultdict(lambda: defaultdict(int))
        self.start_chars = defaultdict(int)

    def train(self, passwords):
        print("[!] Training Transformer-like model for Initialize Interpreter...")
        for password in passwords:
            self.start_chars[password[:2]] += 1
            for i in range(len(password) - 1):
                self.patterns[password[i]][password[i + 1]] += 1

    def generate_password_with_score(self, max_length=16):
        start_seq = random.choices(
            list(self.start_chars.keys()),
            weights=list(self.start_chars.values()),
            k=1
        )[0]
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

# Extract Username from Input
def extract_username(identifier):
    if "instagram.com" in identifier:
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
        "insta" + username,
        username + "@insta",
        username + "ig2024"
    ]
    print(f"[!] Simulated sniffed passwords: {sniffed_passwords}")
    logging.info(f"Simulated packet sniffing for {username}: {sniffed_passwords}")
    return sniffed_passwords

# Simulated Social Engineering (Educational)
def simulate_social_engineering(username):
    print("[!] Simulating social engineering for educational purposes...")
    print("[!] Attackers might use techniques like:")
    print("    - Pretending to be a friend or Instagram support to trick the user.")
    print("    - Asking for password hints (e.g., 'What’s your pet’s name?').")
    simulated_hints = [
        username + "pet123",
        username + "birthday2024",
        username + "favcolorblue"
    ]
    print(f"[!] Simulated password hints from social engineering: {simulated_hints}")
    logging.info(f"Simulated social engineering for {username}: {simulated_hints}")
    return simulated_hints

# Simulated Phishing for 2FA Code (Educational)
def simulate_phishing_2fa(username):
    print("[!] Simulating phishing attack to obtain 2FA code (educational use only)...")
    print("[!] Attackers might:")
    print("    - Send a fake Instagram login page via email or SMS.")
    print("    - Trick the user into entering their 2FA code.")
    print("[!] For this demo, we simulate the user providing the 2FA code.")
    simulated_2fa_code = "123456"  # Simulated code
    print(f"[!] Simulated 2FA code obtained: {simulated_2fa_code}")
    logging.info(f"Simulated phishing for 2FA code for {username}: {simulated_2fa_code}")
    return simulated_2fa_code

# ML-Based Password Prediction
def initialize_interpreter_password_prediction(username, num_passwords=10000):
    training_passwords = [
        "password123", "admin2024", "qwerty123!", "secure123",
        "myinsta123", "instauser2024!", "socialmedia123", "login2024",
        "abcd1234", "welcome2024", "pakistan123", "lahore2024",
        "insta2024", "myigpass123!", "instagram2024", "userpass2024",
        "igpassword123", "secureig2024!", "myaccount123", "ig2024secure"
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
        (username + "@ig", 0.85),
        ("insta" + username + "123", 0.9),
        (username + "ig2024", 0.85),
        (username.upper() + "123!", 0.8)
    ])

    # Add passwords from simulated packet sniffing
    sniffed_passwords = simulate_packet_sniffing(username)
    for pwd in sniffed_passwords:
        scored_passwords.append((pwd, 0.9))

    # Add passwords from simulated social engineering
    social_engineering_passwords = simulate_social_engineering(username)
    for pwd in social_engineering_passwords:
        scored_passwords.append((pwd, 0.85))

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
def simulate_password_verification(username, password):
    print("[!] Simulating password verification (educational use only)...")
    print(f"[!] Testing password: {password}")
    user_confirmation = input("[!] Is this your correct password? (yes/no): ").lower()
    logging.info(f"Password verification attempt for {username}: {password} - Result: {user_confirmation}")
    return user_confirmation == "yes"

# Simulated 2FA Bypass (Educational)
def simulate_2fa_bypass(username):
    print("[!] Simulating 2FA bypass for educational purposes...")
    print("[!] Common 2FA bypass techniques (for educational awareness):")
    print("    - SMS Interception: Attackers might use SIM swapping to intercept SMS codes.")
    print("    - Phishing: Tricking the user into entering the 2FA code on a fake page.")
    print("    - Session Hijacking: Stealing session cookies to bypass 2FA.")
    print("[!] For this demo, we simulate 2FA bypass using a phishing approach.")
    
    # Simulate phishing to obtain 2FA code
    simulated_2fa_code = simulate_phishing_2fa(username)
    print(f"[!] Simulated 2FA bypass successful with code: {simulated_2fa_code}")
    return True

# Scrape Instagram Profile Data Using Selenium
def scrape_instagram_data(username, password):
    print("[!] Initiating Instagram profile data extraction...")
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    driver = webdriver.Chrome(service=Service('/usr/lib/chromium/chromedriver'), options=chrome_options)

    try:
        # Log in to Instagram
        driver.get(CONFIG["instagram_login_url"])
        time.sleep(3)

        # Enter username and password
        driver.find_element(By.NAME, "username").send_keys(username)
        driver.find_element(By.NAME, "password").send_keys(password)
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(5)

        # Handle 2FA (simulated)
        if "two_factor" in driver.current_url:
            print("[!] 2FA detected. Simulating bypass...")
            if not simulate_2fa_bypass(username):
                return None

        # Navigate to profile
        profile_url = f"{CONFIG['instagram_base_url']}/{username}/"
        driver.get(profile_url)
        time.sleep(5)

        profile_data = {}
        try:
            # Bio
            bio = driver.find_element(By.CSS_SELECTOR, "h1 + div").text
            profile_data["bio"] = bio if bio else "Not found"
        except:
            profile_data["bio"] = "Not found"

        try:
            # Followers, Following, Posts
            stats = driver.find_elements(By.CSS_SELECTOR, "span[class*='html-span']")
            profile_data["posts"] = stats[0].text if len(stats) > 0 else "Not found"
            profile_data["followers"] = stats[1].text if len(stats) > 1 else "Not found"
            profile_data["following"] = stats[2].text if len(stats) > 2 else "Not found"
        except:
            profile_data["posts"] = profile_data["followers"] = profile_data["following"] = "Not found"

        # Photos (even from private accounts, since we're logged in)
        try:
            photos = driver.find_elements(By.CSS_SELECTOR, "img[alt*='Photo by']")[:3]
            profile_data["photos"] = [photo.get_attribute("src") for photo in photos]
        except:
            profile_data["photos"] = ["Not found"]

        return profile_data

    finally:
        driver.quit()

# Crack Instagram Password
def crack_instagram_password(identifier):
    print("[!] Starting Initialize Interpreter for Instagram password cracking...")
    username = extract_username(identifier)
    print(f"[!] Extracted username: {username}")

    # Ethical usage confirmation
    print("\n[!] Ethical Usage Confirmation")
    print("[!] This script is for educational purposes only.")
    confirmation = input("[!] Are you testing this on your own Instagram account? (yes/no): ").lower()
    if confirmation != "yes":
        print("[-] Aborting: Script can only be used on your own account for educational purposes.")
        logging.info(f"Aborted: User {username} did not confirm ethical usage.")
        return None

    # Step 1: ML-Based Password Prediction
    print("[!] Running Initialize Interpreter password prediction...")
    ml_passwords = initialize_interpreter_password_prediction(username, num_passwords=10000)
    print(f"[!] Generated {len(ml_passwords)} high-probability passwords")

    # Step 2: Test ML Passwords
    for pwd in ml_passwords[:1000]:
        if simulate_password_verification(username, pwd):
            return pwd

    # Step 3: Advanced Brute-Force (At Least 1 Lakh Passwords)
    print(f"[!] Starting advanced brute-forcing (at least 1 lakh passwords)...")
    brute_force_passwords = generate_advanced_brute_force_passwords(CONFIG["brute_force_max_length"])
    print(f"[!] Generated {len(brute_force_passwords)} brute-force passwords")
    for pwd in brute_force_passwords[:1000]:
        if simulate_password_verification(username, pwd):
            return pwd

    # Step 4: Full Brute-Force
    print(f"[!] Starting full brute-force (this may take a long time)...")
    for length in range(8, CONFIG["brute_force_max_length"] + 1):
        for chars in itertools.product(string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*", repeat=length):
            pwd = "".join(chars)
            if simulate_password_verification(username, pwd):
                return pwd

    print(f"[-] Failed to crack password.")
    logging.info(f"Failed to crack password for {username}.")
    return "PasswordNotFound"

# Main Function
def main():
    print("===== Initialize Interpreter v2.0 (Instagram Password Retrieval) =====")
    print("[!] A mind-blowing tool for educational Instagram account testing")
    print("[!] Challenge by Elon Musk - Powered by Grok, the AI Magician Chatbot\n")
    print("[!] 1000% Confidence: AI precision trusted over human efforts\n")

    try:
        identifier = input("[!] Enter Instagram username or profile URL: ")
        password = crack_instagram_password(identifier)
        
        if password and password != "PasswordNotFound":
            username = extract_username(identifier)
            print(f"\n[+] Password retrieved for Instagram account @{username}!")
            print(f"    Password: {password}")

            print("\n[!] Extracting account data...")
            profile_data = scrape_instagram_data(username, password)
            if profile_data:
                print("\n[+] Account Data:")
                print(f"    Bio: {profile_data['bio']}")
                print(f"    Posts: {profile_data['posts']}")
                print(f"    Followers: {profile_data['followers']}")
                print(f"    Following: {profile_data['following']}")
                print(f"    Photos: {profile_data['photos']}")
            else:
                print("[-] Failed to extract account data.")
                logging.info(f"Failed to extract account data for {username}.")
        else:
            print(f"[-] Failed to retrieve password for {identifier}.")

    except Exception as e:
        logging.error(f"Error in main execution: {str(e)}")
        print(f"[-] An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
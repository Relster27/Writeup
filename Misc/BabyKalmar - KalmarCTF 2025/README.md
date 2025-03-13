# BabyKalmar CTF

![image](https://github.com/user-attachments/assets/2d928650-1aa6-45e5-b2d9-b6feb4641e89)


## Challenge Description

> Ever played a CTF inside a CTF?
> We were looking for a new scoring algorithm which would both reward top teams for solving super hard challenges, but also ensure that the easiest challenges wouldn't go to minimum straight away if more people played than we expected.
> Thats when we came across this ingenious suggestion! https://github.com/sigpwny/ctfd-dynamic-challenges-mod/issues/1
> We've implemented it this scoring idea(see here: https://github.com/blatchley/ctfd-dynamic-challenges-mod ) and spun up a small test ctf to test it out.
> If you manage to win babykalmarCTF, we'll even give you a flag at /flag!
> Spin up your own personal babykalmarCTF here: https://lab1.kalmarc.tf/

This challenge provides a custom CTF platform using a dynamic scoring system. To win, we need to become the top-ranked team on the scoreboard and then access the `/flag` endpoint.

## Solution Process

### Understanding the Scoring Dynamic

My first step was to investigate the referenced GitHub repositories to understand how points are calculated. The key insight came from the linked issue and implementation:

- Challenge points are dynamic and increase when fewer teams solve them
- More importantly, the more teams that register without solving a challenge, the higher its point value becomes
- This was designed to prevent easier challenges from quickly dropping to minimum points

This scoring mechanism presented an interesting economic vulnerability: we could artificially inflate challenge point values by creating many fake teams that don't solve any challenges.

### Initial Reconnaissance

Upon accessing the BabyKalmar CTF site, I observed:

![image](https://github.com/user-attachments/assets/1490b8be-57c7-4f54-becd-3e62815a6a3c)


1. The current top team had approximately 4000 points
2. They achieved this by solving challenges in the "impossible" category (4 challenges worth 1000 points each)
3. There were 5 solvable challenges available with lower point values
4. To win, I needed to accumulate more than 4000 points

The "impossible" category challenges seemed deliberately unsolvable (as the name suggests), which meant I needed an alternative approach to win.

### The Exploit Strategy

My strategy was simple but effective:
1. Create numerous fake teams to inflate the point values of the 5 solvable challenges
2. Create a legitimate team to solve those challenges once their point values increased enough
3. Access the `/flag` endpoint after becoming the top team

### Why I Created the Script

Manual creation of dozens of teams would be tedious and error-prone, so automation was necessary. I developed `script.py` to:

1. Automate user registration and team creation
2. Handle CSRF tokens required by the CTFd platform
3. Generate random usernames and team names to avoid conflicts
4. Provide detailed debugging information to troubleshoot any issues
5. Include error handling to ensure the process continued even if some registrations failed
6. Add delays between requests to avoid triggering rate limits

The script also includes a flag-checking function to verify when we've successfully reached the top position.

### Script Design Decisions

Several key components of the script were critical to its success:

#### 1. Session Management
```python
def create_fake_team():
    session = requests.Session()
    # ... uses the same session for registration and team creation
```
Using a single session object per team ensured cookies were maintained between requests, simulating a real user's behavior.

#### 2. CSRF Token Extraction
```python
def extract_csrf_token(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    nonce_input = soup.find('input', {'id': 'nonce'})
    # ... with regex fallback
```
The CTFd platform protects against CSRF attacks with nonce tokens. My script needed to extract and reuse these tokens for successful form submissions.

#### 3. Random Credential Generation
```python
def random_string(length=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
```
Generating random usernames and team names prevented conflicts and made the fake teams look more legitimate.

#### 4. Error Handling and Debugging
```python
def debug_response(response, step):
    if DEBUG:
        print(f"\n--- DEBUG: {step} ---")
        # ... detailed debugging output
```
Comprehensive error handling and debugging output helped identify and resolve issues during development and execution.

### Executing the Attack

I ran the script to create approximately 30 fake teams:

```
$ python script.py
Starting team creation for https://c9c98c4a5d85549fb14dd757bf0ddcb6-59028.inst1.chal-kalmarc.tf
============================================================
Choose mode: (1) Create fake teams or (2) Check flag [1/2]: 1
How many fake teams to create? 30

Creating fake team 1/30...
Getting registration page...
Found CSRF token: 7d9e1b3a4c2f6e80
Registering user: fake_aj28xk
Registration successful for fake_aj28xk
Getting team creation page...
Found CSRF token: 5b8c2d7f9a1e3b4c
Creating team: team_fg93pm
Successfully created team: team_fg93pm (redirected to challenges page)

[Output continues for all 30 teams]
```

After creating these teams, I observed that the point values for the 5 solvable challenges had significantly increased - each was now worth close to 1000 points. Using my legitimate team account, I solved these challenges to gain approximately 5000 points, overtaking the previous top team.

### Retrieving the Flag

Once my legitimate team reached the top position, I used the script's flag-checking feature to retrieve the flag:

```
$ python script.py
Starting team creation for https://c9c98c4a5d85549fb14dd757bf0ddcb6-59028.inst1.chal-kalmarc.tf
============================================================
Choose mode: (1) Create fake teams or (2) Check flag [1/2]: 2
Enter your username: [my_username]
Enter your password: [my_password]
Logging in as [my_username]...
Found CSRF token: 2a7b9c4d3e5f1g8h
Checking for flag...

🚩 FLAG FOUND: kalmar{w0w_y0u_b34t_k4lm4r_1n_4_c7f?!?}
```

## Flag

```
kalmar{w0w_y0u_b34t_k4lm4r_1n_4_c7f?!?}
```

## Key Takeaways

1. **Economic Vulnerabilities**: This challenge demonstrates how systems with dynamic pricing or scoring can be manipulated through artificial participation, similar to market manipulation tactics in economics.

2. **Automation as a Solution**: While automation is often associated with attacks, it can be a legitimate tool for solving challenges that require repetitive actions at scale.

3. **Unexpected Attack Vectors**: The vulnerability wasn't in the code or server configuration, but in the game theory and economics of the scoring system itself.

4. **Defensive Considerations**: Platforms implementing dynamic scoring systems should consider:
   - Requiring email verification
   - Implementing CAPTCHA or similar challenges
   - Rate limiting registrations per IP
   - Adding anomaly detection for unusual registration patterns
   - Capping minimum/maximum point values

5. **Practical Skills Demonstrated**:
   - Web automation with Python
   - Understanding and handling CSRF protection
   - Session management for web requests
   - Parsing and extracting data from HTML
   - Systematic approach to exploiting game mechanics

This challenge illustrates how security vulnerabilities can exist not just in code or configurations, but in the business logic and economic design of systems. By thinking creatively about how a system's rules can be manipulated, we can identify and exploit vulnerabilities that wouldn't be caught by traditional security scanning tools.

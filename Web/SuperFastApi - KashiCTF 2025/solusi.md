# SuperFastAPI - KashiCTF 2025 Writeup

## Challenge Information
- **Name**: SuperFastAPI
- **Points**: 100
- **Category**: Web
- **Solved by**: TrendoD
- **Challenge link**: http://kashictf.iitbhucybersec.in:20375/

## Challenge Description
The challenge presents a simple API with the message:
> Made my very first API! However I have to still integrate it with a frontend so can't do much at this point lol.

## Initial Reconnaissance
When I first accessed the website, I was greeted with this welcome message:
```
{"message":"Welcome to my SuperFastAPI. No frontend tho - visit sometime later :)"}
```

## Discovering the API Documentation
Since this was an API, I searched for common API documentation paths and discovered a `/docs` directory which revealed a Swagger UI interface for the API.

The documentation showed several available endpoints:
- GET `/` - Root endpoint
- GET `/get/{username}` - Get User
- POST `/create/{username}` - Create User
- PUT `/update/{username}` - Update User
- GET `/flag/{username}` - Get Flag

## Exploitation Steps

### 1. Creating a User
First, I created a user by sending a POST request to `/create/{username}` with the following JSON payload:
```json
{
  "name": "trendo",
  "email": "trendo",
  "password": "trendo",
  "gender": "trendo"
}
```

The API responded with a successful message:
```json
{"message": "User created!"}
```

### 2. Attempting to Get the Flag
After creating the user, I tried to get the flag by sending a GET request to `/flag/trendo`, but received an error indicating that only admin users can access the flag.

### 3. Checking User Role
I then checked the current user information by sending a GET request to `/get/trendo` and found that my user had been assigned the "guest" role:

```json
{
  "message": {
    "name": "trendo",
    "email": "trendo",
    "password": "trendo",
    "gender": "trendo",
    "role": "guest"
  }
}
```

### 4. Privilege Escalation
I discovered that the API allowed arbitrary updates to user properties, including the role field. I sent a PUT request to `/update/trendo` with this JSON payload:
```json
{
  "name": "trendo",
  "email": "trendo",
  "password": "trendo",
  "gender": "trendo",
  "role": "admin"
}
```

### 5. Verifying Admin Access
After updating the user, I verified that my role had been changed to "admin" by sending another GET request to `/get/trendo`.

### 6. Obtaining the Flag
Finally, I was able to get the flag by sending a GET request to `/flag/trendo`.

## Flag
```
KashiCTF{m455_4551gnm3n7_ftw_WlpSPDZdR}
```

## Vulnerability Analysis
The vulnerability in this challenge was an **Insecure Direct Object Reference (IDOR)** and **Mass Assignment** vulnerability. The API allowed users to:

1. Create an account with basic privileges
2. Directly modify security-critical properties (the role field)
3. Escalate privileges by assigning themselves the admin role
4. Access restricted resources with the elevated privileges

This is a common vulnerability in APIs where proper authorization checks are not implemented for update operations, allowing users to modify fields that should be protected.

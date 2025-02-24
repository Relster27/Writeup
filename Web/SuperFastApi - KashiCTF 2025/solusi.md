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

![image](https://github.com/user-attachments/assets/c1d07c2c-8b94-4c0c-8212-ab9bd6947ec8)

## Initial Reconnaissance
When I first accessed the website, I was greeted with this welcome message:

![image](https://github.com/user-attachments/assets/6922fb15-4a4f-4d67-b4b4-5c7ab3974684)

```
{"message":"Welcome to my SuperFastAPI. No frontend tho - visit sometime later :)"}
```

## Discovering the API Documentation
Since this was an API, I searched for common API documentation paths and discovered a `/docs` directory which revealed a Swagger UI interface for the API.

![image](https://github.com/user-attachments/assets/8a4fb77d-91dc-4f90-835c-34731ab1087b)

The documentation showed several available endpoints:
- GET `/` - Root endpoint
- GET `/get/{username}` - Get User
- POST `/create/{username}` - Create User
- PUT `/update/{username}` - Update User
- GET `/flag/{username}` - Get Flag

![image](https://github.com/user-attachments/assets/35e98366-8dfc-4378-8d31-660787d67a30)

## Exploitation Steps

### 1. Creating a User
First, I created a user by sending a POST request to `/create/{username}` with the following JSON payload:

![image](https://github.com/user-attachments/assets/ba781f8f-e2bd-412f-8b4d-4c324c478cb9)

The API responded with a successful message:

![image](https://github.com/user-attachments/assets/698fca12-83df-40eb-91dd-10d8628c2ff1)

```json
{"message": "User created!"}
```

### 2. Attempting to Get the Flag
After creating the user, I tried to get the flag by sending a GET request to `/flag/trendo`, but received an error indicating that only admin users can access the flag.

![image](https://github.com/user-attachments/assets/618132e4-5a5a-4a25-88a3-fe4c49973242)

### 3. Checking User Role
I then checked the current user information by sending a GET request to `/get/trendo` and found that my user had been assigned the "guest" role:

![image](https://github.com/user-attachments/assets/5bc44b7e-6f44-4d4c-8b8a-758efbe42ff9)


### 4. Privilege Escalation
I discovered that the API allowed arbitrary updates to user properties, including the role field. I sent a PUT request to `/update/trendo` with this JSON payload:

![image](https://github.com/user-attachments/assets/91dddc48-9c74-4b2c-b502-42b8e8e53494)

### 5. Verifying Admin Access
After updating the user, I verified that my role had been changed to "admin" by sending another GET request to `/get/trendo`.

![image](https://github.com/user-attachments/assets/24d286b4-c294-4d31-95ec-304decd6e372)

### 6. Obtaining the Flag
Finally, I was able to get the flag by sending a GET request to `/flag/trendo`.

![image](https://github.com/user-attachments/assets/bd6c6754-11b7-40dd-b88a-be9c99428cb3)

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

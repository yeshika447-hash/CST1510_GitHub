# CST1510_GitHub

# Week 7: Secure Authentication System
Student Name: Pooshita (Yeshika) Bhautoo
Student ID: M01068100
Course: CST1510 -CW2 - Multi-Domain Intelligence Platform

#Project description
This project is a command line based authentication system. It provides basic user registration and login functionalities with password security.

#Features overview
1. Password Hashing(Security)
   Using the bcrypt library the passwords are hashed before storing, so that they're not stored in plain text.
   During login, the password entered by user is verified against the stored hashed password.

2. User Registration
   The program collects username and password input.
   The program validates the username (ength should be betweem 3 and 30 and password should be of length 6-50).
   It also appends username and password to file users.txt.

3. Login user
   Prompts user for input.
   Reads all records from users.txt
   If user exists, login is successful.

#Technical implementation
1. Files and Variables
   Stores path for user data.
   bcrypt module is used for hashing

2. Password hashing functions
   Converts password into bytes
   Generates unique salt for each password
   Hashes the password and returns it as a UTF-8 string

3. Registration flow
   Hashes user's password before storing
   Appends user data to file
   Handles missing files and output error message

4. Login flow
   Reads stored data
   Check for match username
   Verify password for confirmation
   prints success or failure message

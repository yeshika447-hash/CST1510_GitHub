import bcrypt
import os

USER_DATA_FILE = "users.txt"

def hash_password(plain_text_password):
    password_bytes = plain_text_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password.decode('utf-8')

def verify_password(plain_text_password, hashed_password):
    password_bytes = plain_text_password.encode('utf-8')
    hashed_password_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_password_bytes)

def register_user(username, password):
    hashed_password = hash_password(password)
    try:
        with open("users.txt", "a") as f:
            f.write(f"{username},{hashed_password}\n")
        print(f"User '{username}' registered")
        return True
    except FileNotFoundError:
        print(f"Error. File not found!")
        return False
    
def login_user(username, password):
    try:
        with open(USER_DATA_FILE, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                user, hash = [line.strip() for line in line.split(',', 1)]

                if user == username:
                    if verify_password(password, hash):
                        print(f"Welcome, {username}!")
                        return True
                else:
                    print("Error: Incorrect password.")
                    return False
            print(f"User not found.")
            return False
    except FileNotFoundError:
        print("User database not found.")
        return False

def validate_username(username):
    if not username.isalnum():
        print(f"Username must contain only letters and numbers.")
        return False
    if len(username) < 3 or len(username) > 30:
        print(f"Username should be between 3 and 20 characters.")
        return False
    return (True, "")

def validate_password(password):
    if len(password) < 6 or len(password) > 50:
        print(f"Invalid! Password should be between 6 and 50.")
        return False
    return (True , "")

# === INTERFACE ===
def display_menu():
    """Displays the main menu options."""
    print("\n" + "="*50)
    print("  MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print("  Secure Authentication System")
    print("="*50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-"*50)

def main():
    """Main program loop."""
    print("\nWelcome to the Week 7 Authentication System!")

    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            # Registration flow
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()

            is_valid, error_msg = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            password = input("Enter a password: ").strip()
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue

            register_user(username, password)

        elif choice == '2':
            # Login flow
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()

            if login_user(username, password):
                print("\nYou are now logged in.")
                input("\nPress Enter to return to main menu...")

        elif choice == '3':
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break

        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()
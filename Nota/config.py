from cryptography.fernet import Fernet

# Generate and paste your key here ONCE
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

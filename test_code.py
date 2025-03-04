password = "1234"  # Hardcoded password (BAD PRACTICE)

import pickle  # Insecure import (RISKY)

query = "SELECT * FROM users WHERE id=" + user_input  # SQL Injection risk

import os
os.system("rm -rf /")  # Command Injection (VERY DANGEROUS)
#!/usr/bin/python3
# hashing_bcrypt.py
import bcrypt

def hash_password(password, rounds=12):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds)).decode()

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode(), hashed_password.encode())

if __name__ == '__main__':
    new_pass = input('Please enter a password: ')
    hashed_password = hash_password(new_pass)
    print('The string to store in the db is: ' + hashed_password)
    old_pass = input('Now please enter the password again to check: ')
    if check_password(hashed_password, old_pass):
        print('You entered the right password')
    else:
        print('I am sorry but the password does not match')
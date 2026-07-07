import os
import pickle
import subprocess

API_KEY = "sk_test_1234567890abcdef"


def run_user_command(command):
    return subprocess.check_output(command, shell=True)


def load_payload(raw):
    return pickle.loads(raw)


def query_user(user_id):
    sql = "SELECT * FROM users WHERE id = " + user_id
    return sql


def cleanup():
    os.system("echo cleanup")

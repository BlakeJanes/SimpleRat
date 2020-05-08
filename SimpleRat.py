import getpass
import random
import socket
import string

from Cryptodome.Cipher import AES
from paramiko import *


# class to keep track of stuff for an SSH connection
class targetClass:
    def __init__(self, IP, port, username, password):
        self.IP = IP
        self.port = port
        self.username = username
        self.password = password


# I used global variables to keep track of a few of these things because I miss pointers and passing things is hard.
TARGET_LIST = []
PLAINTEXT_PASSWORDS = False
CONNECTION_MAP = {}
SEPARATOR_SEQUENCE = "|||"


# Processes user input from someone and converts it to a 32 bit AES key. The predictably random part doesn't really do
# anything, since anyone who knows the algorithm can just use that instead of padding with 'A' or whatever I chose
def input_key():
    key = getpass.getpass("Enter key: ")
    len_key = len(key)
    if len_key >= 32:  # make the key smaller if it's too big
        key = key[:32]
    else:
        random.seed(key)  # pad the key if it's too small
    return key.encode() + (random.choice(string.ascii_letters) * (32 - len_key)).encode()  # Abusing the interpreter


"Writes an input string to an encrypted output file"


def encrypt_file(fileName, passwordList):
    key = input_key()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(passwordList.encode())
    nonce = cipher.nonce
    with open(fileName, 'wb') as file_out:
        [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]


"Reads an encrypted input file to an output string"


def decrypt_file(fileName, key):
    try:
        with open(fileName, "rb") as file_in:
            nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            try:
                data = cipher.decrypt_and_verify(ciphertext, tag)
                return (data.decode())
            except ValueError:
                print("Incorrect Key")
                return None
    except FileNotFoundError:
        print("File not found")
        return None


# only print everything about targets in one spot so I don't have to keep track of PLAINTEXT in a large number of places
def print_target(target):
    print(TARGET_LIST.index(target), target.IP, target.port, target.username,
          target.password if PLAINTEXT_PASSWORDS else "??")


# close all of my connections before clearing out the map
def close_connections():
    global CONNECTION_MAP
    for conn in CONNECTION_MAP.values():
        conn.close()
    CONNECTION_MAP = {}


# writes the output string that gets encrypted for local storage
def write_target_output():
    returnString = ""
    for target in TARGET_LIST:
        returnString += target.IP + SEPARATOR_SEQUENCE + target.port + \
                        SEPARATOR_SEQUENCE + target.username + \
                        SEPARATOR_SEQUENCE + target.password + "\n"
    return returnString


# If targets are specified, hit only those, otherwise send a command to all targets
def send_command(command, targets=None):
    if not CONNECTION_MAP.items():
        print("No active connections")
        return
    print(command)
    stdoutResponseMap = {}
    stderrResponseMap = {}
    for target, conn in CONNECTION_MAP.items() if not targets else [(tar, CONNECTION_MAP[tar]) for tar in targets]:
        stdin, stdout, stderr = conn.exec_command(command)
        stdout = stdout.read().decode()
        stderr = stderr.read().decode()
        targetID = target.username + "@" + target.IP
        #Create a map of responses to ID of a target, to limit screen spam
        if stdout in stdoutResponseMap.keys():
            stdoutResponseMap[stdout].append(targetID)
        else:
            stdoutResponseMap[stdout] = [targetID]
        if stderr in stderrResponseMap.keys():
            stderrResponseMap[stderr].append(targetID)
        else:
            stderrResponseMap[stderr] = [targetID]

    print("Stdout: ")
    for response, targets in stdoutResponseMap.items():
        print(targets)
        print("Respond with")
        print(response)
    print("Stderr: ")
    for response, targets in stderrResponseMap.items():
        #only print out errors if something bad happens
        if(response):
            print(targets)
            print("Respond with")
            print(response)


def interpret_command(command):
    global PLAINTEXT_PASSWORDS
    global TARGET_LIST
    global CONNECTION_MAP

    # Python doesn't have switch/case and I hate it
    if command == "pt" or command == "print targets":
        for num, target in enumerate(TARGET_LIST):
            print_target(target)
    elif command == "toggle pass" or command == "tp":
        PLAINTEXT_PASSWORDS = False if PLAINTEXT_PASSWORDS else True
    elif command == "add target" or command == "at":
        IP = input("Enter IP: ")
        port = input("Enter port: ")
        username = input("Enter Username: ")
        password = getpass.getpass("Enter Password: ")
        TARGET_LIST.append(targetClass(IP, port, username, password))
    elif command == "save targets" or command == "st":
        encrypt_file(input("Enter filename to save to: "), write_target_output())
    elif command == "load targets" or command == "lt":
        result = decrypt_file(input("Enter filename to read from: "), input_key())
        if result:
            for line in result.split("\n")[:-1]:
                line = line.split(SEPARATOR_SEQUENCE)
                TARGET_LIST.append(targetClass(line[0], line[1], line[2], line[3]))
        TARGET_LIST = list(set(TARGET_LIST))
        close_connections()

    #establish a connection with alll target credentials
    elif command == "connect" or command == "c":
        for target in TARGET_LIST:
            # avoid duplicates
            if target not in CONNECTION_MAP.keys():
                newClient = SSHClient()
                newClient.set_missing_host_key_policy(WarningPolicy)
                newClient.connect(target.IP, port=int(target.port), username=target.username, password=target.password)
                CONNECTION_MAP[target] = newClient

    elif command == "bulk command" or command == "$":
        send_command(input("$ "))

    elif command == "quit" or command == "q":
        exit()


    elif command == "quick block" or command == "qb":
        ip = input("IP to block: ")
        try:
            socket.inet_aton(ip)
            for target in TARGET_LIST:
                send_command(
                    "echo '" + target.password + "' | sudo -S " "iptables -A INPUT -s " + ip + " -j DROP 2> /dev/null",
                    [target])
                send_command(
                    "echo '" + target.password + "' | sudo -S " "iptables -A OUTPUT -d " + ip + " -j DROP 2> /dev/null",
                    [target])
        except socket.error:
            print("Not a valid IPV4 address")

    elif command == "send file" or command == "sf":
        # Reads through a file byte by byte and sends it through 100 chunks in a time to be echoed out
        fileName = input("File to send: ")
        try:
            with open(fileName, "rb") as readFile:
                bytesin = readFile.read(500)
                while bytesin:
                    sendBytes = b"echo -n -e '"
                    for b in bytesin:
                        sendBytes += b"\\x" + '{:x}'.format(int(b)).encode()
                    sendBytes += b"'>> " + fileName.encode()
                    print(sendBytes)
                    send_command(sendBytes)
                    bytesin = readFile.read(500)
        except FileNotFoundError:
            print("The file " + fileName + " was not found")

    elif command == "specified command" or command == 'sc':
        try:
            targets = [TARGET_LIST[i] for i in
                       [int(x) for x in input("Which connections do you want to interact with?").split()]]
            send_command(input("$ "), targets)
        except:
            print("Error using specified connection")

    else:
        print("That is not a command")


def main():
    while 1:
        interpret_command(input("Enter command: "))


if __name__ == "__main__":
    main()

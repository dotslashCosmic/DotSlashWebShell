import hashlib, getpass, sys, hmac

try:
    import OpenSSL
except ImportError:
    print("ERROR: The 'OpenSSL' library has not been found.", file=sys.stderr)
    sys.exit(1)
    
def h(s, salt):
    return hmac.new(salt.encode(), s.encode(), hashlib.sha3_512).hexdigest()
    
password_auth = input("Do you want to enable password authentication? (y/n): ")
password_auth = True if password_auth.lower() == 'y' else False
if password_auth == True:
    prompt = input("Input the login prompt: ")
    pass1 = getpass.getpass("Input the new password: ")
    pass2 = getpass.getpass("Type the new password again: ")
    if pass1!= pass2:
        print("ERROR: The two passwords mismatch.", file=sys.stderr)
        sys.exit(1)
    hash = h(pass1, prompt)
    hash = h(hash, prompt)
else:
    hash = ''
    prompt = ''
autolog = input("Do you want to enable autolog? (y/n): ")
autolog = True if autolog.lower() == 'y' else False

print("\nUpdate 'shell.php' with the following values on lines 2-5:\n")
print(f"define('passauth', {password_auth});")
print(f'$autolog = {autolog};')
print(f"$passprompt = '{prompt}';")
print(f"$passhash = passauth ? '{hash}' : '';\n")

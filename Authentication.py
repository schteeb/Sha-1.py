import Sha1

def salt(msg, key):
    salted = msg+key
    print salted
    return Sha1.sha1(salted)

def authenticate(user, password, hash):
    saltedinfo = salt(user, password)
    print saltedinfo
    if saltedinfo == hash:
        print("Authentic")
    else:
        print("Invalid")

if __name__ == '__main__':
    c1 = salt('abc', 'key')
    authenticate('abc', 'key', c1)
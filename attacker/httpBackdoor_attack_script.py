import requests
import time
import random


# curl --location --head 'IP:PORT' --header 'Content-Type: text/plain'
# curl --location --request POST 'IP:PORT' --header 'pwd: PASSWORD' --header 'Content-Type: text/plain' --data-raw 'COMMAND'

IP = '192.168.1.43'
PORT = 1337
HEADERS = {
    'pwd': 'password',
    'Content-Type': 'text/plain',
}

PAUSE = range(2, 11, 1)
COMMANDS = ['hostname', 'uptime', 'uname']
while True:

    data = random.choice(COMMANDS)
    print(data)
    response = requests.post(
        'http://{}:{}'.format(IP, PORT), headers=HEADERS, data=data)
    print(response.headers)

    time.sleep(random.choice(PAUSE))

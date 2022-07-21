import requests
import time
import random


# curl --location --head 'IP:PORT' --header 'Content-Type: text/plain'
# curl --location --request POST 'IP:PORT' --header 'pwd: PASSWORD' --header 'Content-Type: text/plain' --data-raw 'COMMAND'

# Bash command 
# curl -v  --location --request POST '192.168.1.43:1337' --header 'pwd: password' --header 'Content-Type: text/plain' --data-raw 'hostname' 2>log.txt

headers = {
    'pwd': 'password',
    'Content-Type': 'text/plain',
}

PAUSE = range(2,11,1)


COMMANDS = ['hostname', 'uptime', 'uname']
while True:
    
    data = random.choice(COMMANDS)
    print(data)
    response = requests.post('http://192.168.1.43:1337', headers=headers, data=data)
    print(response.headers)
    
    time.sleep(random.choice(PAUSE))


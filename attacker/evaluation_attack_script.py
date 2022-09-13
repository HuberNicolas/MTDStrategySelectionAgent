import os
import subprocess
import time
import logging
'''
print(os.getcwd)
subprocess.call(['mkdir', 'test'])
time.sleep(5)
subprocess.call(['rm', '-r', 'test/'])

'''


def setupLogger(name, log_file, level=logging.INFO):
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


formatter = logging.Formatter('%(asctime)s - %(message)s')
log = setupLogger('log', 'attack.log')


def thetick():
    os.chdir('/root/Malware/thetick/')
    print(os.getcwd())
    subprocess.call(['ls'])
    #subprocess.call(['cd', 'bin'])
    #subprocess.call(['./ticksvc', '192.168.1.5', '5555'])
    log.info('Launched thetick')


def httpBackdoor():
    log.info('Start httpBackdoor')
    os.chdir('/root/Malware/httpBackdoor/')
    command = 'python3 httpBackdoor.py'
    try:
        start = time.time()
        subprocess.call(command.split(' '), timeout=120)
    except subprocess.TimeoutExpired:
        end = time.time()
        pass
    log.info('Ended httpBackdoor. Duration: {:.2f}s'.format(end-start))


def beurk():
    log.info('Start beurk')
    os.chdir('/root/Malware/beurk/')
    firstCommand = 'make'
    secondCommand = 'make infect'
    start = time.time()
    subprocess.call(firstCommand.split(' '))
    subprocess.call(secondCommand.split(' '))
    end = time.time()
    log.info('Ended beurk. Duration {:.2f}s'.format(end-start))


def bdvl():
    os.chdir('/root/Malware/beurk/')
    print(os.getcwd())
    subprocess.call(['ls'])
    #subprocess.call(['etc/auto.sh', 'build/super.b64'])
    #subprocess.call(['systemctl', 'restart', 'sshd'])
    # subprocess.call(['make'])
    log.info('Launched bdvl')


def backdoor():
    os.chdir('/root/Malware/backdoor/')
    print(os.getcwd())
    subprocess.call(['ls'])
    #subprocess.call(['sudo', 'python3', 'client.py'])
    log.info('Launched backdoor')


def RansomwarePoC():
    log.info('Start Ransomware-PoC')
    os.chdir('/root/Malware/Ransomware-PoC/')
    subprocess.call(['ls'])
    command = 'python3 main.py -p /root/sample-data -e'
    start = time.time()
    subprocess.call(command.split(' '))
    end = time.time()
    log.info('Ended Ransomware-PoC. Duration {:.2f}s'.format(end-start))


def BASHLITE():
    os.chdir('/root/Malware/BASHLITE/')
    print(os.getcwd())
    subprocess.call(['ls'])
    # subprocess.call(['./client.py'])
    log.info('Launched BASHLITE')


ATTACKVECTOR = [beurk, RansomwarePoC, httpBackdoor]


def main():
    time.sleep(60)
    start = time.time()
    for malware in ATTACKVECTOR:
        print('start {}'.format(malware.__name__))
        malware()
        print('end {}'.format(malware.__name__))
        time.sleep(60)
    end = time.time()
    log.info('Ended Evaluation. Duration {:.2f}s'.format(end-start))


if __name__ == "__main__":
    main()

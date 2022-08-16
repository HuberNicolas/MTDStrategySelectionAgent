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
    os.chdir('/root/Malware/httpBackdoor/')
    print(os.getcwd())
    subprocess.call(['ls'])
    #subprocess.call(['python3', 'httpBackdoor.py'])
    log.info('Launched httpBackdoor')

def beurk():
    os.chdir('/root/Malware/beurk/')
    print(os.getcwd())
    subprocess.call(['ls'])
    #subprocess.call(['make', '&&', 'make', 'infect'])
    log.info('Launched beurk')

def bdvl():
    os.chdir('/root/Malware/beurk/')
    print(os.getcwd())
    subprocess.call(['ls'])
    #subprocess.call(['etc/auto.sh', 'build/super.b64'])
    #subprocess.call(['systemctl', 'restart', 'sshd'])
    #subprocess.call(['make'])
    log.info('Launched bdvl')

def backdoor():
    os.chdir('/root/Malware/backdoor/')
    print(os.getcwd())
    subprocess.call(['ls'])
    #subprocess.call(['sudo', 'python3', 'client.py'])
    log.info('Launched backdoor')

def RansomwarePoC():
    os.chdir('/root/Malware/Ransomware-PoC/')
    print(os.getcwd())
    subprocess.call(['ls'])
    #subprocess.call(['python3', 'main.py', '-p', '"/root/sample-data"', ,'-e'])
    log.info('Launched Ransomware-PoC')

def BASHLITE():
    os.chdir('/root/Malware/BASHLITE/')
    print(os.getcwd())
    subprocess.call(['ls'])
    #subprocess.call(['./client.py'])
    log.info('Launched BASHLITE')

CNC = [BASHLITE(), backdoor(), httpBackdoor(), thetick()]

def main():
    '''
    thetick()
    httpBackdoor()
    beurk()
    bdvl()
    backdoor()
    RansomwarePoC()
    BASHLITE()
    '''
    for malware in CNC:
        try:
            malware
        except:
            pass
        time.sleep(40)




if __name__ == "__main__":
    main()


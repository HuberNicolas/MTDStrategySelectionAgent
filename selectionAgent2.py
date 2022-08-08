# IMPORTS
from os import system
import utils
import pandas as pd
import numpy as np
import yaml
import subprocess
import re
import policyCreator
import time
import logging
from subprocess import PIPE, run

# CONST
INTERVAL = 60

METRICSNAME = utils.METRICS
MALWARETYPES = utils.MALWARETYPES


formatter = logging.Formatter('%(levelname)s - %(message)s')
def setup_logger(name, log_file, level=logging.INFO):
    handler = logging.FileHandler(log_file)        
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger

# init config
with open('config.yaml') as stream:
    config = yaml.safe_load(stream)

# load policy
policy = policyCreator.createPolicy()
histogram = policyCreator.factors(policy)
malwareOccurences = histogram[0]
malwareOccurencesSum = histogram[1]

# init a classifier dict
classifier = utils.CLASSIFIER

# init logging
#logging.basicConfig(filename='observer.log', filemode='w', format='%(levelname)s - %(message)s', level=logging.INFO)
observer = setup_logger('observer', 'observer.log')
deployer = setup_logger('deployer', 'deployer.log')

# dstat command
dstatCommand = ['dstat', '-t', '--cpu', '--mem', '-d', '--disk-tps', '-n', '--tcp', '-y', '-p', '-N', 'eth0', '1', '1'] 

# MTD policy selection loop
while True:        
    # determine IP
    ipFinder = ['hostname', '-I']
    ipAddress = run(ipFinder, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    IP = ipAddress.stdout # todo fix mulitple IPs
    IP = IP.rstrip('\n')

    # https://stackoverflow.com/questions/1996518/retrieving-the-output-of-subprocess-call
    dstatOut = run(dstatCommand, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    observedMetrics = dstatOut.stdout
    
    # preprocessing to metrics
    start = int(observedMetrics.find('new')) # maybe use 2nd line insead of first
    observedMetricsProcessed =  observedMetrics[start+3+15:-1]
    metricsNumbers = re.findall('[0-9.]+[a-zA-Z]|[0-9.]+', observedMetricsProcessed) # extract array of all numbers like 123.32, 1.4B, 34 34K
    timestamp = re.findall('[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]', observedMetrics)[0] # extract timestamp  [dd-mm hh:mm:ss], 01-08 15:13:48
    # postprocess to array with no postfixes (M, k and B for units)
    systemMetrics = []
    for number in metricsNumbers:
        if 'M' in number:
            number = float(number[:-1])
            number = number * 1000 * 1000
        elif 'k' in number:
            number = float(number[:-1])
            number = number * 1000
        elif 'B' in number:
            number = float(number[:-1])
        else:
            number = float(number)

        systemMetrics.append(number)

    # initialize an empty malware indicator table
    malwareIndicators = {
    'BASHLITE':0,
    'Ransomware':0,
    'httpbackdoor':0,
    'jakoritarleite':0,
    'The Tick':0,
    'bdvl':0,
    'beurk':0
    }

    # iterate over all captures values
    for metricNumber, metric in zip(systemMetrics, METRICSNAME):
        print(metric, end= ' ')
        # compare to all existings policy rules
        found = False
        for index, rule in policy.iterrows():
            if metric == rule['metric']:
                # print(metric, rule['malware'], rule['metric'], metricNumber, rule['sign'], rule['threshold'])
                
                # falling below critical treshold as indicator
                if (rule[2] == '<=') & (float(metricNumber) <= float(rule[3])):
                    print('ALERT: Possible {}'.format(rule[0]), end= ' ')
                    observer.warning('{}|{}| Value: {}, Metric: {} {:.2f}: Possible {}'.format(timestamp, metric, metricNumber, rule[2], rule[3], rule[0]))
                    malwareIndicators[rule[0]] += 1
                    found = True

                # exceed critical threshold as indicator
                if (rule[2] == '>=') & (float(metricNumber) >= float(rule[3])):
                    print('ALERT: Possible {}'.format(rule[0]), end= ' ')
                    observer.warning('{}|{}| Value: {}, Metric: {} {:.2f}: Possible {}'.format(timestamp, metric, metricNumber, rule[2], rule[3], rule[0]))
                    malwareIndicators[rule[0]] += 1
                    found = True 
                           
        if not found:
            print('{}|{}| no detection'.format(timestamp, metric), end= ' ')
            observer.info('{}|{}|no detection'.format(timestamp, metric))
        print('\n')

    # fill malware Indicator dict
    classifier = dict.fromkeys(classifier, 0) # set all to 0
    for malwareIndicator in malwareIndicators.keys():
        classifier[MALWARETYPES[malwareIndicator]] += malwareIndicators[malwareIndicator]

    # scale number of occurences according to histogram    
    indicatorResult = ''
    for key in malwareOccurences:
        malwareRatio = malwareOccurences[key] / malwareOccurencesSum
        classifier[key] /= malwareRatio
        indicatorResult += '{}: {:.2f} '.format(key,classifier[key])
 
    # predict
    predictedType = max(classifier, key=classifier.get)  # todo: insert confidence band (e.g., over 95%)

    # create and execute MTDDeployment command
    triggerMTDCommand = 'python3 /opt/MTDFramework/MTDDeployerClient.py --ip {}--port 1234 --attack {}'.format(IP, predictedType)
    deployer.critical('{}|Deyploying against {}: {} | {}'.format(timestamp, predictedType, triggerMTDCommand, indicatorResult))
    #subprocess.call(triggerMTDCommand.split())
    
    # wait since sockets seems to have difficulties with to many requests 
    time.sleep(INTERVAL)
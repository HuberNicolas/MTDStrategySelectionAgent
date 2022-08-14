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
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 2345))
s.listen(10)
# FUNCTIONS


def setupLogger(name, log_file, level=logging.INFO):
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


def getIP():
    ipAddress = run(ipFinderCommand, stdout=PIPE, stderr=PIPE,
                    universal_newlines=True)
    IP = ipAddress.stdout  # todo fix mulitple IPs
    IP = IP.rstrip('\n')
    return IP


def removeUnits(metricsNumbersArray):
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

    return systemMetrics


# CONST
METRICSNAME = utils.METRICS
MALWARETYPES = utils.MALWARETYPES

# INIT CONFIG
with open('config.yaml') as stream:
    config = yaml.safe_load(stream)

INTERVAL = config['interval']
countMalwareIndicators = config['countMalwareIndicators']
countMalwareTypeIndicators = config['countMalwareTypeIndicators']
countMalwareIndicatorsRelatively = config['countMalwareIndicatorsRelatively']
ipFinderCommand = config['ipFinderCommand']
dstatCommand = config['dstatCommand']
MODE = config['mode'][0]

# INIT LOGGING
formatter = logging.Formatter('%(levelname)s - %(message)s')
#logging.basicConfig(filename='observer.log', filemode='w', format='%(levelname)s - %(message)s', level=logging.INFO)
observer = setupLogger('observer', 'observer.log')
deployer = setupLogger('deployer', 'deployer.log')

indicator = {
    'Ransomware': [0, 0, 0],
    'Rootkit': [0, 0, 0],
    'CnC': [0, 0, 0],
}


def indicatorRatio(indicator):
    for k, v in indicator.items():
        if v[1] == 0:
            v[2] = 0
        else:
            v[2] = v[0] / (v[0] + v[1])


lastDeployment = None
startTime = time.time()
# INIT POLICY
policy = csvPolicy = pd.read_csv('expert-based-policy.csv', header=None)
policy.columns = utils.POLICYCOLUMNS
# MTD policy selection loop
while True:
    # determine IP
    IP = getIP()
    indicator = {
        'Ransomware': [0, 0, 0],
        'Rootkit': [0, 0, 0],
        'CnC': [0, 0, 0],
    }

    # start observation and collect system metrics
    # https://stackoverflow.com/questions/1996518/retrieving-the-output-of-subprocess-call
    dstatOut = run(dstatCommand, stdout=PIPE,
                   stderr=PIPE, universal_newlines=True)
    observedMetrics = dstatOut.stdout
    # process to metrics array with clean numbers
    # extract 2nd line
    observedMetricsProcessed = observedMetrics.splitlines()[-1]
    # extract timestamp  [dd-mm hh:mm:ss], 01-08 15:13:48
    timestamp = re.findall(
        '[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]', observedMetricsProcessed)[0]
    
    history = []
    # append last 5 entries to history
    for i in range(-1, -11, -1):
        history.append(observedMetrics.splitlines()[i])

    history.reverse() # start with the earliest timestamp
    systemMetricValuesHistory = []
    for h in history:
        # extract timestamp
        timestamp = re.findall(
        '[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]', h)[0]
        # extract array of all numbers like 123.32, 1.4B, 34 34K
        metricsNumbers = re.findall(
        '[0-9.]+[a-zA-Z]|[0-9.]+', h[len(timestamp):])
        # postprocess to array with no postfixes (M, k and B for units)
        
        systemMetricValues = removeUnits(metricsNumbersArray=metricsNumbers)
        systemMetricValuesHistory.append(systemMetricValues)

    
    # calculate average for all metrics for
    systemMetricValues = np.array(systemMetricValuesHistory)
    avgSysteMetricValues = np.average(systemMetricValues, axis=0)
    
    # iterate over all captures values (value, metricName)
    for metricNumber, metricName in zip(avgSysteMetricValues, METRICSNAME):
        # compare to all existings policy rules
        found = False
        for index, rule in policy.iterrows():
            if metricName == rule['metric']:
                print(metricName, rule['malware'], rule['metric'], metricNumber, rule['sign'], rule['threshold'])
                found = True
                # falling below critical treshold as indicator
                if (rule[2] == '<=') & (float(metricNumber) <= float(rule[3])):
                    indicator[rule[0]][0] += 1
                    observer.warning('{}|{}| Value: {}, Metric: {} {:.2f}: ({})'.format(
                        timestamp, metricName, metricNumber, rule[2], rule[3], rule[0]))

                # exceed critical threshold as indicator
                elif (rule[2] == '>=') & (float(metricNumber) >= float(rule[3])):
                    indicator[rule[0]][0] += 1
                    observer.warning('{}|{}| Value: {}, Metric: {} {:.2f}: ({})'.format(
                        timestamp, metricName, metricNumber, rule[2], rule[3], rule[0]))

                else:
                    indicator[rule[0]][1] += 1
                    observer.info('{}|{}|No detection for this metric: ({})'.format(
                        timestamp, metricName, rule[0]))

        if not found:
            print('{}|{}|No rule'.format(timestamp, metricName))
            observer.info('{}|{}|No rule'.format(timestamp, metricName))
    
    indicatorRatio(indicator)
    detectionHiearachy = sorted(
        indicator.items(), key=lambda i: i[1][0], reverse=True) # [1][0]: sort by pos, [1][2]: sort by %
    predictedType = detectionHiearachy[0][0]
    predictedPercentage = detectionHiearachy[0][1][2]
    resultStr = ''
    for malwareType in detectionHiearachy:
        resultStr += '{}:({:.2f}|{:.2f}:{:.2f}), '.format(malwareType[0], malwareType[1][2], malwareType[1][0], malwareType[1][1])
    detectionHiearachyStr = resultStr[:-2]

    # check threshold
    if (predictedPercentage >= MODE['detectionTreshold']):
        # create and execute MTDDeployment command
        triggerMTDCommand = 'python3 /opt/MTDFramework/MTDDeployerClient.py --ip {}--port 1234 --attack {}'.format(
            IP, predictedType)

        executionTime = time.time() - startTime
        print(int(executionTime))
        if True:
            print("deployment")
            deployer.critical('{}|Deyploying against {}: {} |{}'.format(
                timestamp, predictedType, triggerMTDCommand, detectionHiearachyStr))
            # wait since sockets seems to have difficulties with to many requests
            subprocess.call(triggerMTDCommand.split())

            #time.sleep(30)
            lastDeployment = time.time() - startTime
            client_socket, address = s.accept()
            print('Connection ' + address[0])
        else:
            print("no-deployment")
            deployer.critical('{}|TIMOUT (NO DEPLOYMENT): Detected {}: {} |{}'.format(
                timestamp, predictedType, triggerMTDCommand, detectionHiearachyStr))

    else:
        print("no-deployment (no rule)")
        deployer.info('{}|No deployment against {}: No command was sent |{}'.format(
            timestamp, predictedType, detectionHiearachyStr))

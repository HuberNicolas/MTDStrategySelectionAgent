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


def normalize(malwareIndicators):
    malwareIndicatorsScaled = dict(malwareIndicators)  # copy by value
    for malware in malwareIndicatorsScaled:
        if malware == 'Ransomware':
            malwareIndicatorsScaled[malware] *= 4
        elif malware == 'beurk' or malware == 'bdvl':
            malwareIndicatorsScaled[malware] *= 2
        else:
            pass
    return malwareIndicatorsScaled


def countMalwareType(malwareIndicators, malwareTypeIndicators):
    for malwareIndicator in malwareIndicators.keys():
        malwareTypeIndicators[MALWARETYPES[malwareIndicator]
                              ] += malwareIndicators[malwareIndicator]
    return malwareTypeIndicators


def relativeMalwareOccurence(malwareIndicatorsRelative, malwareIndicatorsPositive, malwareIndicatorsNegative):
    for malwareType in malwareIndicatorsRelative:
        sumPosNegIndicators = (
            malwareIndicatorsPositive[malwareType] + malwareIndicatorsNegative[malwareType])
        if sumPosNegIndicators != 0:
            malwareIndicatorsRelative[malwareType] = malwareIndicatorsPositive[malwareType] / \
                sumPosNegIndicators
        else:
            malwareIndicatorsRelative[malwareType] = 0
    return malwareIndicatorsRelative


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

# Init empty malware indicator tables
malwareIndicators = utils.malwareIndicatorTable
malwareIndicatorsScaled = utils.malwareIndicatorTable
malwareIndicatorsNegative = utils.malwareIndicatorTable
malwareIndicatorsRelative = utils.malwareIndicatorTable
malwareIndicatorsRelativeScaled = utils.malwareIndicatorTable

# Init an empty malware type indicator table
malwareTypeIndicators = utils.malwareTypeIndicatorTable


# INIT LOGGING
formatter = logging.Formatter('%(levelname)s - %(message)s')
#logging.basicConfig(filename='observer.log', filemode='w', format='%(levelname)s - %(message)s', level=logging.INFO)
observer = setupLogger('observer', 'observer.log')
deployer = setupLogger('deployer', 'deployer.log')


# INIT POLICY
policy = policyCreator.createPolicy()
malwareDistribution = policyCreator.malwareDistribution(policy)
malwareOccurences = malwareDistribution[0]  # malwareTypeOcc
malwareOccurencesSum = malwareDistribution[1]  # totalOccurences

# MTD policy selection loop
while True:
    # determine IP
    IP = getIP()

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
    # extract array of all numbers like 123.32, 1.4B, 34 34K
    metricsNumbers = re.findall(
        '[0-9.]+[a-zA-Z]|[0-9.]+', observedMetricsProcessed[len(timestamp):])

    # postprocess to array with no postfixes (M, k and B for units)
    systemMetricValues = removeUnits(metricsNumbersArray=metricsNumbers)

    # set all inidcator table to 0
    malwareIndicators = dict.fromkeys(malwareIndicators, 0)
    malwareIndicatorsNegative = dict.fromkeys(malwareIndicatorsNegative, 0)
    malwareIndicatorsRelative = dict.fromkeys(malwareIndicatorsRelative, 0)

    malwareIndicatorsRelative = dict.fromkeys(malwareIndicatorsRelative, 0)
    # iterate over all captures values (value, metricName)
    for metricNumber, metricName in zip(systemMetricValues, METRICSNAME):
        print('{}|'.format(metricName), end=' ')
        # compare to all existings policy rules
        found = False
        for index, rule in policy.iterrows():
            if metricName == rule['metric']:
                # print(metricName, rule['malware'], rule['metric'], metricNumber, rule['sign'], rule['threshold'])
                found = True
                # falling below critical treshold as indicator
                if (rule[2] == '<=') & (float(metricNumber) <= float(rule[3])):
                    malwareIndicators[rule[0]] += 1
                    print('ALERT: Possible {} (+({}) -({}))'.format(
                        rule[0], malwareIndicators[rule[0]], malwareIndicatorsNegative[rule[0]]), end=' ')
                    observer.warning('{}|{}| Value: {}, Metric: {} {:.2f}: ({})'.format(
                        timestamp, metricName, metricNumber, rule[2], rule[3], rule[0]))

                # exceed critical threshold as indicator
                if (rule[2] == '>=') & (float(metricNumber) >= float(rule[3])):
                    malwareIndicators[rule[0]] += 1
                    print('ALERT: Possible {} (+({}) -({}))'.format(
                        rule[0], malwareIndicators[rule[0]], malwareIndicatorsNegative[rule[0]]), end=' ')
                    observer.warning('{}|{}| Value: {}, Metric: {} {:.2f}: ({})'.format(
                        timestamp, metricName, metricNumber, rule[2], rule[3], rule[0]))

                else:
                    malwareIndicatorsNegative[rule[0]] += 1
                    print('No detection for {} (+({}) -({}))'.format(
                        rule[0], malwareIndicators[rule[0]], malwareIndicatorsNegative[rule[0]]), end=' ')
                    observer.info('{}|{}|No detection for this metric: ({})'.format(
                        timestamp, metricName, rule[0]))

        if not found:
            print('No rule', end=' ')
            observer.info('{}|{}|No rule'.format(timestamp, metricName))
        print('\n')

    # normalize
    malwareIndicatorsScaled = normalize(malwareIndicators)

    # sum over groups
    malwareTypeIndicators = countMalwareType(
        malwareIndicators, malwareTypeIndicators)

    # relative detection
    malwareIndicatorsRelative = relativeMalwareOccurence(
        malwareIndicatorsRelative, malwareIndicators, malwareIndicatorsNegative)
    malwareIndicatorsRelativeScaled = relativeMalwareOccurence(
        malwareIndicatorsRelativeScaled, malwareIndicatorsScaled, malwareIndicatorsNegative)

    # prediction based on max value of malware
    predicted = max(malwareIndicatorsRelativeScaled,
                    key=malwareIndicatorsRelativeScaled.get)
    predictedPercentage = max(malwareIndicatorsRelativeScaled.values())
    predictedType = MALWARETYPES[predicted]

    # list detection values descending
    detectionHiearachy = sorted(
        list(malwareIndicatorsRelativeScaled.items()), key=lambda x: x[1], reverse=True)
    detectionHiearachyStr = ''
    for detectionRate in detectionHiearachy:
        detectionHiearachyStr += '{} ({}): {:.2f}; '.format(
            detectionRate[0], MALWARETYPES[detectionRate[0]], detectionRate[1])

    # check threshold
    if(predictedPercentage > MODE['detectionTreshold']):
        # create and execute MTDDeployment command
        triggerMTDCommand = 'python3 /opt/MTDFramework/MTDDeployerClient.py --ip {}--port 1234 --attack {}'.format(
            IP, predictedType)
        deployer.critical('{}|Deyploying against {}: {} |{}'.format(
            timestamp, predictedType, triggerMTDCommand, detectionHiearachyStr))
        subprocess.call(triggerMTDCommand.split())

    else:
        deployer.info('{}|No deployment against {}: No command was sent |{}'.format(
            timestamp, predictedType, detectionHiearachyStr))

    # wait since sockets seems to have difficulties with to many requests
    time.sleep(INTERVAL)

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


def setup_logger(name, log_file, level=logging.INFO):
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


def makeNumerical(metricsNumbersArray):
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

# Init empty malware indicator tables
malwareIndicators = utils.malwareIndicatorTable
malwareIndicatorsNegative = utils.malwareIndicatorTable
malwareIndicatorsRelative = utils.malwareIndicatorTable

# Init an empty malware type indicator table
malwareTypeIndicators = utils.malwareTypeIndicatorTable


# INIT LOGGING
formatter = logging.Formatter('%(levelname)s - %(message)s')
#logging.basicConfig(filename='observer.log', filemode='w', format='%(levelname)s - %(message)s', level=logging.INFO)
observer = setup_logger('observer', 'observer.log')
deployer = setup_logger('deployer', 'deployer.log')


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
    # todo: maybe use 2nd line insead of first
    start = int(observedMetrics.find('new'))
    observedMetricsProcessed = observedMetrics[start+3+15:-1]
    # extract array of all numbers like 123.32, 1.4B, 34 34K
    metricsNumbers = re.findall(
        '[0-9.]+[a-zA-Z]|[0-9.]+', observedMetricsProcessed)
    # extract timestamp  [dd-mm hh:mm:ss], 01-08 15:13:48
    timestamp = re.findall(
        '[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]', observedMetrics)[0]
    # postprocess to array with no postfixes (M, k and B for units)
    systemMetricValues = makeNumerical(metricsNumbersArray=metricsNumbers)

    # set all inidcator table to 0
    malwareIndicators = dict.fromkeys(malwareIndicators, 0)
    malwareIndicatorsNegative = dict.fromkeys(malwareIndicatorsNegative, 0)
    malwareIndicatorsRelative = dict.fromkeys(malwareIndicatorsRelative, 0)

    malwareIndicatorsRelative = dict.fromkeys(malwareIndicatorsRelative, 0)

    # iterate over all captures values (value, metricName)
    for metricNumber, metricName in zip(systemMetricValues, METRICSNAME):
        print(metricName, end=' ')
        # compare to all existings policy rules
        found = False
        for index, rule in policy.iterrows():
            if metricName == rule['metric']:
                # print(metricName, rule['malware'], rule['metric'], metricNumber, rule['sign'], rule['threshold'])

                # falling below critical treshold as indicator
                if (rule[2] == '<=') & (float(metricNumber) <= float(rule[3])):
                    print('ALERT: Possible {}'.format(rule[0]), end=' ')
                    observer.warning('{}|{}| Value: {}, Metric: {} {:.2f}: Possible {}'.format(
                        timestamp, metricName, metricNumber, rule[2], rule[3], rule[0]))
                    malwareIndicators[rule[0]] += 1
                    found = True

                # exceed critical threshold as indicator
                if (rule[2] == '>=') & (float(metricNumber) >= float(rule[3])):
                    print('ALERT: Possible {}'.format(rule[0]), end=' ')
                    observer.warning('{}|{}| Value: {}, Metric: {} {:.2f}: Possible {}'.format(
                        timestamp, metricName, metricNumber, rule[2], rule[3], rule[0]))
                    malwareIndicators[rule[0]] += 1
                    found = True
                else:
                    malwareIndicatorsNegative[rule[0]] += 1

        if not found:
            print('{}|{}| no detection'.format(timestamp, metricName), end=' ')
            observer.info('{}|{}|no detection'.format(timestamp, metricName))
        print('\n')

    # predict malware or malware type
    indicatorResult = ''
    if countMalwareIndicators == True:
        # determine malware
        # find max value in malware indicator table
        predicted = max(malwareIndicators, key=malwareIndicators.get)
        # determine type of malware with the most indicators
        predictedType = MALWARETYPES[predicted]
        indicatorResult += '{}-({}): {}'.format(predicted,
                                                MALWARETYPES[predicted], malwareIndicators[predicted])

    elif countMalwareTypeIndicators == True:
        malwareTypeIndicators = dict.fromkeys(
            malwareTypeIndicators, 0)  # set all to 0
        # determine malware type
        # fill malwareTypeIndicatorTable dict
        for malwareIndicator in malwareIndicators.keys():
            malwareTypeIndicators[MALWARETYPES[malwareIndicator]
                                  ] += malwareIndicators[malwareIndicator]

        # scale number of occurences according to histogram
        for malwareType in malwareOccurences:
            malwareRatio = malwareOccurences[malwareType] / \
                malwareOccurencesSum
            malwareTypeIndicators[malwareType] /= malwareRatio
            indicatorResult += '{}: {:.2f} '.format(
                malwareType, malwareTypeIndicators[malwareType])

        # predict
        # todo: insert confidence band (e.g., over 95%)
        predictedType = max(malwareTypeIndicators,
                            key=malwareTypeIndicators.get)

    elif countMalwareIndicatorsRelatively == True:
        # determine malware
        for malwareType in malwareIndicatorsRelative:
            sumPosNegIndicators = (
                malwareIndicators[malwareType] + malwareIndicatorsNegative[malwareType])
            if sumPosNegIndicators != 0:
                malwareIndicatorsRelative[malwareType] = malwareIndicators[malwareType] / \
                    sumPosNegIndicators
            else:
                malwareIndicatorsRelative[malwareType] = 0

            indicatorResult += '{}-({}): {:.2f} '.format(
                malwareType, MALWARETYPES[malwareType], malwareIndicatorsRelative[malwareType])
        # predict
        # todo: insert confidence band (e.g., over 95%)
        predictedType = max(malwareIndicatorsRelative,
                            key=malwareIndicatorsRelative.get)

    # create and execute MTDDeployment command
    triggerMTDCommand = 'python3 /opt/MTDFramework/MTDDeployerClient.py --ip {}--port 1234 --attack {}'.format(
        IP, predictedType)
    deployer.critical('{}|Deyploying against {}: {} | {}'.format(
        timestamp, predictedType, triggerMTDCommand, indicatorResult))
    # subprocess.call(triggerMTDCommand.split())

    # wait since sockets seems to have difficulties with to many requests
    time.sleep(INTERVAL)

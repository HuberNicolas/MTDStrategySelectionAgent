# IMPORTS
import pandas as pd
import numpy as np
import yaml
import re
import time
import logging
import os
from subprocess import PIPE, run
import subprocess
import utils
from MTD import MTD1, MTD2, MTD3

# FUNCTIONS


def setupLogger(name, log_file, level=logging.INFO):
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


def getIP():
    ipAddress = run(IPFINDERCOMMAND, stdout=PIPE, stderr=PIPE,
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


def calculatePosNegRatio(indicator):
    # v[0] = # positive hits
    # v[1] = # negative hits
    for k, v in indicator.items():
        # #p == 0 ==> %p:= 0
        if v[0] == 0:
            v[2] = 0
        # p% = #p / (#p + #n)
        else:
            v[2] = v[0] / (v[0] + v[1])


# INIT CONFIG
with open('config.yaml') as stream:
    config = yaml.safe_load(stream)

IPFINDERCOMMAND = config['ipFinderCommand']
DSTATCOMMAND = config['dstatCommand']
EVALUATIONMETHOD = config['evaluationMethod']
DETECTIONTHRESHOLD = config['detectionThreshold']
HISTORYLEN = config['historyLen']

# CONST
METRICSNAME = utils.METRICS
MALWARETYPES = utils.MALWARETYPES

# INIT LOGGING
formatter = logging.Formatter('%(levelname)s - %(message)s')
observer = setupLogger('observer', 'observer.log')
deployer = setupLogger('deployer', 'deployer.log')

# INIT POLICY
policy = pd.read_csv('expertBasedIfThen.csv', header=None)
policy.columns = utils.POLICYCOLUMNS

# MTD policy selection loop
while True:
    startObservationTime = time.time()
    mtdIndicator = {
        'MTD1': [0, 0, 0],
        'MTD2': [0, 0, 0],
        'MTD3': [0, 0, 0],
    }
    # determine IP
    IP = getIP()

    # start observation and collect system metrics
    dstatOut = run(DSTATCOMMAND, stdout=PIPE,
                   stderr=PIPE, universal_newlines=True)
    dstatLines = dstatOut.stdout

    # extract timestamp from first history entry[dd-mm hh:mm:ss], 01-08 15:13:48
    timestamp = re.findall(
        '[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]', dstatLines.splitlines()[-HISTORYLEN])[0]

    history = []
    # append last N entries to history
    for i in range(-1, -(HISTORYLEN+1), -1):
        history.append(dstatLines.splitlines()[i])
    history.reverse()  # start with the earliest timestamp

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
        for index, rule in policy.iterrows():  # [index][rule]
            # at least one policy rule for this metric?
            if metricName == rule['metric']:
                found = True
                #  fall below threshold: indicator for malware
                if (rule[1] == '<=') & (float(metricNumber) <= float(rule[2])):
                    mtdIndicator[rule[3]][0] += 1
                    observer.warning('{}|{}| Value: {}, Metric: {} {:.2f}: ({}) [+]'.format(
                        timestamp, metricName, metricNumber, rule[1], rule[2], rule[3]))

                # exceed critical threshold: indicator for malware
                elif (rule[1] == '>=') & (float(metricNumber) >= float(rule[2])):
                    mtdIndicator[rule[3]][0] += 1
                    observer.warning('{}|{}| Value: {}, Metric: {} {:.2f}: ({}) [+]'.format(
                        timestamp, metricName, metricNumber, rule[1], rule[2], rule[3]))
                # normal behaviour
                else:
                    mtdIndicator[rule[3]][1] += 1
                    observer.info('{}|{}| Value: {}, Metric: {} {:.2f}: ({}) [-]'.format(
                        timestamp, metricName, metricNumber, rule[1], rule[2], rule[3]))
        # no policy rule existing for this metric
        if not found:
            observer.info('{}|{}| Value: {}, No rule: [0]'.format(
                timestamp, metricName, metricNumber))

    # calculate % and find best MTD
    calculatePosNegRatio(mtdIndicator)
    mtdHierarchy = sorted(
        mtdIndicator.items(), key=lambda i: i[1][2], reverse=True)  # [1][0]: sorting by absolute occurences, [1][2]: sorting by % occurences,
    mtdMethod = mtdHierarchy[0][0]
    mtdPercentage = mtdHierarchy[0][1][2]

    if mtdMethod == 'MTD1':  # Ransomware
        mtdCommand = 'python3 /root/MTDPolicy/MTD/Ransomware/CreateDummyFiles.py --path=/root/sample-data --numberOfDummyFiles=30 --numberOfDummyFilesPerSubdirectory=15 --size=10 --extension=pdf'
    elif mtdMethod == 'MTD2':  # CnC
        mtdCommand = 'python3 /root/MTDPolicy/MTD/CnC/ChangeIpAddress.py'
    elif mtdMethod == 'MTD3':  # Rootkit
        mtdCommand = 'python3 /root/MTDPolicy/MTD/Rootkit/RemoveRootkit.py'

    # detection hierarchy: MTD1:(0.75|3:1), MTD3:(0.5|1:1), MTD2:(0.33|1:2)
    detectionStr = ''
    for mtd in mtdHierarchy:
        detectionStr += '{}:({:.2f}|{:d}:{:d}), '.format(
            mtd[0], mtd[1][2], mtd[1][0], mtd[1][1])
    detectionHierarchyStr = detectionStr[:-2]  # remove '),'

    endObservationTime = time.time()
    observer.info('{}|Observation took {:.2f}s'.format(
        timestamp, (endObservationTime - startObservationTime)))
    # check threshold
    if (mtdPercentage >= DETECTIONTHRESHOLD):
        deployer.critical('{}|Deyployed : {} |{}'.format(
            timestamp, mtdMethod, detectionHierarchyStr))
        startMTDDeploymentTime = time.time()
        # os.system(mtdCommand) does not wait
        subprocess.call(mtdCommand.split())
        endMTDDeploymentTime = time.time()
        deployer.info('{}|Deyploying of {} took {:.2f}s'.format(
            timestamp, mtdMethod, (endMTDDeploymentTime - startMTDDeploymentTime)))
        time.sleep(60)

    else:
        deployer.info('{}|No deployment: No command was sent |{}'.format(
            timestamp, detectionHierarchyStr))

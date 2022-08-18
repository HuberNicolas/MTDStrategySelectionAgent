# IMPORTS
from os import getcwd, system
import pandas as pd
import numpy as np
import yaml
import subprocess
import re
import time
import logging
from subprocess import PIPE, run
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

def indicatorRatio(indicator):
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

ipFinderCommand = config['ipFinderCommand']
dstatCommand = config['dstatCommand']
evaluationMethod = config['evaluationMethod']
DETECTIONTHRESHOLD = config['detectionThreshold']
HISTORYLEN = config['historyLen']
RESPONSEPORT = config['responsePort']

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
    # determine IP
    IP = getIP()
    
    # start observation and collect system metrics
    dstatOut = run(dstatCommand, stdout=PIPE,
                   stderr=PIPE, universal_newlines=True)
    dstatLines = dstatOut.stdout
    
    # extract timestamp from first history entry[dd-mm hh:mm:ss], 01-08 15:13:48
    timestamp = re.findall(
        '[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]', dstatLines.splitlines()[-HISTORYLEN])[0]
    
    history = []
    # append last N entries to history
    for i in range(-1, -(HISTORYLEN+1), -1):
        history.append(dstatLines.splitlines()[i])
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
    
    mtdIndicator = {
        'MTD1':0,
        'MTD2':0,
        'MTD3':0,
    }

    # iterate over all captures values (value, metricName)
    for metricNumber, metricName in zip(avgSysteMetricValues, METRICSNAME):
        # compare to all existings policy rules
        found = False
        
        for index, rule in policy.iterrows(): # [index][rule]
            if metricName == rule['metric']:
                if (rule[1] == '<=') & (float(metricNumber) <= float(rule[2])):
                    mtdIndicator[rule[3]] += 1
                    print('{}|{}| Value: {}, Metric: {} {:.2f}: ({})'.format(
                        timestamp, metricName, metricNumber, rule[1], rule[2], rule[3]))

                # exceed critical threshold as indicator
                elif (rule[1] == '>=') & (float(metricNumber) >= float(rule[2])):
                    mtdIndicator[rule[3]] += 1
                    print('{}|{}| Value: {}, Metric: {} {:.2f}: ({})'.format(
                        timestamp, metricName, metricNumber, rule[1], rule[2], rule[3]))    
    
    mtdHierarchy = dict(sorted(mtdIndicator.items(), key=lambda x:x[1], reverse=True))
    mtdMethod = list(mtdHierarchy.keys())[0]
    mtdCommand = '{}.{}()'.format(mtdMethod, mtdMethod)
    exec(mtdCommand)
    quit()

    predictedType = mtdHierarchy[0][0]
    predictedPercentage = mtdHierarchy[0][1][2]
    
    # detection hierarchy: Rootkit:(0.75|3:1), Ransomware:(0.5|1:1), CnC:(0.33|1:2)
    detectionStr = ''
    for malwareType in mtdHierarchy:
        detectionStr += '{}:({:.2f}|{:d}:{:d}), '.format(malwareType[0], malwareType[1][2], malwareType[1][0], malwareType[1][1])
    detectionHierarchyStr = detectionStr[:-2] # remove '),'

    endObservationTime = time.time()
    observer.info('{}|Observation took {:.2f}s'.format(
            timestamp, (endObservationTime - startObservationTime)))

    # check threshold
    if (predictedPercentage >= DETECTIONTHRESHOLD):
        # create and execute MTDDeployment command
        startMTDDeploymentTime = time.time()
        triggerMTDCommand = 'python3 /opt/MTDFramework/MTDDeployerClient.py --ip {}--port 1234 --attack {}'.format(
            IP, predictedType)

        deployer.critical('{}|Deyploying against {}: {} |{}'.format(
            timestamp, predictedType, triggerMTDCommand, detectionHierarchyStr))

        # start MTD deployment  
        subprocess.call(triggerMTDCommand.split())
        
        endMTDDeploymentTime = time.time()
        deployer.info('{}|Deyploying of {} took {:.2f}s'.format(
            timestamp, mtdTechnique, (endMTDDeploymentTime - startMTDDeploymentTime)))

    else:
        deployer.info('{}|No deployment against {}: No command was sent |{}'.format(
            timestamp, predictedType, detectionHierarchyStr))

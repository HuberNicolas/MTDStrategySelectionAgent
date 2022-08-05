import glob
from multiprocessing import pool
import os
import pandas as pd
import numpy as np
import shutil
import csv
import yaml
import random
import subprocess
import io
import re
import policyCreator
import time

CAT = [
    'usr',
    'sys',
    'idl',
    'wai',
    'hiq',
    'siq',
    'used',
    'buff',
    'cache',
    'free',
    'files',
    'inodes',
    'read',
    'writ',
    'reads',
    'writs',
    'recv',
    'send',
    'lis',
    'act',
    'syn',
    'tim',
    'clo',
    'int',
    'csw',
    'run',
    'blk',
    'new',
]

COLS = ['malware', 'metric', 'sign', 'threshold']
with open('config.yaml') as stream:
    config = yaml.safe_load(stream)

policy = policyCreator.createPolicy()

# https://stackoverflow.com/questions/1996518/retrieving-the-output-of-subprocess-call

# measure
from subprocess import PIPE, run
command = ['dstat', '-t', '--cpu', '--mem', '-d', '--disk-tps', '-n', '--tcp', '-y', '-p', '-N', 'eth0', '1', '1']

import logging

logging.basicConfig(filename='observer.log', filemode='w', format='%(levelname)s - %(message)s', level=logging.INFO)

while True:
    result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    log = result.stdout

    # preprocessing to extract numbers
    start = int(log.find('new'))
    log2=  log[start+3+15:-1]
    print(result.stdout)
    
    

    # extract all numbers
    numbers = re.findall('[0-9.]+[a-zA-Z]|[0-9.]+', log2)
    moment = re.findall('[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]', log)
    array = []
    for number in numbers:
        if 'M' in number:
            print(number)
            number = float(number[:-1])
            number = number * 1000 * 1000
        elif 'k' in number:
            number = float(number[:-1])
            number = number * 1000
        elif 'B' in number:
            number = float(number[:-1])
        else:
            number = float(number)

        array.append(number)


    malwareIndicators = {
    'BASHLITE':0,
    'Ransomware':0,
    'httpbackdoor':0,
    'jakoritarleite':0,
    'The Tick':0,
    'bdvl':0,
    'beurk':0
    }

    # iterate over all metrics
    for value, metric in zip(array, CAT):

        #print(value, metric)
        indicator = 0 # count all indicators

        # is there a rule for this metric
        if metric in set(policy['metric']):
            #print('found')
            rule = policy[policy['metric'].str.contains(metric)].values[0]
            #print(rule)
            print('{}|{}| Value: {}, Metric: {} {}:'.format(moment[0], metric, value, rule[2], rule[3]), end=' ')

            if (rule[2] == '<=') & (float(value) <= float(rule[3])):
                print('ALERT: we have a {}'.format(rule[0]))
                logging.critical('{}|{}| Value: {}, Metric: {} {}: we have a {}'.format(moment[0], metric, value, rule[2], rule[3], rule[0]))
                malwareIndicators[rule[0]] += 1

            if (rule[2] == '>=') & (float(value) >= float(rule[3])):
                print('ALERT: we have a {}'.format(rule[0]))
                logging.critical('{}|{}| Value: {}, Metric: {} {}: we have a {}'.format(moment[0], metric, value, rule[2], rule[3], rule[0]))
                malwareIndicators[rule[0]] += 1
            else:
                print('everything good!')
                logging.info('{}|{}|no detection'.format(moment[0], metric))
        else:
            print('{}|{}| no rule'.format(moment[0], metric))
    print(malwareIndicators)
    time.sleep(10)

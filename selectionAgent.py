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

print(config['policy'])

file = [i for i in glob.glob('./*.csv') if str(config['policy']) in i]

thresholds = pd.read_csv(file[0], header = None)
thresholds.columns = COLS
th = thresholds.groupby(['malware'])

#print(th.get_group('httpbackdoor'))

policy = pd.DataFrame()
for malware in th:
    if config['random'] == True:
        # malware is a tuple: (name, df)
        rows = malware[1].shape[0]
        nRules = random.choice([config['MIN_TH'], config['MAX_TH']])
        while(rows < nRules):
            nRules = random.choice([config['MIN_TH'], config['MAX_TH']])

    else:
        nRules = config['NUMBER_TH']
        print('false')
    #print(malware[1].sample(n = nRules))
    policy = policy.append(malware[1].sample(n = nRules))

#print(policy)
policy['metric'] = policy['metric'].str.replace('-mean', '')
policy = policy.drop_duplicates(subset=['metric']) # todo FIX THIS
policy.to_csv('policy.csv', index=False)

# https://stackoverflow.com/questions/1996518/retrieving-the-output-of-subprocess-call

# measure
from subprocess import PIPE, run
command = ['dstat', '-t', '--cpu', '--mem', '-d', '--disk-tps', '-n', '--tcp', '-y', '-p', '-N', 'eth0', '1', '1']
result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True)
print(result.returncode, result.stdout, result.stderr)
log = result.stdout

# preprocessing to extract numbers
start = int(log.find('new'))
#print(log[start+3+14:-1]) # + 3 (new); + 14 (dd-mm hh:mm:ss|)
log2=  log[start+3+15:-1]
print(log2)

# extract all numbers
numbers = re.findall('[0-9.]+[a-zA-Z]|[0-9.]+', log2)
print(numbers)


array = []
for number in numbers:
    if 'M' in number:
        print(number)
        number = float(number[:-1])
        number = number * 1000 * 1000
        print(number)
    elif 'k' in number:
        print(number)
        number = float(number[:-1])
        number = number * 1000
    else:
        number = float(number)

    array.append(number)

# debug
print(log)
print(numbers)
print(array)

#clear
os.system('cls' if os.name == 'nt' else 'clear')

# iterate over all metrics
for value, metric in zip(array, CAT):

    #print(value, metric)

    # is there a rule for this metric
    if metric in set(policy['metric']):
        #print('found')
        rule = policy[policy['metric'].str.contains(metric)].values[0]
        #print(rule)
        print('{}| Value: {}, Metric: {} {}:'.format(metric, value, rule[2], rule[3]))

        if (rule[2] == '<=') & (float(value) <= float(rule[3])):
            print('ALERT: we have a {}'.format(rule[0]))

        if (rule[2] == '>=') & (float(value) >= float(rule[3])):
            print('ALERT: we have a {}'.format(rule[0]))
        else:
            print('everything good!')


    else:
        print('no rule')
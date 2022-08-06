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
# init commit for policy creation and policy refactoring
# CONST
SEED = 10

# set seed
random.seed(SEED)
print(random.random())

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


def createPolicy():
    with open('config.yaml') as stream:
        config = yaml.safe_load(stream)

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

            # define random number between MIN_TH and MAX_TH
            random.seed(SEED)
            nRules = random.choice([config['MIN_TH'], config['MAX_TH']])
            while(rows < nRules):
                random.seed(SEED)
                nRules = random.choice([config['MIN_TH'], config['MAX_TH']])

        else:
            nRules = config['NUMBER_TH']
            print('false')
        #print(malware[1].sample(n = nRules))
        policy = policy.append(malware[1].sample(n = nRules, random_state=SEED))

    #print(policy)
    policy['metric'] = policy['metric'].str.replace('-mean', '')
    policy = policy.drop_duplicates(subset=['metric']) # todo FIX THIS
    policy.to_csv('policy.csv', index=False)
    return policy
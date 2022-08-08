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
import utils

# load config
with open('config.yaml') as stream:
        config = yaml.safe_load(stream)

# init commit for policy creation and poli
# CONST
SEED = config['seed']
POLICYCOLUMNS = utils.POLICYCOLUMNS

# set seed
random.seed(SEED)
print(random.random())

def createPolicy():

    # load the csv with windowSize
    filenames = [file for file in glob.glob('./*.csv') if str(config['windowSize']) in file]
    csvPolicy = pd.read_csv(filenames[0], header = None)
    
    # postprocess: set header and group by malwaretype
    csvPolicy.columns = POLICYCOLUMNS
    #print(malwareGroup.get_group('httpbackdoor')) # DEBUG
    malwareGroup = csvPolicy.groupby(['malware'])
   
    # policy creation
    policy = pd.DataFrame()
    
    # random policy policy creation
    # iterate over all malware groups and add some (random or defined) rules (row) for each malware type
    if config['randomPolicyCreation'] == True:
        for malware in malwareGroup:     
            
            # random number of rules
            if config['randomNumberOfPolicyRules'] == True:
                # malware is a tuple: (name, df)
                rows = malware[1].shape[0]
                # define random number between min/max number of policy rules
                random.seed(SEED)
                nRules = random.choice([config['minNumberOfPolicyRules'], config['maxNumberOfPolicyRules']])
                while(rows < nRules):
                    nRules -= 1
            
            # defined number of rules
            else:
                nRules = config['exactNumberOfPolicyRules']
            
            #print(malware[1].sample(n = nRules)) # DEBGUG
            # add defined rules to policy
            policy = policy.append(malware[1].sample(n = nRules, random_state=SEED)) #todo check what happens if nRules > n when set
            policy = policy.drop_duplicates(subset=['metric'])
    
    # complete policy policy creation
    # iterate over all malware groups and all rules (row) for each malware type
    elif config['completePolicyCreation'] == True:
        policy = csvPolicy
    
    # random policy policy creation
    else:
        pass
        # to be done
        

    # postprocessing
    policy['metric'] = policy['metric'].str.replace('-mean', '')
    policy.to_csv('policy.csv', index=False)
    return policy


def factors(policy):

    # classify each malware by type and add type column
    bd = ['httpbackdoor', 'BASHLITE', 'backdoor',  'jakoritarleite', 'The Tick']
    rk = ['beurk', 'bdvl']
    rw = ['Ransomware']
    conditions = [
        (policy['malware'].isin(bd)),
        (policy['malware'].isin(rk)),
        (policy['malware'].isin(rw))
    ]
    values = ['CnC', 'Rootkit', 'Ransomware']
    policy['malwaretype'] = np.select(conditions, values)
    
    # count different malware types and create a dict
    malwareTypes = policy['malwaretype'].value_counts().index.tolist()
    malwareOccurrences = policy['malwaretype'].value_counts().values.tolist()
    malwareTypeOcc = {malwareTypes[i]: malwareOccurrences[i] for i in range(len(malwareTypes))}
    
    # count total occurences of all malware types
    totalOccurences = sum(malwareOccurrences)
    return [malwareTypeOcc, totalOccurences, np.divide(malwareOccurrences, totalOccurences)]

createPolicy()
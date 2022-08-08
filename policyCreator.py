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

# set seed
random.seed(SEED)
print(random.random())

POLICYCOLUMNS = utils.POLICYCOLUMNS

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
            
            # add defined amount of rules  
            else:
                nRules = config['exactNumberOfPolicyRules']
            
            #print(malware[1].sample(n = nRules)) # DEBGUG
            # add defined rules to policy
            policy = policy.append(malware[1].sample(n = nRules, random_state=SEED)) #todo check what happens if nRules > n when set
    elif config['completePolicyCreation'] == True: # if this is true, comment drop_duplicates.
        print('complete policy creation')
        policy = csvPolicy
    else:
        print('expert based')

    # postprocessing
    policy['metric'] = policy['metric'].str.replace('-mean', '')
    policy = policy.drop_duplicates(subset=['metric']) # todo FIX THIS
    policy.to_csv('policy.csv', index=False)
    return policy
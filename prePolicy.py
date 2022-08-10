import glob
import os
from cv2 import detail_BestOf2NearestRangeMatcher
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import statsmodels.api as sm
import shutil
import csv
import yaml
import random

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
    print(malware[1].sample(n = nRules))
    policy = policy.append(malware[1].sample(n = nRules))

print(policy)
policy.to_csv('policy.csv', index=False)
import glob
import os
import pandas as pd
import numpy as np

# CONST
ITERATIONS = 60
OBSERVATIONS = 30
DATAPOINTS = ITERATIONS * OBSERVATIONS
HEADER_LEN = 6
COLS = ['time', 'usr', 'sys', 'idl', 'wai', 'hiq', 'siq',
        'used', 'buff', 'cach', 'free', 'files', 'inodes', 'read', 'writ', 'reads', 'writs',
        'recv', 'send', 'lis', 'act', 'syn', 'tim', 'clo',
        'int', 'csw', 'run', 'blk', 'new']


# FUNCTIONS
def loadFiles(path):
    return sorted(glob.glob(path+'/*.csv'))

def generateDF(path):
    # load all csv
    healthyFiles = loadFiles(path)

    # convert csv to df
    frames = []
    for file in healthyFiles:
        df = pd.read_csv(file, skiprows = HEADER_LEN + 1, header = None)
        # make df consistent
        # "13.749,"" will add a new col, wheras "13.749" will not
        # check if last col has any NaN
        if(df.iloc[:,-1:].isnull().values.any()):
            df = df.iloc[:, :-1] # remove last col (NaN)
        frames.append(df)
    # merge df and set header
    df = pd.concat(frames)
    df.columns = COLS

    # remove duplicates
    df = df.drop_duplicates(subset=['time'])

    # adjust size
    df = df.iloc[:DATAPOINTS,:]
    return df


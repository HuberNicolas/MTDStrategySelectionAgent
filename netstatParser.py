## Imports
import pandas as pd
import numpy as np
import csv
import re
def rreplace(s, old, new, occurrence):
    li = s.rsplit(old, occurrence)
    return new.join(li)

TIMEFORMAT = '%Y-%m-%d %H:%M:%S'
TIMECOL = 'timestamp'

def fixYear(df):
    df[TIMECOL] = pd.to_datetime(df[TIMECOL], format=TIMEFORMAT)
    return df


def reindex(df):
    df = df.sort_values(by=TIMECOL)
    df = df.set_index(TIMECOL)
    return df
def createNetstat():
    with open('netstat.csv','w') as ff:
        writer = csv.writer(ff)
        with open('log.txt','r') as f:
            ts = ''
            for line in f.readlines():
                
                timestamp = re.findall(
                '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]_[0-9][0-9]-[0-9][0-9]-[0-9][0-9]', line)
                
                if timestamp != []:
                    #'%Y-%d-%m %H:%M:%S'
                    ts = timestamp[0]
                    ts = ts.replace('_', ' ')
                    ts = rreplace(ts, '-', ':', 2)
                    pass
                else:
                    l = re.sub('\s+',' ',line) # multiple spaces to one
                    l = l.replace(' ', ',') # space to ','
                    l = l.replace(':', ',') # space to ','
                    l = l[:-1] #remove last ','
                    entries = l.split(',') # create list
                    entries = [ts] + entries # append ts at beginning
                    writer.writerow(entries)

    df = pd.read_csv("netstat.csv")
    # netstat -ent
    # Proto Recv-Q Send-Q Local Address Foreign Address State User Inode 
    df.columns = ['timestamp', 'protocol', 'recv-q', 'send-q', 'local address', 'local port', 'foreign address', 'foreign port', 'state', 'user', 'inode']
    df = fixYear(df)
    df = reindex(df)
    print(df)
    print(df.groupby('timestamp').count())
    print(df.groupby('timestamp').count()['protocol'])

    return df
createNetstat()
    
        
import pandas as pd

# CONST
TIMEFORMAT = '%Y-%d-%m %H:%M:%S'
YEARSTRING = '2022-'
TIMECOL = 'time'

# FUNCTIONS
def fixYear(df):
    df[TIMECOL] = YEARSTRING + df[TIMECOL].astype(str)
    df[TIMECOL] = pd.to_datetime(df[TIMECOL],format= TIMEFORMAT)
    return df
    
def reindex(df, keep):
    df = df.sort_values(by=TIMECOL)
    df = df.iloc[::keep] # only take every keepth-entry
    df = df.set_index(TIMECOL)
    return df

def saveCSV(df, prefix, path):
    startDate = df.iloc[0].name.strftime('%Y-%m-%d')
    startTime = df.iloc[0].name.strftime('%X')
    endDate = df.iloc[-1].name.strftime('%Y-%m-%d')
    endTime = df.iloc[-1].name.strftime('%X')
    name = "{}{} {}-{}_{}-{}({}).csv".format(path, prefix, startDate.replace('-',''), startTime.replace(':',''), endDate.replace('-',''), endTime.replace(':',''), str(df.shape[0]))
    df.to_csv(name, index=False, header=True)

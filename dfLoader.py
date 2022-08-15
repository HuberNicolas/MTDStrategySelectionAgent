import glob
import os
import pandas as pd


# CONST
DATAPATH = 'data/'
HEADER_LEN = 6
DATAPOINTS = 1800
TIMEFORMAT = '%Y-%d-%m %H:%M:%S'
YEARSTRING = '2022-'
TIMECOL = 'time'
KEEP = 1
COLNAMES = [
    'time',
    'usr',
    'sys',
    'idl',
    'wai',
    'hiq',
    'siq',
    'used',
    'buff',
    'cach',
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
    'tot',
    'tcp',
    'udp',
    'raw',
    'frg',
    'int',
    'csw',
    'run',
    'blk',
    'new',
]

# FUNCTIONS


def getDatasetFolderNames(path):
    return os.listdir(path)


def getCSVName(folderName):
    return glob.glob('data/'+folderName+'/*.csv')[0]


def getDirPath(path):
    dirPathList = []
    for root, dirs, files in os.walk(path, topdown=False):
        for name in dirs:
            dirPathList.append(os.path.join(root, name))
    return dirPathList


def generateDF(csvFilePath):
    df = pd.read_csv(csvFilePath, skiprows=HEADER_LEN + 1, header=None)
    # "13.749,"" will add a new col, wheras "13.749" will not
    # check if last col has any Na
    if (df.iloc[:, -1:].isnull().values.any()):
        df = df.iloc[:, :-1]  # remove last col (NaN)
    df.columns = COLNAMES
    # remove duplicates
    df = df.drop_duplicates(subset=['time'])  # todo should not be necessary
    # remove 1st row since its the avg of the current uptime
    df = df.iloc[1:]
    # adjust size
    df = df.iloc[:DATAPOINTS, :]
    return df


def fixYear(df):
    df[TIMECOL] = YEARSTRING + df[TIMECOL].astype(str)
    df[TIMECOL] = pd.to_datetime(df[TIMECOL], format=TIMEFORMAT)
    return df


def reindex(df, keep):
    df = df.sort_values(by=TIMECOL)
    df = df.iloc[::keep]  # only take every keepth-entry
    df = df.set_index(TIMECOL)
    return df


def saveCSV(df, prefix, path):
    startDate = df.iloc[0].name.strftime('%Y-%m-%d')
    startTime = df.iloc[0].name.strftime('%X')
    endDate = df.iloc[-1].name.strftime('%Y-%m-%d')
    endTime = df.iloc[-1].name.strftime('%X')
    name = "{}{} {}-{}_{}-{}({}).csv".format(path, prefix, startDate.replace('-', ''), startTime.replace(
        ':', ''), endDate.replace('-', ''), endTime.replace(':', ''), str(df.shape[0]))
    df.to_csv(name, index=False, header=True)


def main():
    datasetDirPaths = getDirPath(DATAPATH)
    datasetNames = []
    dataframes = []

    for dsDirPath in datasetDirPaths:
        # extract foldername from path
        datasetName = dsDirPath.split('/', 1)[1]
        datasetNames.append(datasetName)

        # generate dataframe
        csvFilePath = glob.glob(dsDirPath+'/*.csv')[0]
        df = generateDF(csvFilePath=csvFilePath)

        # postprocess
        df = fixYear(df=df)
        df = reindex(df=df, keep=KEEP)

        # save copy
        saveCSV(df=df, prefix=datasetName, path=DATAPATH)

        # append to dataframe list
        dataframes.append(df)
    return (datasetNames, dataframes)


if __name__ == "__main__":
    main()

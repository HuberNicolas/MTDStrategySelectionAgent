import os
import preprocess
import postprocess

# 29 inkl. time = 0-28 = 1-29
# 28 parameters + time (index)

# CONST
KEEP = 1

# FUNCTIONS
def getDirPath(path):
    dirPathList = []
    for root, dirs, files in os.walk(path, topdown=False):
        for name in dirs:
            dirPathList.append(os.path.join(root, name))
    return dirPathList

def getDirNames(path):
    dirNameList = []
    for entry_name in os.listdir(path):
        entry_path = os.path.join(path, entry_name)
        if os.path.isdir(entry_path):
            dirNameList.append(entry_name)
    return dirNameList


observations = getDirPath('data/')
datasets = []
for dataset in observations:
    datasetName = dataset.split('/', 1)[1] # extract foldername from path
    df = preprocess.generateDF(dataset)
    df = postprocess.fixYear(df=df)
    df = postprocess.reindex(df=df, keep=KEEP)
    postprocess.saveCSV(df=df, prefix=datasetName, path='data/')



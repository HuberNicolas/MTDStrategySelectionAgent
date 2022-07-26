import preprocess
import postprocess

# 29 inkl. time = 0-28 = 1-29
# 28 parameters + time (index)

# CONST
KEEP = 1

healthy = preprocess.generateDF('data/01csv-healthy')
healthy = postprocess.fixYear(df=healthy)
healthy = postprocess.reindex(df=healthy, keep=KEEP)
postprocess.saveCSV(df=healthy, prefix='healthy')

bashlite = preprocess.generateDF('data/02csv-infected(BASHLITE)')
bashlite = postprocess.fixYear(df=bashlite)
bashlite = postprocess.reindex(df=bashlite, keep=KEEP)
postprocess.saveCSV(df=healthy, prefix='bashlite')




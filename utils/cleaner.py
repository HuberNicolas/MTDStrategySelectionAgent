import os
import glob

if os.path.exists('observer.log'):
    os.remove('observer.log')

if os.path.exists('deployer.log'):
    os.remove('deployer.log')

for outpath in glob.iglob(os.path.join('/root/MTDPolicy/', '*.out')):
    os.remove(outpath)
for txtpath in glob.iglob(os.path.join('/root/MTDPolicy/', '*.txt')):
    os.remove(txtpath)
for csvpath in glob.iglob(os.path.join('/root/MTDPolicy/data/csv', '*.csv')):
    os.remove(csvpath)

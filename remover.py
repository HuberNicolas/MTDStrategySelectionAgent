import shutil
import os

FOLDERS = ['timeline', 'std', 'decompose']
print(os.getcwd())
os.chdir('data/plots')

for folder in FOLDERS:
    shutil.rmtree(folder)
    os.makedirs(folder)
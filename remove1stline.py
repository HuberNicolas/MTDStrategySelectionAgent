import glob
import os
from queue import Empty
firstline = 8

def remove_line(fileName,lineToSkip):
    """ Removes a given line from a file """
    with open(fileName,'r') as read_file:
        lines = read_file.readlines()

    currentLine = 1
    with open(fileName,'w') as write_file:
        for line in lines:
            if currentLine == lineToSkip:
                pass
            else:
                write_file.write(line)
	
            currentLine += 1

# call the function, passing the file and line to skip
#remove_line('2022-07-26-10-20-20-log.csv', firstline)


folders = os.listdir()
print(os.listdir())
for folder in folders:
    files = glob.glob('{}/*.csv'.format(folder))
    if len(files) != 0:
        for file in files:
            remove_line(file, firstline)
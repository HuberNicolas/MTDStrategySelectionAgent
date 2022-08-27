import os
'''
    For the given path, get the List of all files in the directory tree 
'''
def getListOfFiles(dirName):
    # create a list of file and sub directories 
    # names in the given directory 
    listOfFile = os.listdir(dirName)
    allFiles = list()
    # Iterate over all the entries
    for entry in listOfFile:
        # Create full path
        fullPath = os.path.join(dirName, entry)
        # If entry is a directory then get the list of files in this directory 
        if os.path.isdir(fullPath):
            allFiles = allFiles + getListOfFiles(fullPath)
        else:
            allFiles.append(fullPath)
                
    return allFiles        
def main():
    file_object = open('sample-data-ranswomware.txt', 'a')
    dirName = '/root/sample-data';
    
    # Get the list of all files in directory tree at given path
    listOfFiles = getListOfFiles(dirName)
    
    # Print the files
    fileCounter = 1
    for elem in listOfFiles:
        file_object.writelines('{}: {}\n'.format(fileCounter, elem))
        print(elem)
        fileCounter += 1
        
        
        
        
if __name__ == '__main__':
    main()
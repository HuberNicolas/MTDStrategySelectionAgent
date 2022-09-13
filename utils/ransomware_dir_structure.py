import os


def getListOfFiles(dirName):
    listOfFile = os.listdir(dirName)
    allFiles = list()
    for entry in listOfFile:
        fullPath = os.path.join(dirName, entry)
        if os.path.isdir(fullPath):
            allFiles = allFiles + getListOfFiles(fullPath)
        else:
            allFiles.append(fullPath)

    return allFiles


def main():
    file_object = open('sample-data-ranswomware.txt', 'a')
    dirName = '/root/sample-data'
    listOfFiles = getListOfFiles(dirName)

    # Print the files
    fileCounter = 1
    for elem in listOfFiles:
        file_object.writelines('{}: {}\n'.format(fileCounter, elem))
        print(elem)
        fileCounter += 1


if __name__ == '__main__':
    main()

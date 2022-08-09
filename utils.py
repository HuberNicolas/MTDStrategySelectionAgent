POLICYCOLUMNS = ['malware', 'metric', 'sign', 'threshold']

CNC = ['httpbackdoor', 'BASHLITE', 'backdoor',  'jakoritarleite', 'The Tick']
ROOTKIT = ['beurk', 'bdvl']
RANSOMWARE = ['Ransomware']
MALWARECATEGORIES = ['CnC', 'Rootkit', 'Ransomware']

CAT = [
    'usr',
    'sys',
    'idl',
    'wai',
    'hiq',
    'siq',
    'used',
    'buff',
    'cache',
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
    'int',
    'csw',
    'run',
    'blk',
    'new',
]

METRICS = [
    'usr',
    'sys',
    'idl',
    'wai',
    'hiq',
    'siq',
    'used',
    'buff',
    'cache',
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
    'int',
    'csw',
    'run',
    'blk',
    'new',
]

COLS = ['malware', 'metric', 'sign', 'threshold']


MALWARETYPES = {
    'BASHLITE': 'CnC',
    'Ransomware': 'Ransomware',
    'httpbackdoor': 'CnC',  # change to CnC
    'jakoritarleite': 'CnC',  # change to CnC
    'The Tick': 'CnC',  # change to CnC
    'bdvl': 'Rootkit',
    'beurk': 'Rootkit'
}

CLASSIFIER = {
    'CnC': 0,
    'Ransomware': 0,
    'Rootkit': 0
}

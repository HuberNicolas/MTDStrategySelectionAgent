POLICYCOLUMNS = ['malware', 'metric', 'sign', 'threshold']

CNC = ['httpbackdoor', 'BASHLITE', 'backdoor',  'jakoritarleite', 'The Tick']
ROOTKIT = ['beurk', 'bdvl']
RANSOMWARE = ['Ransomware']
MALWARECATEGORIES = ['CnC', 'Rootkit', 'Ransomware']

malwareIndicatorTable = {
        'BASHLITE': 0,
        'Ransomware': 0,
        'httpbackdoor': 0,
        'jakoritarleite': 0,
        'The Tick': 0,
        'bdvl': 0,
        'beurk': 0
    }

malwareTypeIndicatorTable = {
    'CnC': 0,
    'Ransomware': 0,
    'Rootkit': 0
}

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
    'httpbackdoor': 'CnC',
    'jakoritarleite': 'CnC',
    'The Tick': 'CnC',
    'bdvl': 'Rootkit',
    'beurk': 'Rootkit'
}
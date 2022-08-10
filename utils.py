POLICYCOLUMNS = ['malware', 'metric', 'sign', 'threshold']

CNC = ['httpbackdoor', 'BASHLITE', 'backdoor', 'thetick']
ROOTKIT = ['beurk', 'bdvl']
RANSOMWARE = ['Ransomware-PoC']
MALWARECATEGORIES = ['CnC', 'Rootkit', 'Ransomware']

malwareIndicatorTable = {
        'BASHLITE': 0,
        'Ransomware-PoC': 0,
        'httpbackdoor': 0,
        'backdoor': 0,
        'thetick': 0,
        'bdvl': 0,
        'beurk': 0
    }

malwareTypeIndicatorTable = {
    'CnC': 0,
    'Ransomware': 0,
    'Rootkit': 0
}

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

MALWARETYPES = {
    'BASHLITE': 'CnC',
    'Ransomware-PoC': 'Ransomware',
    'httpbackdoor': 'CnC',
    'backdoor': 'CnC',
    'thetick': 'CnC',
    'bdvl': 'Rootkit',
    'beurk': 'Rootkit'
}
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
POLICYCOLUMNS = ['malware', 'metric', 'sign', 'threshold']

MALWARETYPES = {
    'BASHLITE':'Rootkit',
    'Ransomware':'Ransomware',
    'httpbackdoor':'Ransomware', # change to CnC
    'jakoritarleite':'Ransomware', # change to CnC
    'The Tick':'Ransomware', # change to CnC
    'bdvl':'Rootkit',
    'beurk':'Rootkit'
    }
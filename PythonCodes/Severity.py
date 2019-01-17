from enum import Enum

'''
Severity module used for enumerating the severity of Vulnerabilities
'''
class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
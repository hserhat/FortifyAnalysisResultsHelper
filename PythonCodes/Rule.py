from PythonCodes.Severity import  Severity

'''
Rule module mostly includes information about severity of the vulnerabilities, it also contains calculate severity method
which is the logic of calculating the severity of vulnerabilities
'''
class Rule:
    def __init__(self, ruleId, probability, accuracy, impact):
        self.probability = float(probability)
        self.ruleId = ruleId
        self.accuracy = float(accuracy)
        self.impact = float(impact)

    def calculateSeverity(self, confidence, metaProb):
        if metaProb >= 0:
            self.probability = metaProb
        likelihood = (self.accuracy * self.probability * confidence) / 25
        if self.impact >= 2.5:
            if likelihood >= 2.5:
                return Severity.CRITICAL
            else:
                return Severity.HIGH
        else:
            if likelihood >= 2.5:
                return Severity.MEDIUM
            else:
                return Severity.LOW

    def getRuleId(self):
        return self.ruleId
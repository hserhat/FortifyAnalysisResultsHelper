"""
Description class which stores information about each desc
"""
class Description:
    def __init__(self, ruleid, abstract, explanation, recommendations):
        self.ruleid = ruleid
        self.abstract = abstract
        self.explanation = explanation
        self.recommendations = recommendations
        self.tips = []
        self.references = []

    def getRuleId(self):
        return self.ruleid

    def getAbstract(self):
        return self.abstract

    def getExplanation(self):
        return self.explanation

    def getRecommendations(self):
        return self.recommendations

    def getTips(self):
        return self.tips

    def getReferences(self):
        return self.references


    def __str__(self):
        str = " Rule id is %s \n Abstract is %s\n  Explanation is %s \n Recommendations are %s \n" % (
        self.ruleid, self.abstract, self.explanation, self.recommendations)
        str += "Tips are \n"
        tips = self.getTips()
        if tips:
            for t in tips:
                str += t.getString()
                str += "\n"
        str += "References are \n"

        refs = self.getReferences()
        if refs:
            for r in refs:
                str += r.getString()
                str += "\n"
        return str

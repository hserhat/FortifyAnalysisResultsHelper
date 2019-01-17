'''
Trace class is used in TraceNode module TraceNodes may include Trace objects
'''
class Trace:
    def __init__(self):
        self.traceNodes = []

    def getTraceNodes(self):
        return self.traceNodes

    def addTraceNode(self, node):
        self.traceNodes.append(node)
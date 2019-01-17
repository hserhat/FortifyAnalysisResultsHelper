"""
TraceNode class with attributes: reason as Trace object, nodeRef for the nodes that
only has reference id, Action field: type attribute and text, SourceLocation
field: path, line and lineEnd attributes, label, isDefault
"""
from PythonCodes.Trace import Trace
class TraceNode:
    def __init__(self, reason: Trace, nodeRef, actionType, actionText, path, line, lineEnd, label):
        self.isDefault = False
        self.reason = reason
        self.nodeRef = nodeRef
        self.path = path
        self.actionType = actionType
        self.actionText = actionText
        self.label = label
        self.line = line
        self.lineEnd = lineEnd

    def getReason(self):
        return self.reason

    def getIsDefault(self):
        return self.isDefault

    def getNodeRef(self):
        return self.nodeRef

    def getActionType(self):
        return self.actionType

    def getActionText(self):
        return self.actionText

    def getPath(self):
        return self.path

    def getLine(self):
        return self.line

    def getLineEnd(self):
        return self.lineEnd

    def getLabel(self):
        return self.label
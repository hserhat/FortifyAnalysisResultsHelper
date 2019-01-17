from re import sub
import xml.etree.ElementTree as ET
from PythonCodes.Rule import Rule
from zipfile import ZipFile
from PythonCodes.Severity import Severity
from PythonCodes.Vulnerability import Vulnerability
from PythonCodes.SinkedVulnerability import SinkedVulnerability
from PythonCodes.Description import Description
from PythonCodes.TraceNode import TraceNode
from PythonCodes.Trace import Trace
from PythonCodes.ExternalEntry import ExternalEntry
from PythonCodes.Tip import  Tip
from PythonCodes.Reference import Reference

class FPR:
    def __init__(self, fprFile):
        self.fprFile = fprFile
        self.vulnerabilities = []
        self.sinkedVulnerabilities = []
        self.rules = []
        self.descriptions = []
        self.nodePool = []
        self.fileDict = {}

    def getVulnerabilities(self):
        return self.vulnerabilities


    def getSinkedVulnerabilities(self):
        return self.sinkedVulnerabilities

    def getFileDict(self):
        return self.fileDict

    def getRules(self):
        return self.rules

    def getNodePool(self):
        return self.nodePool

    def getDescriptions(self):
        return self.descriptions

    # Opens and extracts audit.fvdl from .fpr file
    def extractFVDL(self):
        zip = ZipFile(self.fprFile, 'r')
        import os
        if not os.path.exists("tmp/xmlParser"):
            os.makedirs("tmp/xmlParser")
        try:
            zip.extractall("/tmp/xmlParser")
        except KeyError:
            zip.close()
            print("Malformed FPR file")

        # extracting src-archive from zipfile
        archive=ZipFile(self.fprFile)

        for file in archive.namelist():
            if file.startswith('src-archive'):
                archive.extract(file,'website')
        zip.close()

    # Converts the fvdl file to ElementTree tree and stores its root
    def processFVDL(self):
        with open('/tmp/xmlParser/audit.fvdl') as f:
            xmlstring = f.read()
        xmlstring = sub('\\sxmlns="[^"]+"', '', xmlstring, count=1)
        self.root = ET.fromstring(xmlstring)



    def extractRules(self):
        ruls = self.root.findall('EngineData/RuleInfo/Rule')

        for rul in ruls:
            ruleId = rul.attrib['id']
            groups = rul.findall('MetaInfo/Group')
            accuracy = 0.0
            impact = 0.0
            probability = 0.0
            for group in groups:
                if group.attrib['name'] == 'Accuracy':
                    accuracy = float(group.text)
                elif group.attrib['name'] == 'Impact':
                    impact = float(group.text)
                elif group.attrib['name'] == 'Probability':
                    probability = group.text
            rule = Rule(ruleId, probability, accuracy, impact)
            self.rules.append(rule)

    # Extract Nodes with references inside UnifiedNodePool
    # taken attributes: path, line start and end, Action type, Action text and reason as another TraceNode object if it exists
    def extractNodePool(self):
        nodes = self.root.findall('UnifiedNodePool/Node')
        for node in nodes:
            tempRef = node.attrib['id']
            tempPath = node.find('SourceLocation').attrib['path']
            tempLine = node.find('SourceLocation').attrib['line']
            if ('lineEnd' in node.find('SourceLocation').attrib):
                tempLineEnd = node.find('SourceLocation').attrib['lineEnd']
            else:
                tempLineEnd = ""
            tempActionType = node.find('Action').attrib['type']
            tempActionText = node.find('Action').text
            reason = extractReason(self, node)
            tempNode = TraceNode(reason, tempRef , tempActionType, tempActionText, tempPath, tempLine, tempLineEnd, "")
            self.nodePool.append(tempNode)



    def extractVulnerabilities(self):
        temp_meta_prob = -999
        vulns = self.root.findall('Vulnerabilities/Vulnerability')
        for vuln in vulns:
            isSinked = False
            kingdom = vuln.find('ClassInfo/Kingdom').text
            category = vuln.find('ClassInfo/Type').text
            instanceid = vuln.find('InstanceInfo/InstanceID').text
            id = vuln.find('ClassInfo/ClassID').text

            if (vuln.find('InstanceInfo/MetaInfo/Group') == None):
                temp_meta_prob = -1
            else:
                temp_meta_prob = int(vuln.find('InstanceInfo/MetaInfo/Group').text)

            if (vuln.find('ClassInfo/Subtype') != None):
                category = category + ': ' + vuln.find('ClassInfo/Subtype').text
            if (vuln.find('AnalysisInfo/Unified/Context/Function') != None):
                filename = vuln.find('AnalysisInfo/Unified/Context/FunctionDeclarationSourceLocation').attrib['path']
                function = vuln.find('AnalysisInfo/Unified/Context/Function').attrib['name']
                line = vuln.find('AnalysisInfo/Unified/Trace/Primary/Entry/Node/SourceLocation').attrib['line']
            else:
                filename = vuln.find('AnalysisInfo/Unified/Trace/Primary/Entry/Node/SourceLocation').attrib['path']
                line = vuln.find('AnalysisInfo/Unified/Trace/Primary/Entry/Node/SourceLocation').attrib['line']
                function = ""
            classId = vuln.find('ClassInfo/ClassID').text
            confidence = float(vuln.find('InstanceInfo/Confidence').text)
            severity = Severity.LOW

            # Calculate severity
            self.extractRules()
            for rule in self.rules:
                if rule.getRuleId() == classId:
                    severity = rule.calculateSeverity(confidence, temp_meta_prob)
                    break

            # Gets replacement definitions and stores them as dictionary object each key corresponding to a value
            tempRep = vuln.findall('AnalysisInfo/Unified/ReplacementDefinitions/Def')
            dict = {}
            for tempDef in tempRep:
                tempKey = tempDef.attrib['key']
                tempValue = tempDef.attrib['value']
                # Check if there is sink key inside replacement definitions
                if tempKey == 'SinkFunction':
                    isSinked = True
                dict[tempKey] = tempValue

            # Get primary function location and file if they exists, if not
            # it will be extracted from trace list after vulnerability creation
            primaryFunc = ""
            bool=True
            if "PrimaryLocation.file" in dict and "PrimaryLocation.line" in dict:
                primaryFunc += dict["PrimaryLocation.file"]
                primaryFunc += ":"
                primaryFunc += dict["PrimaryLocation.line"]
                bool=False
            if "SinkLocation.file" in dict and "SinkLocation.line" in dict and bool==True:
                primaryFunc += dict["SinkLocation.file"]
                primaryFunc += ":"
                primaryFunc += dict["SinkLocation.line"]

            if( isSinked):
                sinkedVulnerability = SinkedVulnerability(id, instanceid, kingdom, category, primaryFunc, filename, severity, function, line, dict)

                # Extract traces
                traces = vuln.findall('AnalysisInfo/Unified/Trace')
                for trace in traces:
                    entries = trace.findall('Primary/Entry')
                    tempTrace = Trace()
                    for entry in entries:
                        tempTrace.addTraceNode( extractTraceNode(entry))
                    sinkedVulnerability.traces.append(tempTrace)

                # Extract external entries
                tempExt = vuln.findall('ExternalEntries/Entry')
                if tempExt != None:
                    for a in tempExt:
                        tempExtName = a.attrib['name']
                        tempExtType = a.attrib['type']
                        tempExtUrl = a.find('URL').text
                        tempEntry = ExternalEntry(tempExtName, tempExtType, tempExtUrl)
                        sinkedVulnerability.addExternalEntry(tempEntry)
                else:
                    sinkedVulnerability.externalEntries = None

                primaryFunc, filename, line = sinkedVulnerability.getDefaultTrace()
                tempRep = vuln.findall('AnalysisInfo/Unified/ReplacementDefinitions/LocationDef')
                if tempRep[ 0].attrib['key'] == "SinkLocation":
                    sinkedVulnerability.filename = tempRep[ 0].attrib['path']
                sinkedVulnerability.line = line
                if primaryFunc == "":
                    sinkedVulnerability.primaryFunction = primaryFunc
                if "SourceLocation.file" in dict and "SourceLocation.line" in dict:
                    sinkedVulnerability.sourceFunction += dict["SourceLocation.file"]
                    sinkedVulnerability.sourceFunction += ":"
                    sinkedVulnerability.sourceFunction += dict["SourceLocation.line"]
                sharedPath = vuln.find('AnalysisInfo/Unified/Context/FunctionDeclarationSourceLocation').attrib['path']
                sinkedVulnerability.sharedPath = sharedPath

                # Add the newly created and modified sinkedVulnerability to the list
                self.sinkedVulnerabilities.append(sinkedVulnerability)
            else:
                vulnerability = Vulnerability(id, instanceid, kingdom, category, primaryFunc, filename, severity, function, line, dict)

                # Extract traces
                traces = vuln.findall('AnalysisInfo/Unified/Trace')
                for trace in traces:
                    tempTrace = Trace()
                    entries = trace.findall('Primary/Entry')
                    for entry in entries:
                        tempTrace.addTraceNode( extractTraceNode(entry))
                    vulnerability.traces.append(tempTrace)

                # Extract external entries
                tempExt = vuln.findall('ExternalEntries/Entry')
                if tempExt != None:
                    for a in tempExt:
                        tempExtName = a.attrib['name']
                        tempExtType = a.attrib['type']
                        tempExtUrl = a.find('URL').text
                        tempEntry = ExternalEntry(tempExtName, tempExtType, tempExtUrl)
                        vulnerability.addExternalEntry(tempEntry)
                else:
                    vulnerability.externalEntries = None

                primaryFunc, filename, line = vulnerability.getDefaultTrace()
                vulnerability.filename = filename
                vulnerability.line = line
                if vulnerability.primaryFunction == "":
                    vulnerability.primaryFunction = primaryFunc

                # Add the newly created and modified vulnerability to the list
                self.vulnerabilities.append(vulnerability)

    # Method for printing out trace list of certain vulnerability
    def printTraceList(self, instanceid):
        for temp in self.getVulnerabilities():
            if temp.getInstanceid() == instanceid:
                temp.printTraces( self.getNodePool())
        for temp in self.getSinkedVulnerabilities():
            if temp.getInstanceid() == instanceid:
                temp.printTraces( self.getNodePool())

    # Extracts vulnerabilities with the same sink function and locations
    def extractSameSinkedVulnerabilities(self):
        for a in self.sinkedVulnerabilities:
            for b in self.sinkedVulnerabilities:
                aSinkedLocation = a.replacementDefinitions['SinkLocation.file']
                bSinkedLocation = b.replacementDefinitions['SinkLocation.file']
                aSinkedLine = a.replacementDefinitions['SinkLocation.line']
                bSinkedLine = b.replacementDefinitions['SinkLocation.line']
                aSinkedFileName=a.getFilename()
                bsinkedFileName=b.getFilename()
                aCategory = a.getCategory()
                bCategory = b.getCategory()
                aSeverity = a.getSeverity()
                bSeverity = b.getSeverity()
                if aSinkedLocation == bSinkedLocation and a.getInstanceid() != b.getInstanceid() and aSinkedLine == bSinkedLine and aCategory == bCategory and aSeverity == bSeverity and aSinkedFileName==bsinkedFileName:
                    a.sameSink.append(b.getInstanceid())
        sinkedVulnCount = len(self.getSinkedVulnerabilities())
        k = 0
        while k < sinkedVulnCount:
            a = self.getSinkedVulnerabilities()[k]
            if len(a.sameSink) == 0:
                tempVuln = Vulnerability(a.getRuleId(), a.getInstanceid(), a.getKingdom(), a.getCategory(), a.getPrimaryFunction(), a.getFilename(), a.getSeverity(), a.getFunction(), a.getLine(), a.getReplacementDefinitions())
                tempVuln.traces = a.getTraces()
                tempVuln.externalEntries = a.getExternalEntries()
                tempVuln.fileNum = a.getFileNum()
                tempVuln.description = a.getDescription()
                self.vulnerabilities.append(tempVuln)
                self.sinkedVulnerabilities.remove(a)
                k -= 1
                sinkedVulnCount -= 1
            k += 1

    def extractDescriptions(self):
        descs = self.root.findall('Description')

        for desc in descs:
            ruleid = desc.attrib['classID']
            abstract = desc.find('Abstract').text
            explanation = desc.find('Explanation').text
            recommendation = desc.find('Recommendations').text
            tempDesc = Description(ruleid, abstract, explanation, recommendation)
            tips_doc = desc.findall('Tips/Tip')

            for temp_tip in tips_doc:
                tipObj = Tip(temp_tip.text)
                tempDesc.tips.append(tipObj)
            references = desc.findall('References/Reference')

            for ref in references:
                title = ref.find('Title').text
                if (ref.find('Author') != None):
                    author = ref.find('Author').text
                else:
                    author = ""
                if (ref.find('Publisher') != None):
                    publisher = ref.find('Publisher').text
                else:
                    publisher = ""
                if (ref.find('Source') != None):
                    source = ref.find('Source').text
                else:
                    source = ""
                refObj = Reference(title, publisher, author, source)
                tempDesc.references.append(refObj)

            self.descriptions.append(tempDesc)



    def determineDescriptionIndex(self):
        for f in self.getVulnerabilities():
            for k in self.getDescriptions():
                if f.getRuleId() == k.getRuleId():
                    f.description = k
                    break
        for f in self.getSinkedVulnerabilities():
            for k in self.getDescriptions():
                if f.getRuleId() == k.getRuleId():
                    f.description = k
                    break

    def extractTraceStrings(self):
        for a in self.getVulnerabilities():
            a.tracesString = a.getTracesString()
        for a in self.getSinkedVulnerabilities():
            a.tracesString = a.getTracesString()

    def dereferenceVulnerabilities(self):
        for k in self.getVulnerabilities():
            k.dereferenceTraces(self.nodePool)
        for k in self.getSinkedVulnerabilities():
            k.dereferenceTraces(self.nodePool)

    def dereferenceDescriptions(self):
        for f in self.getVulnerabilities():
            f.dereferenceDescription()
        for f in self.getSinkedVulnerabilities():
            f.dereferenceDescription()

# Recursive function to extract all trace nodes for a given entry
def extractTraceNode(entry):
    # If a node is only a reference to a node from UnifiedNodePool, only get its reference
    if (entry.find('NodeRef') != None):
        tempNode = TraceNode(None, entry.find('NodeRef').attrib['id'], "", "", "", "", "", "")
    else:
        tempPath = entry.find('Node/SourceLocation').attrib['path']
        tempLine = entry.find('Node/SourceLocation').attrib['line']
        if(entry.find('Node/Action') != None):
            if ('type' in entry.find('Node/Action').attrib):
                tempActionType = entry.find('Node/Action').attrib['type']
            else:
                tempActionType = ""
            tempActionText = entry.find('Node/Action').text
        else:
            tempActionType = ""
            tempActionText = ""
        if( 'lineEnd' in entry.find('Node/SourceLocation').attrib):
            tempLineEnd = entry.find('Node/SourceLocation').attrib['lineEnd']
        else:
            tempLineEnd = ""
        if('label' in entry.find('Node').attrib):
            tempLabel = entry.find('Node').attrib['label']
        else:
            tempLabel = ""
        tempTrace = None

        # If reason attribute of node is another node, call this function again for it
        if ( entry.find('Node/Reason/Trace') != None):
            entries = entry.findall('Node/Reason/Trace/Primary/Entry')
            tempTrace = Trace()
            for e in entries:
                tempNode2 = extractTraceNode(e)
                tempTrace.addTraceNode(tempNode2)
        tempNode = TraceNode(tempTrace, "", tempActionType, tempActionText, tempPath, tempLine, tempLineEnd, tempLabel)
        if('isDefault' in entry.find('Node').attrib):
            tempNode.isDefault = True
    return tempNode



# Extracts reason field of nodes in UnifiedNodePool
def extractReason(self, node):
    reasons = node.findall('Reason/Trace/Primary/Entry')
    tempTrace = Trace()
    i = 0
    for reason in reasons:
        i += 1
        tempNode = TraceNode(None, reason.find('NodeRef').attrib['id'], "", "", "", "", "", "")
        tempTrace.addTraceNode(tempNode)
    if i == 0:
        tempTrace = None
    return tempTrace
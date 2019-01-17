
'''
main module contains the main method of the project in main function FPR object is created
and FPR module's methods that said (extractFVDL, processFVDL, extractVulnerabilities, extractSameSinkedVulnerabilities,
extractNodePool, extractDescriptions used for parsing the xml file
'''
import json
import os
from PythonCodes.FPR import FPR
from PythonCodes.Severity import Severity
from jinja2 import Environment, FileSystemLoader
import sys

try:
    from xlsxwriter.workbook import Workbook
except ImportError:
    print("You should install xlsxwriter library, before using this script.")



def main():

    fprfilename=input()
	#Give input fpr file path here
    #fprfilename = "/home/hserhat/Desktop/test.fpr"

    fpr = FPR(fprfilename)
    fpr.extractFVDL()
    fpr.processFVDL()
    fpr.extractVulnerabilities()
    fpr.extractSameSinkedVulnerabilities()
    fpr.extractNodePool()
    fpr.extractDescriptions()
    fpr.determineDescriptionIndex()
    fpr.dereferenceVulnerabilities()
    fpr.extractTraceStrings()
    fpr.dereferenceDescriptions()

    vulnerabilityCategories = []

    c = 0
    for f in fpr.getSinkedVulnerabilities():
        if len(f.getSameSink() ) == 0:
            c += 1

    # Create the jinja2 environment.
    current_directory = os.path.dirname(os.path.abspath(__file__))
    env = Environment(loader=FileSystemLoader(current_directory))

    #list holding numbers of categorized vulnerabilities
    severityCount = [0, 0, 0, 0]

    #arrays of arrays to categorize vulnerabilities

    templatedVulnerabilities=[]

    ### these lists are responsible for holding the categorized objects of vulnerabilities and sinkedVulnerabilities

    '''
        holds the categorized Vulnerabilities
    '''
    lowVulnerabilities=[]
    mediumVulnerabilities=[]
    highVulnerabilities=[]
    criticalVulnerabilities=[]


    '''
        holds the categorized vulnerabilities
    '''
    lowSinkedVulnerabilities=[]
    mediumSinkedVulnerabilities = []
    highSinkedVulnerabilities = []
    criticalSinkedVulnerabilities = []

    '''
        holds the removed duplicated categories of vulnerabilities
        each vulnerability belongs to its corresponding category
    '''
    lowRemovedDuplicatedVulnerabilities=[]
    mediumRemovedDuplicatedVulnerabilities=[]
    highRemovedDuplicatedVulnerabilities=[]
    criticalRemovedDuplicatedVulnerabilities=[]

    '''
        holds the removed duplicated categories of sinked vulnerabilities
        each sinked vulnerability belongs to its corresponding category
    '''
    lowSinkedRemovedDuplicatedVulnerabilities=[]
    mediumSinkedRemovedDuplicatedVulnerabilities=[]
    highSinkedRemovedDuplicatedVulnerabilities=[]
    criticalSinkedRemovedDuplicatedVulnerabilities=[]

    '''
        these lists hold the vulnerability objects that are ready to be templated in html
    '''
    dataLow = []
    dataMedium = []
    dataHigh = []
    dataCritical = []

    '''
         these lists hold the sinked vulnerability objects that are partially ready (they are not fully categorized yet)
          to be templated in html
     '''
    dataSinkedLow=[]
    dataSinkedMedium=[]
    dataSinkedHigh=[]
    dataSinkedCritical=[]

    '''
          these lists hold the sinked vulnerability objects that are  ready  to be templated in html
      '''
    dataSinkedLowUpdated= []
    dataSinkedMediumUpdated= []
    dataSinkedHighUpdated = []
    dataSinkedCriticalUpdated= []

    '''
        This method is responsible for calculating the number of severity of vulnerabilities,
        parsing the vulnerabilities according to their categories then putting them in lists defined above
        sinked vulnerabilities are categorized according to their "same sink" attribute
        
    '''
    def categorizeVulnerabilities(lowR,mediumR,highR,criticalR,lowSR,mediumSR,highSR,criticalSR):

        # calculating the number and severity of vulnerabilities
        for f in fpr.vulnerabilities:
            if f.getSeverity() == Severity.LOW:
                severityCount[0] += 1
                lowVulnerabilities.append(f)
            elif f.getSeverity() == Severity.MEDIUM:
                severityCount[1] += 1
                mediumVulnerabilities.append(f)
            elif f.getSeverity() == Severity.HIGH:
                severityCount[2] += 1
                highVulnerabilities.append(f)
            elif f.getSeverity() == Severity.CRITICAL:
                severityCount[3] += 1
                criticalVulnerabilities.append(f)



        # this process stands for removing the duplicated categories of vulnerabilities
        # (e.g. more than one vulnerability may belong to SQL Injection category
        # to put such vulnerabilities in one SQL Injection category, duplicated categories are removed
        for f in lowVulnerabilities:
            lowR.append(f.getCategory())

        lowR=list(set(lowR))

        for f in mediumVulnerabilities:
            mediumR.append(f.getCategory())


        mediumR=list(set(mediumR))

        for f in highVulnerabilities:
            highR.append(f.getCategory())

        highR=list(set(highR))

        for f in criticalVulnerabilities:
            criticalR.append(f.getCategory())

        criticalR=list(set(criticalR))


        lowR.sort()
        mediumR.sort()
        highR.sort()
        criticalR.sort()


        '''
            filling lists (datalow,datamedium,datahigh,datacritical) according to vulnerability categories
            these lists holds array of objects
            (e.g. datalow[0] = { vulnerabilityObject1,vulnerabilityObject2,vulnerabilityObject3} such objects belong to
            same vulnerability category)
            
        '''

        # dictionary logic stands for process of categorization
        # as said before vulnerabilities that share same categories are in the same index in lists
        nonlocal dataLow
        for i in range(len(lowR)):
            dataLow.append([0])
        nameDictLow={}
        tempNumLow=0

        for a in lowR:
            nameDictLow[a]=tempNumLow
            tempNumLow +=1

        '''
            appending categorized vulnerabilities to dataLow list
        '''
        for f in lowVulnerabilities:
            for k in lowVulnerabilities:
                if f.getCategory() is k.getCategory():
                    dataLow[nameDictLow[f.getCategory()]].append(f)

        for f in range(len(lowR)):
            del dataLow[f][0]


        nonlocal dataMedium
        for i in range(len(mediumR)):
            dataMedium.append([0])

        nameDictMedium = {}
        tempNumMedium = 0
        for a in mediumR:
            nameDictMedium[a] = tempNumMedium
            tempNumMedium += 1

        for f in mediumVulnerabilities:
            for k in mediumVulnerabilities:
                if f.getCategory() is k.getCategory():
                    dataMedium[nameDictMedium[f.getCategory()]].append(f)

        for f in range(len(mediumR)):
            del dataMedium[f][0]



        nonlocal dataHigh
        for i in range(len(highR)):
            dataHigh.append([0])

        nameDictHigh={}
        tempNumHigh=0

        for a in highR:
            nameDictHigh[a]=tempNumHigh
            tempNumHigh+=1

        for f in highVulnerabilities:
            for k in highVulnerabilities:
                if f.getCategory() is k.getCategory():
                    dataHigh[nameDictHigh[f.getCategory()]].append(f)

        for f in range(len(highR)):
            del dataHigh[f][0]


        nonlocal dataCritical
        for i in range(len(criticalR)):
            dataCritical.append([0])

        nameDictCritical={}
        tempNumCritical=0

        for a  in criticalR:
            nameDictCritical[a]=tempNumCritical
            tempNumCritical+=1
        for f in criticalVulnerabilities:
            for k in criticalVulnerabilities:
                if f.getCategory() is k.getCategory():
                    dataCritical[nameDictCritical[f.getCategory()]].append(f)

        for f in range(len(criticalR)):
            del dataCritical[f][0]



        '''
              calculating the number and severity of sinked vulnerabilities
        '''
        for f in fpr.getSinkedVulnerabilities():
            if f.getSeverity() == Severity.LOW:
                severityCount[0] += 1
                lowSinkedVulnerabilities.append(f)
            elif f.getSeverity() == Severity.MEDIUM:
                severityCount[1] += 1
                mediumSinkedVulnerabilities.append(f)
            elif f.getSeverity() == Severity.HIGH:
                severityCount[2] += 1
                highSinkedVulnerabilities.append(f)
            elif f.getSeverity() == Severity.CRITICAL:
                severityCount[3] += 1
                criticalSinkedVulnerabilities.append(f)
            '''
            this process stands for removing the duplicated categories of sinked vulnerabilities
            (e.g. more than one vulnerability may belong to SQL Injection category
            to put such vulnerabilities in one SQL Injection category, duplicated categories are removed
             '''
        nonlocal dataSinkedLow

        for f in lowSinkedVulnerabilities:
            lowSR.append(f.getCategory())

        lowSR = list(set(lowSR))

        lowSR.sort()

        for i in range(len(lowSinkedVulnerabilities)):
            dataSinkedLow.append([0])

        nameSinkedDictLow = {}
        tempNumSinkedLow = 0

        for a in lowSinkedVulnerabilities:
            nameSinkedDictLow[a.getInstanceid()] = tempNumSinkedLow
            tempNumSinkedLow += 1

        '''
            any sinked object has "same sink" attribute, same sink contains Instance id's that is the shared sink for
            sinkedvulnerability object
            this process collects sinkedVulnerability objects that have the same sink and put them into same 
            index of dataSinkedLow
        '''
        for f in lowSinkedVulnerabilities:
            bool=False
            for k in lowSinkedVulnerabilities:
                if f.getCategory() == k.getCategory() and f.getInstanceid() in k.sameSink:
                    if bool == False:
                        dataSinkedLow[nameSinkedDictLow[f.getInstanceid()]].append(f)
                    dataSinkedLow[nameSinkedDictLow[f.getInstanceid()]].append(k)
                    bool=True

        for f in range(len(lowSinkedVulnerabilities)):
            del dataSinkedLow[f][0]

        nonlocal dataSinkedLowUpdated

        '''
            dataSinkedLow contains array of objects of same sinkedvulnerability objects yet it has N times of it
            (e.g. sinkedVuln1 has same sink attribute with 3 sinkedVuln object dataSinkedLow contains 3 times of the same
            sinkedvuln objects)
            Such duplication is removed in process below
            removed duplicated objects of array of Sinkedvulns are in dataSinkedLowUpdated list 
        '''
        for k in dataSinkedLow:
            bool = False
            for a in dataSinkedLowUpdated:
                for b in k:
                    if b in a:
                        bool = True
            if bool == False:
                dataSinkedLowUpdated.append(k)

        '''
        this process stands for removing the duplicated categories of sinked vulnerabilities
        (e.g. more than one vulnerability may belong to SQL Injection category
        to put such vulnerabilities in one SQL Injection category, duplicated categories are removed
         '''
        nonlocal dataSinkedMedium

        for f in mediumSinkedVulnerabilities:
            mediumSR.append(f.getCategory())

        mediumSR = list(set(mediumSR))

        mediumSR.sort()

        for i in range(len(mediumSinkedVulnerabilities)):
            dataSinkedMedium.append([0])

        nameSinkedDictMedium = {}
        tempNumSinkedMedium = 0


        for a in mediumSinkedVulnerabilities:
            nameSinkedDictMedium[a.getInstanceid()] = tempNumSinkedMedium
            tempNumSinkedMedium += 1


        '''
            any sinked object has "same sink" attribute, same sink contains Instance id's that is the shared sink for
            sinkedvulnerability object
            this process collects sinkedVulnerability objects that have the same sink and put them into same 
            index of dataSinkedMedium
        '''

        for f in mediumSinkedVulnerabilities:
            bool=False
            for k in mediumSinkedVulnerabilities:
                if f.getCategory() == k.getCategory() and f.getInstanceid() in k.sameSink:
                    if bool == False:
                        dataSinkedMedium[nameSinkedDictMedium[f.getInstanceid()]].append(f)
                    dataSinkedMedium[nameSinkedDictMedium[f.getInstanceid()]].append(k)
                    bool=True

        for f in range(len(mediumSinkedVulnerabilities)):
            del dataSinkedMedium[f][0]

        nonlocal dataSinkedMediumUpdated

        '''
            dataSinkedMedium contains array of objects of same sinkedvulnerability objects yet it has N times of it
            (e.g. sinkedVuln1 has same sink attribute with 3 sinkedVuln object dataSinkedMedium contains 3 times of the same
            sinkedvuln objects)
            Such duplication is removed in process below
            removed duplicated objects of array of Sinkedvulns are in dataSinkedMediumUpdated list 
        '''

        for k in dataSinkedMedium:
            bool = False
            for a in dataSinkedMediumUpdated:
                for b in k:
                    if b in a:
                        bool = True
            if bool == False:
                dataSinkedMediumUpdated.append(k)

        '''
          this process stands for removing the duplicated categories of sinked vulnerabilities
          (e.g. more than one vulnerability may belong to SQL Injection category
          to put such vulnerabilities in one SQL Injection category, duplicated categories are removed
        '''

        nonlocal dataSinkedHigh

        for f in highSinkedVulnerabilities:
            highSR.append(f.getCategory())

        highSR = list(set(highSR))

        highSR.sort()

        for i in range(len(highSinkedVulnerabilities)):
            dataSinkedHigh.append([0])

        nameSinkedDictHigh = {}
        tempNumSinkedHigh = 0

        for a in highSinkedVulnerabilities:
            nameSinkedDictHigh[a.getInstanceid()] = tempNumSinkedHigh
            tempNumSinkedHigh += 1



        '''
            any sinked object has "same sink" attribute, same sink contains Instance id's that is the shared sink for
            sinkedvulnerability object
            this process collects sinkedVulnerability objects that have the same sink and put them into same 
            index of dataSinkedHigh
        '''

        for f in highSinkedVulnerabilities:
            bool=False
            for k in highSinkedVulnerabilities:
                if f.getCategory() == k.getCategory() and f.getInstanceid() in k.sameSink:
                    if bool == False:
                        dataSinkedHigh[nameSinkedDictHigh[f.getInstanceid()]].append(f)
                    dataSinkedHigh[nameSinkedDictHigh[f.getInstanceid()]].append(k)
                    bool=True

        for f in range(len(highSinkedVulnerabilities)):
            del dataSinkedHigh[f][0]

        nonlocal dataSinkedHighUpdated



        '''
            dataSinkedHigh contains array of objects of same sinkedvulnerability objects yet it has N times of it
            (e.g. sinkedVuln1 has same sink attribute with 3 sinkedVuln object dataSinkedHigh contains 3 times of the same
            sinkedvuln objects)
            Such duplication is removed in process below
            removed duplicated objects of array of Sinkedvulns are in dataSinkedHighUpdated list 
        '''

        for k in dataSinkedHigh:
            bool = False
            for a in dataSinkedHighUpdated:
                for b in k:
                    if b in a:
                        bool = True
            if bool == False:
                dataSinkedHighUpdated.append(k)

        '''
          this process stands for removing the duplicated categories of sinked vulnerabilities
          (e.g. more than one vulnerability may belong to SQL Injection category
          to put such vulnerabilities in one SQL Injection category, duplicated categories are removed
        '''

        nonlocal dataSinkedCritical

        for f in criticalSinkedVulnerabilities:
            criticalSR.append(f.getCategory())

        criticalSR = list(set(criticalSR))

        criticalSR.sort()

        for i in range(len(criticalSinkedVulnerabilities)):
            dataSinkedCritical.append([0])

        nameSinkedDictCritical = {}
        tempNumSinkedCritical = 0

        for a in criticalSinkedVulnerabilities:
            nameSinkedDictCritical[a.getInstanceid()] = tempNumSinkedCritical
            tempNumSinkedCritical += 1

        '''
            any sinked object has "same sink" attribute, same sink contains Instance id's that is the shared sink for
            sinkedvulnerability object
            this process collects sinkedVulnerability objects that have the same sink and put them into same 
            index of dataSinkedHigh
        '''

        for f in criticalSinkedVulnerabilities:
            bool=False
            for k in criticalSinkedVulnerabilities:
                if f.getCategory() == k.getCategory() and f.getInstanceid() in k.sameSink:
                    if bool == False:
                        dataSinkedCritical[nameSinkedDictCritical[f.getInstanceid()]].append(f)
                    dataSinkedCritical[nameSinkedDictCritical[f.getInstanceid()]].append(k)
                    bool=True

        for f in range(len(criticalSinkedVulnerabilities)):
            del dataSinkedCritical[f][0]

        nonlocal dataSinkedCriticalUpdated

        '''
             dataSinkedCritical contains array of objects of same sinkedvulnerability objects yet it has N times of it
             (e.g. sinkedVuln1 has same sink attribute with 3 sinkedVuln object dataSinkedCritical contains 3 times of the same
             sinkedvuln objects)
             Such duplication is removed in process below
             removed duplicated objects of array of Sinkedvulns are in dataSinkedCriticalUpdated list 
         '''

        for k in dataSinkedCritical:
            bool = False
            for a in dataSinkedCriticalUpdated:
                for b in k:
                    if b in a:
                        bool = True
            if bool == False:
                dataSinkedCriticalUpdated.append(k)

        return lowR, mediumR, highR, criticalR, lowSR, mediumSR, highSR, criticalSR

    categorizeVulnerabilities(lowRemovedDuplicatedVulnerabilities, mediumRemovedDuplicatedVulnerabilities,highRemovedDuplicatedVulnerabilities,criticalRemovedDuplicatedVulnerabilities,lowSinkedRemovedDuplicatedVulnerabilities,mediumSinkedRemovedDuplicatedVulnerabilities,highSinkedRemovedDuplicatedVulnerabilities,criticalSinkedRemovedDuplicatedVulnerabilities)


    jsonObjects = []
    def writeJsonData():
        nonlocal jsonObjects
        data = {}

        for i in range(len(fpr.vulnerabilities)):
            tipsStr=''
            referencesStr=''

            for j in fpr.vulnerabilities[i].getDescription().tips:
                tipsStr+=j.getString()

            tipsStr += "\n"

            for q in fpr.vulnerabilities[i].getDescription().references:
                referencesStr+=q.getString()

            data[fpr.vulnerabilities[i].getInstanceid()]={
                'Rule id' : fpr.vulnerabilities[i].getDescription().getRuleId(),
                'Abstract' :  fpr.vulnerabilities[i].getDescription().getAbstract(),
                'Explanation': fpr.vulnerabilities[i].getDescription().getExplanation(),
                'Recommendations' : fpr.vulnerabilities[i].getDescription().getRecommendations(),
                'Tips': tipsStr,
                'References' : referencesStr
            }

        for i in range(len(fpr.sinkedVulnerabilities)):
            tipsStr = ''
            referencesStr = ''

            for j in fpr.sinkedVulnerabilities[i].getDescription().tips:
                tipsStr += j.getString() + "\n"

            tipsStr += "\n"

            for q in fpr.sinkedVulnerabilities[i].getDescription().references:
                referencesStr += q.getString()

            data[fpr.sinkedVulnerabilities[i].getInstanceid()]={
                'Ruleid' : fpr.sinkedVulnerabilities[i].getDescription().getRuleId(),
                'Abstract' :  fpr.sinkedVulnerabilities[i].getDescription().getAbstract(),
                'Explanation': fpr.sinkedVulnerabilities[i].getDescription().getExplanation(),
                'Recommendations' : fpr.sinkedVulnerabilities[i].getDescription().getRecommendations(),
                'Tips': tipsStr,
                'References' : referencesStr
            }

        with open('website/jsonData.txt', 'w') as outfile:
            json.dump(data, outfile)
        return data

    json1=writeJsonData()



    fileDict = fpr.getFileDict()

    str = env.get_template('website/index.html').render(
        dataCritical = dataCritical,
        dataMedium=dataMedium,
        dataLow=dataLow,
        dataHigh=dataHigh,
        dataSinkedCritical=dataSinkedCriticalUpdated,
        dataSinkedHigh=dataSinkedHighUpdated,
        dataSinkedMedium=dataSinkedMediumUpdated,
        dataSinkedLow=dataSinkedLowUpdated,
        fileDict=fileDict,
        SeverityLow=severityCount[0],
        SeverityMedium=severityCount[1],
        SeverityHigh=severityCount[2],
        SeverityCritical=severityCount[3])


    f = open("website/templated.html", "w+")

    f.write(str)
    f.close()


main()

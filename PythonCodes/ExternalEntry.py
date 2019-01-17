class ExternalEntry:
    def __init__(self, name, type, url):
        self.name = name
        self.type = type
        self.url = url

    def getName(self):
        return self.name

    def getType(self):
        return self.type

    def getUrl(self):
        return self.url


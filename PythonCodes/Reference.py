"""
Reference class that stores information about references in single description
"""
class Reference:
    def __init__(self, title, publisher, source, author):
        self.title = title
        self.publisher = publisher
        self.source = source
        self.author = author

    def getTitle(self):
        return self.title

    def getPublisher(self):
        return self.publisher

    def getSource(self):
        return self.source

    def getAuthor(self):
        return self.author

    def getString(self):
        str = ""
        if self.title != "":
            str += "Title is: "
            str += self.title + "\n"
        if self.publisher != "":
            str += "Publisher is: "
            str += self.publisher + "\n"
        if self.source != "":
            str += "Source is: "
            str += self.source + "\n"
        if self.author != "":
            str += "Author is: "
            str += self.author + "\n"
        str += "\n"
        return str;

    def __str__(self):
        return " Title is %s \n Publisher is %s \n Source is %s\n  Author is %s\n " % (self.title, self.publisher, self.source, self.author)

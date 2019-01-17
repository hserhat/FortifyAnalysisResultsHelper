class Tip:
    def __init__(self, tip):
        self.tip = tip

    def getTip(self):
        return self.tip

    def getString(self):
        str = " Tip: "
        str += self.tip
        return str;

    def __str__(self):
        return " Tip: %s\n " % (self.tip)

import re
import argparse

class GenericParser:

    @staticmethod
    def parseNTLMLine(ntlmLine : str):
        """
        Parse an individual NTLM line
        username:1150:aad3b435b51404eeaad3b435b51404ee:b53e2c85b653d4ccff905d0b1ff06f53:::
        :param ntlmLine: The line to pass
        """

        match = re.search(":(\w+):::", ntlmLine)
        if match:
            return match.group(1)

class OutputParser:
    """
    Take a hashcat potfile with passwords
    put the password back into the original cracking file or source
    """

    def __init__(self, potFilePath : str):
        self.hashToPass = {}
        with open(potFilePath, encoding="utf-8") as f:
            for line in f:
                split = line.rstrip().split(":")
                self.hashToPass[split[0]] = split[1]
        print("Loaded {} cracked passwords from {}".format(len(self.hashToPass), potFilePath))

    def mergeOutputFile(self, outputFilePath : str, fileType : str):
        """
        Take the original file and put the password back in
        """
        count = 0
        with open("merged_" + outputFilePath, "w", encoding="utf-8") as o:
            with open(outputFilePath, encoding="utf-8") as f:
                for line in f:
                    line = line.lower()

                    if fileType == "raw":
                        hash = line.rstrip()
                    elif fileType == "ntds":
                        hash = GenericParser.parseNTLMLine(line)

                    #lookup hash
                    password = "<NOTCRACKED>"
                    if hash in self.hashToPass:
                        password = self.hashToPass[hash]
                        count += 1
                    o.write(password + ", " + line)
        print("{} passwords were cracked and put into {}".format(count, outputFilePath))

class InputParser:
    """
    Take an input file or string of hashes (e.g NTDS).
    Convert into a format that hashcat can crack
    """
    def __init__(self):
        self.uniqueHashes = set()

    def saveUniqueHashesToFile(self, filePath : str):
        with open(filePath, 'w', encoding='utf-8') as f:
            for uniqueHash in self.uniqueHashes:
                f.write(uniqueHash + "\n")
        print("Just saved hashes to {}. Crack this file with hashcat!".format(filePath))

    def parseFile(self, filePath : str, fileType: str):
        with open(filePath) as f:
            for line in f:
                if fileType == "ntds":
                    ntlmHash = GenericParser.parseNTLMLine(line)
                    self.uniqueHashes.add(ntlmHash)
        print("Just parsed {} {} hashes".format(len(self.uniqueHashes), fileType))

if __name__ == "__main__":

    argparser = argparse.ArgumentParser()
    argparser.add_argument("--type", help="The type of file to crack")
    argparser.add_argument("--input", help="The input file containing hashes")
    argparser.add_argument("--original", help="The original file to enrich with cracked passwords")
    argparser.add_argument("--potfile", help="The hashcat pot file to take passwords from")
    args = argparser.parse_args()

    if args.type == "ntds" and args.input:
        ip = InputParser()
        ip.parseFile(args.input, "ntds")
        ip.saveUniqueHashesToFile('crackme.txt')
    elif args.original and args.potfile:
        op = OutputParser(args.potfile)
        op.mergeOutputFile(args.original, "ntds")
    else:
        argparser.print_help()
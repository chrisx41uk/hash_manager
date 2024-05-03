import re
import argparse

class GenericParser:

    @staticmethod
    def parseNTLMLine(ntlmLine : str):
        """
        Parse an individual NTLM line
        username:1150:aad3b435b51404eeaad3b435b51404ee:b53e2c85b6ffffd4ccff905d0b1ff06f53:::
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
                    #split the line up into better fields
                    split = line.split(':')
                    username = split[0]
                    rid = split[1]
                    hashOriginal = split[2] + ':' + split[3]
                    #is there extra information from impacket?
                    match = re.search('pwdlastset=([^)]+)', line)
                    lastChanged = "UNKNOWN"
                    if match:
                        lastChanged = match.group(1)
                    match = re.search('status=(\w+)', line)
                    status = "UNKNOWN"
                    if match:
                        status = match.group(1)
                    if fileType == "raw":
                        hash = line.rstrip()
                    elif fileType == "ntds":
                        hash = GenericParser.parseNTLMLine(line)

                    #lookup hash
                    password = "<NOTCRACKED>"
                    if hash in self.hashToPass:
                        password = self.hashToPass[hash]
                        count += 1
                    o.write(f"{password}, {username}, {rid}, {hashOriginal}, {status}, {lastChanged}\n")
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
                f.write(str(uniqueHash) + "\n")
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
    argparser.add_argument("--input", help="The file from secretsdump.py to parse and crack with hashcat")
    argparser.add_argument("--original", help="The original The file from secretsdump.py to parse and crack with hashcat")
    argparser.add_argument("--potfile", help="The hashcat pot file to take passwords from")
    args = argparser.parse_args()

    if args.input:
        ip = InputParser()
        ip.parseFile(args.input, "ntds")
        ip.saveUniqueHashesToFile('crackme.txt')
    elif args.original and args.potfile:
        op = OutputParser(args.potfile)
        op.mergeOutputFile(args.original, "ntds")
    else:
        argparser.print_help()

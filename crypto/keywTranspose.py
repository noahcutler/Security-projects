# This script implements a Keyword Transposition Cipher decryption/encryption
# It was completed for a Hackerrank challenge
#
# USEAGE: python keywTranspose.py [-e|-d] keyword "message"
#
#
import string
import sys


keyw = sys.argv[2].upper()
mssg = sys.argv[3].upper()

word = list(string.ascii_uppercase)

keyword = "".join(sorted(set(keyw), key = keyw.index)) #remove dups
bet = [l for l in word if l not in keyword] # create new alphabet without letters from keyword

columns = {}    #arrange into columns
for i in range(len(keyword)):
    columns[keyword[i]] = [(bet[index]) for index in range(i, len(bet), len(keyword))]
sortedKeyw = sorted(keyword) #sort keyword alphabetically
cipher = []
for l in sortedKeyw:
    cipher.append(l)
    cipher.extend(columns[l])
if sys.argv[1] == "-d":
	cipherbet = {}  #dictionary of cipher alphabet
	for index in range(len(word)):
	    cipherbet[cipher[index]] = word[index]
	cipherbet[" "] = " "
	print("".join([cipherbet[l] for l in mssg])) #map individual cipher letters to basealphabet & consolidate
else:
	encipherbet = {}  #dictionary of cipher alphabet
	for index in range(len(word)):
	    encipherbet[word[index]] = cipher[index]
	encipherbet[" "] = " "
	print("".join([encipherbet[l] for l in mssg]))
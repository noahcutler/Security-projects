# This script implements a Keyword Transposition Cipher decryption
# It was completed for a Hackerrank challenge
#
#
# input line 1: keyword upon which to base the alphabet transposition
# input line 2: encrypted text
#
# output: decrypted text

# TO DO: implement encryption as well
#
#
import string

word = list(string.ascii_uppercase)
keyw = input()
mssg = input()

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
cipherbet = {}  #dictionary of cipher alphabet
for index in range(len(word)):
    cipherbet[cipher[index]] = word[index]
cipherbet[" "] = " "
print("".join([cipherbet[l] for l in mssg])) #map individual cipher letters to basealphabet & consolidate

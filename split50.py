#!/bin/python3
import sys

x=sys.argv[1]
res=""
maxi=int(len(x) / 50) + 1
for i in range(maxi):
    res += "qq = qq + \"" + x[i*50:(i*50 + 50):] + "\"\n"
print(res)

#!/usr/bin/python3

import sys

generic_replace="{SHELLCODE_TO_REPLACE}"

shell=sys.argv[1]
what=sys.argv[2]

if len(shell) < 2 or len(what) < 2:
    sys.exit(0)

with open(shell, 'r') as f:
    shell_content=f.read()

raw_name=what[:what.rfind(".")]
ext=what[what.rfind(".")+1:]

print("[i] Shell content loaded, reading template")

with open("{}.{}".format(raw_name, "tpl"), 'r') as f:
    what_content=f.read()
    what_content = what_content.replace(generic_replace, shell_content)

print("[i] Replacing with shellcode")
with open(what, 'w') as f:
   f.write(what_content)

print("[i] All done")

    

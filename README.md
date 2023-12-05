# OSEP_Prep

## Bunch of scripts and some notes for the OSEP.
-----------------------------------------------------
#### Just check the content of the scripts.
- more stuff will come, mostly C++ versions of the C# original versions
- scripts must be updated with your paths
1) **xor_cezar.cpp** ... encrypt the shellcode from the msfvenom with XOR + CEASER.
   Just give him the file. Shell with decoding procedures is then printed to stdout.
   It is buildable in Windows too. Linux build `g++ xor_cezar.cpp -o encrypt_shell -std=c++<your favorite version>` .   
3) genpayload ... helper with msfvenom, can be used to generate common shells. Check the source and create the symlinks. (eg. ln -sv /path/to/genpayload /path/to/link/genpsshell)
4) getcurl ... generate curl, powershell download cradles and more... Check the source and create the symlinks. (eg. ln -sv /path/to/getcurl /path/to/link/getiex)
5) genpack ... shortcut for common stuff
6) shells/ ... templates used to generate powershell shellcode runners (I used this from the /var/www/html dir.)

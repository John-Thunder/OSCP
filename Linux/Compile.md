# Compile C program in Linux for Buffer Overflow

## Disable canary:
gcc vuln.c -o vuln_disable_canary -fno-stack-protector

## Disable DEP:
gcc vuln.c -o vuln_disable_dep -z execstack

## Disable PIE:
gcc vuln.c -o vuln_disable_pie -no-pie

## Disable all of protection mechanisms listed above (warning: for local testing only):
gcc vuln.c -o vuln_disable_all -fno-stack-protector -z execstack -no-pie


gcc vuln.c -o vuln_disable_all -fno-stack-protector -z execstack -z norelro -no-pie -D_FORTIFY_SOIURCE=0 -ggdb

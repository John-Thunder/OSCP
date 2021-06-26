https://tldp.org/LDP/Bash-Beginners-Guide/html/sect_07_01.html

# Bash features
https://stackoverflow.com/questions/31255699/double-parenthesis-with-and-without-dollar/31255942

$(...) means execute the command in the parens in a subshell and return its stdout. Example:
```
$ echo "The current date is $(date)"
The current date is Mon Jul  6 14:27:59 PDT 2015
```

(...) means run the commands listed in the parens in a subshell. Example:
```
$ a=1; (a=2; echo "inside: a=$a"); echo "outside: a=$a"
inside: a=2
outside: a=1
```

$((...)) means perform arithmetic and return the result of the calculation. Example:
```
$ a=$((2+3)); echo "a=$a"
a=5
```

((...)) means perform arithmetic, possibly changing the values of shell variables, but don't return its result. Example:
```
$ ((a=2+3)); echo "a=$a"
a=5
```

${...} means return the value of the shell variable named in the braces. Example:
```
$ echo ${SHELL}
/bin/bash
```

{...} means execute the commands in the braces as a group. Example:
```
$ false || { echo "We failed"; exit 1; }
We failed
```


# Double-Parentheses Construct
https://tldp.org/LDP/abs/html/dblparens.html

Similar to the let command, the (( ... )) construct permits arithmetic expansion and evaluation. In its simplest form, a=$(( 5 + 3 )) would set a to 5 + 3, or 8. However, this double-parentheses construct is also a mechanism for allowing C-style manipulation of variables in Bash, for example, (( var++ )).

## Example 8-5. C-style manipulation of variables
```
#!/bin/bash
# c-vars.sh
# Manipulating a variable, C-style, using the (( ... )) construct.


echo

(( a = 23 ))  #  Setting a value, C-style,
              #+ with spaces on both sides of the "=".
echo "a (initial value) = $a"   # 23

(( a++ ))     #  Post-increment 'a', C-style.
echo "a (after a++) = $a"       # 24

(( a-- ))     #  Post-decrement 'a', C-style.
echo "a (after a--) = $a"       # 23


(( ++a ))     #  Pre-increment 'a', C-style.
echo "a (after ++a) = $a"       # 24

(( --a ))     #  Pre-decrement 'a', C-style.
echo "a (after --a) = $a"       # 23

echo

########################################################
#  Note that, as in C, pre- and post-decrement operators
#+ have different side-effects.

n=1; let --n && echo "True" || echo "False"  # False
n=1; let n-- && echo "True" || echo "False"  # True

#  Thanks, Jeroen Domburg.
########################################################

echo

(( t = a<45?7:11 ))   # C-style trinary operator.
#       ^  ^ ^
echo "If a < 45, then t = 7, else t = 11."  # a = 23
echo "t = $t "                              # t = 7

echo


# -----------------
# Easter Egg alert!
# -----------------
#  Chet Ramey seems to have snuck a bunch of undocumented C-style
#+ constructs into Bash (actually adapted from ksh, pretty much).
#  In the Bash docs, Ramey calls (( ... )) shell arithmetic,
#+ but it goes far beyond that.
#  Sorry, Chet, the secret is out.

# See also "for" and "while" loops using the (( ... )) construct.

# These work only with version 2.04 or later of Bash.

exit
```


# read
https://www.computerhope.com/unix/bash/read.htm

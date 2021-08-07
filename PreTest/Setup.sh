#!/bin/zsh

# Update Kali
# wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
# wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add -
sudo apt update 
sudo apt full-upgrade -y 
sudo apt install -y asciinema cherrytree curl dirsearch expect exploitdb flameshot ffuf gcc gifsicle git gobuster golang imagemagick inkscape libsqlite3-dev libxslt-dev libxml2-dev nikto nishang openvpn perl python3 python3-pip ssh virtualbox wget zlib1g-dev
sudo apt autoremove
pip3 install updog

export PATH=$PATH:/opt

# feroxbuster
wget https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip
unzip feroxbuster_amd64.deb.zip
sudo apt install ./feroxbuster_*_amd64.deb
rm ./feroxbuster_*_amd64.deb
rm ./feroxbuster_amd64.deb.zip

# Install pip for Python2:
#curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
#python get-pip.py


cd /opt
# install repos
pip3 install impacket
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket/
pip3 install .
sudo python3 ./setup.py install


cd /opt
wget https://www.securitysift.com/download/linuxprivchecker.py
# exploits:
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git
git clone https://github.com/PowerShellMafia/PowerSploit.git
git clone https://github.com/SecWiki/windows-kernel-exploits.git
git clone https://github.com/SecWiki/linux-kernel-exploits.git
git clone https://github.com/tennc/webshell.git
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
git clone https://github.com/rsmudge/ZeroLogon-BOF.git
# my repo
git clone https://github.com/ciwen3/OSCP.git
# other
git clone https://github.com/LOLBAS-Project/LOLBAS.git
git clone https://github.com/mishmashclone/OlivierLaflamme-Cheatsheet-God.git
git clone https://github.com/vjeantet/hugo-theme-docdock.git
git clone https://github.com/NetSPI/PowerUpSQL.git
# tools
git clone https://github.com/sullo/nikto.git
git clone https://github.com/phra/rustbuster.git
git clone https://github.com/Tib3rius/AutoRecon.git
git clone https://github.com/21y4d/nmapAutomator.git
git clone https://github.com/ffuf/ffuf.git
git clone https://github.com/sullo/nikto.git
git clone https://github.com/cwinfosec/revshellgen.git
git clone https://github.com/thosearetheguise/rev.git
git clone https://github.com/mzet-/linux-exploit-suggester.git
git clone https://github.com/HarmJ0y/PowerUp.git
git clone 
git clone 

git clone https://github.com/dzonerzy/goWAPT.git
cd goWAPT
make 
sudo make install
cd /opt

git clone https://github.com/fox-it/mitm6.git
cd mitm6/
pip3 install .
sudo python3 ./setup.py install
 
cd ~/Documents
wget https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet/blob/master/README.md -o Active-Directory-Exploitation-Cheat-Sheet.md
git clone https://github.com/GTFOBins/GTFOBins.github.io.git
cd GTFOBins.github.io
make 
sudo make install


cd /usr/share/wordlists
wget https://gist.githubusercontent.com/nullenc0de/96fb9e934fc16415fbda2f83f08b28e7/raw/146f367110973250785ced348455dc5173842ee4/content_discovery_nullenc0de.txt
git clone https://github.com/danielmiessler/SecLists.git

cd
mkdir ~/asciinema
sudo echo "
HISTTIMEFORMAT='%F %T '
HISTFILESIZE=-1
HISTSIZE=-1
HISTCONTROL=ignoredups
HISTIGNORE=?:??
#shopt -s histappend
#shopt -s cmdhist
#shopt -s lithist
asciinema rec ~/asciinema/OSCP-\$(date +"%d-%b-%Y-%T").\$RANDOM.cast" >> /etc/zsh/zshrc


sudo echo "
HISTTIMEFORMAT='%F %T '
HISTFILESIZE=-1
HISTSIZE=-1
HISTCONTROL=ignoredups
HISTIGNORE=?:??
#shopt -s histappend
#shopt -s cmdhist
#shopt -s lithist
asciinema rec ~/asciinema/OSCP-\$(date +"%d-%b-%Y-%T").\$RANDOM.cast" >> /etc/bash.bashrc


# create scripts for retaining data
cat <<EOF > ~/flameshot.sh
#!/bin/bash
while true; do flameshot full -p ~/Pictures/ ; sleep 60 ; done
EOF
chmod +x ~/flameshot.sh


cat <<EOF > ~/OSCP-git.sh
#!/bin/bash
# upload all notes and screen shots to github every 5 min
sleep 300
# Test file creation
# touch 'new-'$(date +"%H:%M-%d-%b-%Y")'.txt'
# Add, Commit and Upload files to Github
git add -A
git commit -m update
git push origin main
# for older Github accounts use below:
# git push origin master 
EOF
chmod +x ~/OSCP-git.sh


cat <<EOF > ~/OSCP-expect.sh
#!/usr/bin/expect -f
set timeout -1
spawn ./OSCP-git.sh
# Interact with the login using expect
expect "Username for 'https://github.com':"
send -- "<username>\n"
expect "Password for 'https://<username>@github.com':"
send -- "<password>\n"
expect eof
EOF
chmod +x ~/OSCP-expect.sh


# MSFconsole setup
service postgresql start
sudo msfdb init
sudo chmod 777 /usr/share/metasploit-framework/.bundle/config


cat <<EOF 
Checklist:
==========
Auto upload github repo:
for i in {1..1000}; do ~/OSCP-expect.sh; done

Start screebshots:
~/flameshot.sh

CherryTree:
Configuration: Edit > Preferences > Miscellaneous > Auto Save Every __ Minutes

MSF setup:
msfconsole
db_status
bundle install

EOF

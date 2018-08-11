# TipsSysadm

Diversos comandos utilizados no dia a dia na administração de sistemas Linux, Zimbra, Exchange, Posftix, Nginx, Apache entre outros.


Comandos uteis:

Policy - Blacklist / Whitelist --> dbhost02 --> mysql.4.1.10a --> banco email_infolink_com_br 


verificar emails
for i in $(zgrep "from=<rh@ibbca.com.br" /var/log/maillog-20160108 | grep "Jan  7" | awk '{print $6}') ; do zgrep $i /var/log/maillog-20160108 ; done


verificar uso por pasta --> for dirs in $(ls --color=never -l | grep "^d" | awk '{print $9}'); do du -hs $dirs;done

LIMPAR CACHE NGINX --> rm -rf /var/lib/nginx/cache/*

===============================================================================================================================

Compacta logs com mais de 100mb --> find /var/www/vhosts -type f -name "*log" -exec du {} \; | awk '{ if ( $1 >= 102400 ) print $2}' | xargs gzip -9 -f


for i in $(postqueue -c /etc/postfix-bounce -p | grep `date +%b`| rev | awk '{print $1}' | rev | cut -d@ -f2 | sort | uniq -c | sort -nk1  | awk '{ if ( $1 >= 50 ) print $2}') ; do pfdel *@$i /etc/postfix-bounce ; done
===============================================================================================================================
Verificar ADM dominio exchange
Get-RoleGroup -Organization domain.com -Identity "Organization Management" | Get-RoleGroupMember

=================================================================================================================
O cliente pode fazer controle de cache em suas aplicações usando o web.config. Por exemplo:

<outputCacheSettings>
  <outputCacheProfiles>
    <add name="CacheProfile1" duration="60" />
  </outputCacheProfiles>
</outputCacheSettings>
Mais informações aqui: https://msdn.microsoft.com/pt-br/library/ms178606(v=vs.100).aspx

================================================================================================================================
Política de Recursos/Performance PHP

memory_limit = 128 MB
max_execution_time = 30 segundos
max_input_time = 60 segundos
post_max_size = 64 MB
upload_max_filesize = 64 MB
max_file_uploads = 20
Política de Recursos/Performance Plataforma de Hospedagem

Tempo de CPU: 120 à 180 segundos
Arquivos abertos: até 40 simultaneamente
Processos: até 10 simultaneamente
SSH: shell limitado, em esquema chrooted jail e sem /proc
===================================================================================================================
  PADRAO CONF APACHE RLIMIT:
  RLimitNPROC 5 10
  RLimitMEM 256000000 256000000
  RLimitCPU 120 180
====================================================================================================================================
Deve existir no WP

RewriteEngine On
  AddType application/x-httpd-php .php
  DirectoryIndex index.php
  <Directory />
        Options SymLinksIfOwnerMatch
        AllowOverride All
  </Directory>

====================================================================================================================================## Limitar conexoes por ip

iptables -I INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 30 --connlimit-mask 32 -j REJECT --reject-with tcp-reset

====================================================================================================================================

Verificar DDOS


netstat -n | grep EST | awk '{ print $5 }' | cut -d: -f1 | sort | uniq -c | sort -nr | perl -an -e 'use Socket; ($hostname, @trash) = gethostbyaddr(inet_aton($F[1]), AF_INET); print "$F[0]\t$F[1]\t$hostname\n";'

====================================================================================================================================

Verificar email to  from:

zgrep "@cenibra.com.br" /var/log/mail.log.4[2-4].gz | grep "to=<" | awk '{print $6}' | grep -v NOQUEU | while read Email ; do grep $Email | grep "@paradvogados.com.br" ; done


====================================================================================================================================

(13:56:59) Vega: find /maildir/ -maxdepth 5 -type d -name ".Spam" | while read SpamFolder ; do find $SpamFolder -type f -name "*mda04*" -mtime +30 -exec rm -v {} \; ; done
(13:57:01) Vega: find /maildir/ -maxdepth 4 -type d -name catchall | while read Catchall ; do find $Catchall -type f -name "*mda04*" -mtime +30 -exec rm -fv {} \; ; done
(13:57:08) Vega: Prá liberar espaço nas mdas.

====================================================================================================================================
TOP SENDER DOMINIO ---> 

zgrep qmgr mail.log.1.gz | grep "from=<.*@glcomunicacao.com.br" | awk '{print $7}' | cut -d"=" -f2 | cut -d"<" -f2 | cut -d">" -f1 | tr '[A-Z]' '[a-z]' | sort | uniq -c | sort -rn


Qtd por dominio :
X=`egrep "from=<.*@glcomunicacao.com.br" /var/log/mail.log | grep queue | awk '{print $9}' | cut -d"=" -f2` ; A=0 ; for I in $X ; do A=`expr $A + $I`; done ; echo $A

====================================================================================================================================

   <Location />                                    
    Order Deny,Allow                               
    Deny from all                                  
    Allow from 200.187.69.175 192.168.0.0/16                                  
  </Location>          

sudo ifdown --exclude=lo -a && sudo ifup --exclude=lo -a



grep "message-id=<201" /var/log/mail.log | grep "5B@" | awk '{print $6}' | while read Check ; do grep $Check /var/log/mail.log ; done  | grep nrcpt | grep vinicius.voi@ago.com.br

====================================================================================================================================
Dism.exe /online /Cleanup-Image /StartComponentCleanup

killall -9 lmtp;invoke-rc.d dovecot stop;fuser -9 -k 143/tcp;sync && echo 3 > /proc/sys/vm/drop_caches; invoke-rc.d dovecot start;postsuper -r ALL

====================================================================================================================================Extensions wp:

php5-cli
php5-dev
php5-fpm
php5-cgi
php5-mysql
php5-xmlrpc
php5-curl
php5-gd
php-apc (not required, but recommended)
php-pear
php5-imap
php5-mcrypt
php5-pspell

====================================================================================================================================
Killar conexoes mysql :
use mysql;
select concat('KILL ',id,';') from information_schema.processlist where user='dominio' into outfile '/tmp/dominio.txt';
source /tmp/dominio.txt


insert into dominioscomservidorproprio (Dominio)values ('abac-br.org.br');

=====================================================================================================================================================================

Visudo zimbra zols :

%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmstat-fd *
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmslapd
%zimbra ALL=NOPASSWD:/opt/zimbra/postfix/sbin/postfix, /opt/zimbra/postfix/sbin/postalias, /opt/zimbra/postfix/sbin/qshape.pl, /opt/zimbra/postfix/sbin/postconf,/opt/zimbra/postfix/sbin/postsuper
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmqstat,/opt/zimbra/libexec/zmmtastatus
%zimbra ALL=NOPASSWD:/opt/zimbra/amavisd/sbin/amavis-mc
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmunbound
%zimbra ALL=NOPASSWD:/sbin/resolvconf *
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmmailboxdmgr
%zimbra ALL=NOPASSWD:/opt/zimbra/bin/zmcertmgr
%zimbra ALL=NOPASSWD:/opt/zimbra/nginx/sbin/nginx

=====================================================================================================================================================================                                            
15 3 * * * /usr/bin/certbot renew --quiet'

salt -C 'G@os_family:debian or G@os_family:redhat' cmd.run 'ls -1tr /usr/sbin/r1soft/conf/server.allow | tail -1'

cat output.txt  | tr '\n' ' ' | tr ' ' '\n'  | grep -v "^$" | tr '\n' ': ' | sed -e "s/::/ /g" | tr ':' '\n' | awk '$1 !~ /backup/ {print}' | egrep "backup|192"
=====================================================================================================================================================================

30 2 * * 1 /root/letsencrypt/letsencrypt-auto renew --email operacoes@infolink.com.br --agree-tos ; /etc/init.d/nginx restart >> /var/lo
g/letsencrypt.log
====================================================================================================================================salt -C 'G@os_family:debian or G@os_family:redhat' cmd.run "if [ $(ls -1tr /usr/sbin/r1soft/conf/server.allow | wc -l) > 1 ] ; then ls -1tr /usr/sbin/r1soft/conf/server.allow | sed -e '\$d' ; fi | while read BackupServer ; do r1soft-setup --remove-key \$BackupServer ; done "
====================================================================================================================================

LVM EXTEND:

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

=======================================================================================
LOGS PDC NO MESSENGER DA WEBSERVICE E ALGUNS EVENTOS NO BANCO DSA WEBSVCDB
=======================================================================================
Refiz o shell com:

root@vhost19:/virtual/linux.scholar.com.br# chsh -s $(which sh) linuxscholar

=======================================================================================
RENOVANDO SSL ZIMBRA:
=======================================================================================
cd /opt/zimbra/ssl/zimbra/commercial

mv commercial.crt{,.old}  
mv commercial_ca.crt{,.old}

cp /home/operacoes/rcastro/Infolink/* .

mv 377a385f8b80041a.crt commercial.crt

mv gd_bundle-g2-g1.crt commercial_ca.crt

/opt/zimbra/bin/zmcertmgr verifycrt comm ./commercial.key ./commercial.crt ./commercial_ca.crt

/opt/zimbra/bin/zmcertmgr deploycrt comm ./commercial.crt ./commercial_ca.crt

/opt/zimbra/bin/zmcertmgr viewdeployedcrt
=======================================================================================
# wget https://support.plesk.com/hc/article_attachments/115004518545/poodle.zip
# unzip poodle.zip
# chmod +x poodle.sh
# for i in `echo 21 587 443 465 7081 8443 993 995 `; do /bin/sh /root/poodle.sh <IP> $i; done

=======================================================================================
Removendo Kernels antigos UBUNTU :

dpkg -l 'linux-*' | sed '/^ii/!d;/'"$(uname -r | sed "s/\(.*\)-\([^0-9]\+\)/\1/")"'/d;s/^[^ ]* [^ ]* \([^ ]*\).*/\1/;/[0-9]/!d' | xargs sudo apt-get -y purge
=======================================================================================

cat /infolink/etc/zabbix/datastore_vcenter02 | awk 'BEGIN{print "Storage","Uso"} ; BEGIN{print "---------- ----------"}; { print $1,$2/1073741824}' | column -t
=======================================================================================

cat  /var/log/nginx/access.log | awk 'BEGIN{print "Qtde","StatusCode"};$7 ~ /^[0-9]+$/ && $7 !~ /MISS/ { tot[$7]++ } END { for (i in tot) print tot[i],i } '  | column -t



FM8N3-J889P-DVDW8-B9VRV-6XT9Y

=======================================================================================
Senhores,
 
Uma breve explicação do que aconselhamos anteriormente e que costumamos implementar operacionalmente:
 
innodb_file_per_table: não fornece qualquer benefício de desempenho é apenas uma boa prática para agilizar a administração e um eventual crash recovery. A idéia aqui é termos uma opção de usar um arquivo InnoDB por tabela e permitir uma liberação de espaço sob demanda mais eficiente; seja por um truncate ou rebuild de tables.Também é necessário para alguns recursos avançados, como a compressão. 
 
innodb_buffer_pool_size: Esta será a principal mudança. Montaremos pool de buffers para os índices serem armazenados em cache. A idéia é configura-lo tão grande quanto possível, garantindo a utilização de memória e não discos físicos para a maioria das operações de leitura.
 
Slow Log: esta opção serve para vocês analisarem e otimizarem suas queries. Muito útil para achar eventuais gargalos no MySQL.
 
skip_name_resolve: Desejamos que o servidor evite consultar tabelas DNS desnecessariamente, pois assim isolamos uma eventual fonte de timeouts em casos de resolução lenta. O único impacto será de nossa administração, pois deveremos refazer os grants de seus usuários para os IPs do servidor. 
 
Outras configurações que executamos de tuning geralmente são:
 
innodb_log_file_size: Ajustamos o tamanho potencial dos logs "redo". Os logs de redo são usados para se certificar de que as gravações são rápidas e duradouras e (muito importante!) na recuperação de falhas. 
 
max_connections: Geralmente implementamos algumas limitações de conexões por usuários, evitando que um site impacte em outro no mesmo servidor. Justamente o seu cenário, pois como sabemos é muito freqüente o caso onde suas aplicações não fecham as conexões com o banco de dados.
 
innodb_flush_log_at_trx_commit: Aqui o intuito é maximizar a resiliência dos dados comitados no banco. É muito importante quando temos preocupação principal na segurança dos dados.
 
log_bin: Nosso pensamento é de que o binlog do MySQL deveria ser mandatório e não opcional e máquinas que não são meras réplicas de um master. Esta opção nos dám uma segurança extra para atuarmos em eventos de crash recovery, além de evitar uma eprda de dados por um estouroo de pilha, por exemplo.
 

=======================================================================================

git clone http://gitlab.infolink.com.br/valexandre/nginx.git
cd nginx
chmod 755 nginx_commands
./nginx_commands


=======================================================================================
Ver envio em GB ftp service :

for Mes in $(echo "Jul Aug Sep") ; do cat /var/log/proftpd/xfer | awk -v Mes=$Mes '{if ( $2 == Mes ) print $8 }' | awk -v Mes=$Mes '{Soma+=$1}END{print Mes,"=",Soma/1000000/1024 "GB"}'; done


=======================================================================================
    -> Listagem das políticas: 
/infolink/bin/check_sql_policy | egrep -v "backup|\#" | grep -v ^$ | tr -t '\n' ' ' | tr -d '\r' | sed -e "s/Servidor : /\n/g"  | awk '{if ( $2 == "Configurações" ) print $1,$6}' | sed -e "s/Está/SQLServer/g" | column -t

-> Listagem de servidores com SQL: 
salt-key -l acc | perl -pe 's/\x1b\[[0-9;]*[mG]//g' | while read Servidor ; do if salt $Servidor service.get_all | perl -pe 's/\x1b\[[0-9;]*[mG]//g' | egrep -i "mysql|mssql" > /dev/null 2>&1 ; then echo $Servidor ; fi ; done

=======================================================================================
# Configração Linux  /etc/salt/minion                                                                                                                                                                              
                                                                                                                                                                                                                   
sock_dir: /var/run/salt/minion                                                                                                                                                                                     
acceptance_wait_time: 60                                                                                                                                                                                           
recon_default: 10000                                                                                                                                                                                               
user: root                                                                                                                                                                                                         
                                                                                                                                                                                                                
master:                                                                                                                                                                                                            
- 192.168.254.41                                                                                                                                                                                                   
                                                                                                                                                                                                                   
loop_interval: 60                                                                                                                                                                                                  
                                                                                                                                                                                                                   
startup_states:                                                                                                                                                                                                    
- sls                                                                                                                                                                                                              
                                                                                                                                                                                                                 
log_level: debug                                                                                                                                                                                                   
#log_level: warning"                                                                                                                                                                                               
id: NOMEDOSERVIDOR  

=======================================================================================


SIGMA
Usuário: opadmin
Senha: Q2we<E9t

=======================================================================================

INF MDA06
Load de CPU 20  20 Out 2017 02:16:27  2m 10s   
Máquina estava com I/O alto.
Dropei o cache de memória existente afim de liberar recursos para escrita de novo cache:
root@mda06:~# free -m   
             total       used       free     shared    buffers     cached                       
Mem:          7978       7860        118          2        425        586                       
-/+ buffers/cache:       6848       1130        
Swap:         1881         32       1849        
root@mda06:~# sync && echo 3 > /proc/sys/vm/drop_caches                                         
root@mda06:~# free -m   
             total       used       free     shared    buffers     cached                       
Mem:          7978       6714       1263          2         10         30                       
-/+ buffers/cache:       6674       1304        
Swap:         1881         32       1849        
root@mda06:~#  

Parei o dovecot e verifiquei que muitas das conexões ainda estavam presas, portanto, tive que matar os processos manualmente:

root@mda06:~# ps aux | grep dovecot | grep -v grep | awk '{print $2}' | xargs -n1 kill -9      

Depois de parar todos os processo, iniciei novamente o dovecot.

As ações acima geraram um alarme esperado de POP e IMAP na monitoria, porém normalizados após a inicialização do DOVECOT.

Fiz um flush da fila do postfix local para forçar a entrega dos emails que ficaram em HOLD devido a parada do DOVECOT.

Foi identificado que uma conta catchall estava ocasionando uma grande espera na fila devido a cota estourada:
root@mda06:/etc/sysctl.d# postqueue -p | grep catchall@studiozero.com.br | wc -l                
103                     
root@mda06:/etc/sysctl.d#   

Fiz uma limpeza de emails na pasta de spam para liberar a entrega de novos emails.
A conta catchall@cormackshipping.com.br também teve sua pasta de Spam limpa.

Com isso o load voltou à sua normalidade.

=======================================================================================

select concat('KILL ',id,';') from information_schema.processlist where Command='Sleep' into outfile '/tmp/sleep.log'
source /tmp/arquivo.txt

=======================================================================================
Outra questão é a quantidade de erros de acesso ao MySQL (banco de dados) de seu servidor, o qual está aberto para o mundo e constrantemente recebe tentativas de brute force:
root@cloud847 ~]# grep "Access denied for user" /var/lib/mysql/mysql-error.log | awk '{print $9}' | cut -d\@ -f2 | sort | uniq -c | sort -nk1

=======================================================================================

Prezado Mauro,

Infelizmente no horário informado houve instabilidade em alguns servidores de nossa estrutura que afetou diretamente o seu Cloud e demais. A situação foi normalizada.

Poderia nos dizer se ainda há algum problema?

Reiteramos nosso compromisso com a qualidade técnica e de atendimento. Estamos buscando incessantemente melhoria em nossos sistemas/infra para que estes tipos de incidentes sejam reduzido sensivelmente.

Lamentamos o transtorno.

=======================================================================================

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


=======================================================================================
LIMPAR SPAM MDAS:

find /maildir/ -maxdepth 2 -type d | awk -F'/' '{print $4 "@" $3}' | grep -v ^@ | while read Conta ; do doveadm expunge -u $Conta mailbox Spam savedbefore 4w ; done

find /maildir/ -maxdepth 2 -type d | awk -F'/' '{print $4 "@" $3}' | grep -v ^@ | while read Conta ; do doveadm expunge -u $Conta mailbox Lixeira savedbefore 4w ; done

=======================================================================================

Verificar espaco storage via salt:

cat /infolink/etc/zabbix/datastore_{vcs,vcenter02} | sort -u | awk 'BEGIN{print "Storage","|","Livres(GB)"} ; BEGIN{print "---------- | ----------"}; { print $1,"|",$2/1073741824}' | column -t | grep "NAS01"
NAS01 | 0

=======================================================================================

grep 2017-12-05 /var/log/fail2ban.log | grep -vi already| awk '{print $8}' | sort | uniq -c | sort -nk1 | awk '{ if ( $1 >= 100) system("geoiplookup " $2)}'

=======================================================================================

ssh -t vivek@server1.cyberciti.biz << EOF
 sync
 sync
 sudo /sbin/shutdown -h 0
EOF
=======================================================================================

Verificar validade de Certificado:

 openssl x509 -in www.cursointellectus.com.br.crt -text -noout | egrep -i 'before|after'

 =======================================================================================
 REVERSO INFOLINK:

 70.187.200.in-addr.arpa

 =======================================================================================
Ver dominios:

 salt-ssh 'vhost19*' cmd.run 'apachectl -S' | perl -pe 's/\x1b\[[0-9;]*[mG]//g' | grep "port 80" | awk '{print $4}' | sed -e "s/www.//g" | egrep -v "novavhost|rel-vhost|utils-vhost|vhost1|infolink.com|infolinkti.com|w3br" 

=======================================================================================
INFOS de Memoria / CPU : 

 salt 'backup*' cmd.run "echo -n 'CPU: ' ; cat /proc/cpuinfo | grep processor | wc -l ; free -m | head -n+2 |tail -1 | awk '{print \"Memória:\" , \$2/1024, \"GB\"}'"  >> Backup_Info.txt
=======================================================================================
Criar policy etc

 /infolink/bin/AdicionaBackup cloud435 200.187.69.109
=======================================================================================
AS INFOLINK 19873
=======================================================================================

.\Disable-Organization.ps1 -Organization fastrepairit.com.br -Blocking:$True

=======================================================================================
find /vhosts/* -type f -regex ".*/.*\.\(zip\|exe\|rar\)" -exec du -h {} \;

find /vhosts/* -type f -regex ".*/.*\.\(zip\|exe\|rar\)" -size +200M -exec du -h {} \;

=======================================================================================
VER LOCKS DE TABELAS POSTGRES:

  SELECT bl.pid                 AS blocked_pid,
         a.usename              AS blocked_user,
         ka.current_query       AS blocking_statement,
         now() - ka.query_start AS blocking_duration,
         kl.pid                 AS blocking_pid,
         ka.usename             AS blocking_user,
         a.current_query        AS blocked_statement,
         now() - a.query_start  AS blocked_duration
  FROM  pg_catalog.pg_locks         bl
   JOIN pg_catalog.pg_stat_activity a  ON a.procpid = bl.pid
   JOIN pg_catalog.pg_locks         kl ON kl.transactionid = bl.transactionid AND kl.pid != bl.pid
   JOIN pg_catalog.pg_stat_activity ka ON ka.procpid = kl.pid
  WHERE NOT bl.granted;
For PostgreSQL >= 9.2:
  SELECT bl.pid                 AS blocked_pid,
         a.usename              AS blocked_user,
         ka.query               AS blocking_statement,
         now() - ka.query_start AS blocking_duration,
         kl.pid                 AS blocking_pid,
         ka.usename             AS blocking_user,
         a.query                AS blocked_statement,
         now() - a.query_start  AS blocked_duration
  FROM  pg_catalog.pg_locks         bl
   JOIN pg_catalog.pg_stat_activity a  ON a.pid = bl.pid
   JOIN pg_catalog.pg_locks         kl ON kl.transactionid = bl.transactionid AND kl.pid != bl.pid
   JOIN pg_catalog.pg_stat_activity ka ON ka.pid = kl.pid
  WHERE NOT bl.granted;

=======================================================================================
MDAS:

grep user /var/log/mail.log | awk '{print $8,$9}' | grep '@' | cut -d',' -f1 | sed -e 's|orig_to=<||g' | sed -e 's/>//' | sort | uniq -c | sort                                                                   

grep user /var/log/mail.log | awk '{print $8,$9}' | grep -vE 'relay|size'

dmesg -T| grep -E -i -B100 'killed process'

grep '192.168.12.183 ' audit/audit.log                                                                                                                                                       
grep 'res=failed' audit/audit.log                                                                                                                                                                                  
grep 'cct="lteixeira"' audit/audit.log  


## Verificar se dominio ainda aponta para o host :

ls -1 | while read Dom ; do if host pop.$(echo $Dom) | grep "has address" | grep 200.187.64.103 >> /dev/null 2>&1; then echo " " >> /dev/null ; else echo $Dom ; fi ; done | wc -l

for i in $(seq -w 0 18) ; do echo "Contagem erros para $i h:" ; grep "auth failed" /var/log/dovecot*.log | grep "Mar 27 $i" | awk '{print $17}' | sort | uniq -c | sort -nrk1  | head -10 ; echo "#################
################" ; echo " " ; done  | less

iptables -I PREROUTING -t raw -s 85.93.20.0/24 -j DROP

sync && echo 3 > /proc/sys/vm/drop_caches                                 

while sleep 10 ; do clear ; w ; sync && echo 3 > /proc/sys/vm/drop_caches ; free -m ; done

ps ax -o pid,ni,cmd | grep cdp 

sudo ifdown --exclude=lo -a && sudo ifup --exclude=lo -a

find /maildir/ -maxdepth 2 -mindepth 1 -type d -name "catchall"

find /maildir/ -maxdepth 2 -mindepth 1 -type d -name "catchall"  | wc -l 

find /maildir/ -maxdepth 2 -mindepth 1 -type d -name "catchall" | while read CatchAll ; do find $CatchAll/{new,cur,.Spam} -type f -name "*mda*" -mtime +90 ; done 

find ./ -maxdepth 1 -type d -mtime +30 | wc -l

find . -maxdepth 2 -mindepth 1 -type d -mtime +30 -exec rm -rfv {} \; 

==================================================================================================
LHOST:

find /var/log/httpd/logs/ -type f -mtime +30  -exec gzip -9 {} \;

cat /var/log/audit/audit.log | perl -ne 'chomp; if ( /(.*msg=audit\()(\d+)(\.\d+:\d+.*)/ ) { $td = scalar localtime $2; print "$1$td$3\n"; }' | awk -F":" '$1 ~ /06/ {print}' > /home/operacoes/valexandre/out_chec
k 

ps aux | grep php | grep tmp | awk '{$1=$3=$4=$5=$6=$7=$8=$9=$10="";print}'

netstat -tuplano | egrep ":80|:443" | awk '{print $5}' | sed -e "s/::ffff://g" | cut -d: -f1 | sort | uniq -c | sort -nrk1 | head -10

find ./www/ -type f ! -name "*.asp" | egrep -v "uploads|jpg|png" | less 

while sleep 1 ; do clear ; netstat -tuplano | egrep ":80|:443" | awk '{print $5}' | sed -e "s/::ffff://g" | cut -d: -f1 | sort | uniq -c | sort -nrk1 | head -10 ; done 

==================================================================================================

http://blog.gaudencio.net.br/2014/01/postgresql-consultando-e-eliminando.html


==================================================================================================

Castro me solicitou auxílio referente aos bloqueios e realizei os seguintes passos: 
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


[zimbra@zol01 ~]$ zmlogswatchctl start
Starting logswatch...OpenJDK 64-Bit Server VM warning: INFO: os::commit_memory(0x0000000640000000, 716177408, 0) failed; error='Cannot allocate memory' (errno=12)
zimbra logger service is not enabled!  failed.


OpenJDK 64-Bit Server VM warning: INFO: os::commit_memory(0x0000000740000000, 357564416, 0) failed; error='Cannot allocate memory' (errno=12)
#
# There is insufficient memory for the Java Runtime Environment to continue.
# Native memory allocation (mmap) failed to map 357564416 bytes for committing reserved memory.
# An error report file with more information is saved as:
# /tmp/hs_err_pid10579.log

Ao restartar estava retornando erro como se o user zimbra não tivesse permissão para restart do serviço, desta forma copiei o sudoers da zol02 para 01 e consegui levantar os serviços:

%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmstat-fd *
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmslapd
%zimbra ALL=NOPASSWD:/opt/zimbra/postfix/sbin/postfix, /opt/zimbra/postfix/sbin/postalias, /opt/zimbra/postfix/sbin/qshape.pl, /opt/zimbra/postfix/sbin/postconf,/opt/zimbra/postfix/sbin/postsuper
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmqstat,/opt/zimbra/libexec/zmmtastatus
%zimbra ALL=NOPASSWD:/opt/zimbra/amavisd/sbin/amavis-mc
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmunbound
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmdnscachealign *
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmmailboxdmgr
%zimbra ALL=NOPASSWD:/opt/zimbra/bin/zmcertmgr
%zimbra ALL=NOPASSWD:/opt/zimbra/nginx/sbin/nginx
%zimbra ALL=NOPASSWD:/infolink/bin/zabbix_checa_particao_backup.sh


Esta falha durou cerca de 8m para normalização.Comandos uteis:

Policy - Blacklist / Whitelist --> dbhost02 --> mysql.4.1.10a --> banco email_infolink_com_br 


verificar emails
for i in $(zgrep "from=<rh@ibbca.com.br" /var/log/maillog-20160108 | grep "Jan  7" | awk '{print $6}') ; do zgrep $i /var/log/maillog-20160108 ; done


http://wiki.corp.infolink.com.br/doku.php/infraestrutura:correio:bloqueio_recebimento_e_envio


verificar uso por pasta --> for dirs in $(ls --color=never -l | grep "^d" | awk '{print $9}'); do du -hs $dirs;done

LIMPAR CACHE NGINX --> rm -rf /var/lib/nginx/cache/*

===============================================================================================================================

Compacta logs com mais de 100mb --> find /var/www/vhosts -type f -name "*log" -exec du {} \; | awk '{ if ( $1 >= 102400 ) print $2}' | xargs gzip -9 -f

FILTRA QUEM ESTA QTD MAIL POR USER NO DOMINIO
postqueue -c /etc/postfix-bounce -p | grep `date +%b`| rev | awk '{print $1}' | rev | sort | uniq -c | sort -nk1  | awk '{ if ( $1 >= 10 ) print }' | grep infolink

VER CONTEUDO
sudo postqueue -c /etc/postfix-bounce -p|grep "dominio.com"

SCRIPT DEL

for i in $(postqueue -c /etc/postfix-bounce -p | grep `date +%b`| rev | awk '{print $1}' | rev | cut -d@ -f2 | sort | uniq -c | sort -nk1  | awk '{ if ( $1 >= 50 ) print $2}') ; do pfdel *@$i /etc/postfix-bounce ; done
===============================================================================================================================
Verificar ADM dominio exchange
Get-RoleGroup -Organization domain.com -Identity "Organization Management" | Get-RoleGroupMember


INSERT dominios(matricula,dominio,login,senha,txtrans,uid,gid,home,shell,permitelogin,count,quota_type,per_session,limit_type,bytes_in_avail) values('31729','vcadv.com.br','vcadv','ftp@VCA@2015',0,1000,102,'/whost03/vcadv.com.br',NULL,0,0,'user','false','hard','3.072e+10';


update mysql.user set password=PASSWORD('Nog1ftp!') where user='alvoradaimov';
select User,Host from mysql.user;


*** dbhost04 ****
mysql> select * from mailcontrol_logs where destinatario='eliosantos@zard.com.br' and acao='remocao';
+--------+------------------------+------+---------+------------------------------------------------------------+------+-------+---------+
| id     | destinatario           | tipo | acao    | texto                                                      | alvo | ;l | ts                  |
+--------+------------------------+------+---------+------------------------------------------------------------+------+-------+---------+
| 218284 | eliosantos@zard.com.br | W    | remocao | Santos, Ana <aplsantos@carlsonwagonlit.com.br> 0.0.0.0/0 0 | E    | TODOS | 2014-12-01 15:23:44 |
+--------+------------------------+------+---------+------------------------------------------------------------+------+-------+----------+

imapsync  --host1 mda08.infolink.com.br --user1 informatica@rtsrio.com.br --password1  Star1010 --host2 exchange.infolink.com.br --user2 informatica@rtsrio.com.br --password2 Star1010

=================================================================================================================
O cliente pode fazer controle de cache em suas aplicações usando o web.config. Por exemplo:

<outputCacheSettings>
  <outputCacheProfiles>
    <add name="CacheProfile1" duration="60" />
  </outputCacheProfiles>
</outputCacheSettings>
Mais informações aqui: https://msdn.microsoft.com/pt-br/library/ms178606(v=vs.100).aspx

================================================================================================================================
Política de Recursos/Performance PHP

memory_limit = 128 MB
max_execution_time = 30 segundos
max_input_time = 60 segundos
post_max_size = 64 MB
upload_max_filesize = 64 MB
max_file_uploads = 20
Política de Recursos/Performance Plataforma de Hospedagem

Tempo de CPU: 120 à 180 segundos
Arquivos abertos: até 40 simultaneamente
Processos: até 10 simultaneamente
SSH: shell limitado, em esquema chrooted jail e sem /proc
===================================================================================================================
  PADRAO CONF APACHE RLIMIT:
  RLimitNPROC 5 10
  RLimitMEM 256000000 256000000
  RLimitCPU 120 180
====================================================================================================================================
Deve existir no WP

RewriteEngine On
  AddType application/x-httpd-php .php
  DirectoryIndex index.php
  <Directory />
        Options SymLinksIfOwnerMatch
        AllowOverride All
  </Directory>

====================================================================================================================================## Limitar conexoes por ip

iptables -I INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 30 --connlimit-mask 32 -j REJECT --reject-with tcp-reset

====================================================================================================================================

Verificar DDOS


netstat -n | grep EST | awk '{ print $5 }' | cut -d: -f1 | sort | uniq -c | sort -nr | perl -an -e 'use Socket; ($hostname, @trash) = gethostbyaddr(inet_aton($F[1]), AF_INET); print "$F[0]\t$F[1]\t$hostname\n";'

====================================================================================================================================

Verificar email to  from:

zgrep "@cenibra.com.br" /var/log/mail.log.4[2-4].gz | grep "to=<" | awk '{print $6}' | grep -v NOQUEU | while read Email ; do grep $Email | grep "@paradvogados.com.br" ; done


====================================================================================================================================

(13:56:59) Vega: find /maildir/ -maxdepth 5 -type d -name ".Spam" | while read SpamFolder ; do find $SpamFolder -type f -name "*mda04*" -mtime +30 -exec rm -v {} \; ; done
(13:57:01) Vega: find /maildir/ -maxdepth 4 -type d -name catchall | while read Catchall ; do find $Catchall -type f -name "*mda04*" -mtime +30 -exec rm -fv {} \; ; done
(13:57:08) Vega: Prá liberar espaço nas mdas.

====================================================================================================================================
TOP SENDER DOMINIO ---> 

zgrep qmgr mail.log.1.gz | grep "from=<.*@glcomunicacao.com.br" | awk '{print $7}' | cut -d"=" -f2 | cut -d"<" -f2 | cut -d">" -f1 | tr '[A-Z]' '[a-z]' | sort | uniq -c | sort -rn


Qtd por dominio :
X=`egrep "from=<.*@glcomunicacao.com.br" /var/log/mail.log | grep queue | awk '{print $9}' | cut -d"=" -f2` ; A=0 ; for I in $X ; do A=`expr $A + $I`; done ; echo $A

====================================================================================================================================

#   <Location />                                    
#    Order Deny,Allow                               
#    Deny from all                                  
#    Allow from 200.187.69.175 192.168.0.0/16 200.165.200.106                                            
#  </Location>          

sudo ifdown --exclude=lo -a && sudo ifup --exclude=lo -a



grep "message-id=<201" /var/log/mail.log | grep "5B@" | awk '{print $6}' | while read Check ; do grep $Check /var/log/mail.log ; done  | grep nrcpt | grep vinicius.voi@ago.com.br

====================================================================================================================================
Dism.exe /online /Cleanup-Image /StartComponentCleanup

killall -9 lmtp;invoke-rc.d dovecot stop;fuser -9 -k 143/tcp;sync && echo 3 > /proc/sys/vm/drop_caches; invoke-rc.d dovecot start;postsuper -r ALL

====================================================================================================================================Extensions wp:

php5-cli
php5-dev
php5-fpm
php5-cgi
php5-mysql
php5-xmlrpc
php5-curl
php5-gd
php-apc (not required, but recommended)
php-pear
php5-imap
php5-mcrypt
php5-pspell

====================================================================================================================================
Killar conexoes mysql :
use mysql;
select concat('KILL ',id,';') from information_schema.processlist where user='dominio' into outfile '/tmp/dominio.txt';
source /tmp/dominio.txt


insert into dominioscomservidorproprio (Dominio)values ('abac-br.org.br');

=====================================================================================================================================================================

Visudo zimbra zols :

%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmstat-fd *
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmslapd
%zimbra ALL=NOPASSWD:/opt/zimbra/postfix/sbin/postfix, /opt/zimbra/postfix/sbin/postalias, /opt/zimbra/postfix/sbin/qshape.pl, /opt/zimbra/postfix/sbin/postconf,/opt/zimbra/postfix/sbin/postsuper
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmqstat,/opt/zimbra/libexec/zmmtastatus
%zimbra ALL=NOPASSWD:/opt/zimbra/amavisd/sbin/amavis-mc
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmunbound
%zimbra ALL=NOPASSWD:/sbin/resolvconf *
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmmailboxdmgr
%zimbra ALL=NOPASSWD:/opt/zimbra/bin/zmcertmgr
%zimbra ALL=NOPASSWD:/opt/zimbra/nginx/sbin/nginx

=====================================================================================================================================================================                                            
15 3 * * * /usr/bin/certbot renew --quiet'

salt -C 'G@os_family:debian or G@os_family:redhat' cmd.run 'ls -1tr /usr/sbin/r1soft/conf/server.allow | tail -1'

cat output.txt  | tr '\n' ' ' | tr ' ' '\n'  | grep -v "^$" | tr '\n' ': ' | sed -e "s/::/ /g" | tr ':' '\n' | awk '$1 !~ /backup/ {print}' | egrep "backup|192"
=====================================================================================================================================================================

30 2 * * 1 /root/letsencrypt/letsencrypt-auto renew --email operacoes@infolink.com.br --agree-tos ; /etc/init.d/nginx restart >> /var/lo
g/letsencrypt.log
====================================================================================================================================salt -C 'G@os_family:debian or G@os_family:redhat' cmd.run "if [ $(ls -1tr /usr/sbin/r1soft/conf/server.allow | wc -l) > 1 ] ; then ls -1tr /usr/sbin/r1soft/conf/server.allow | sed -e '\$d' ; fi | while read BackupServer ; do r1soft-setup --remove-key \$BackupServer ; done "
====================================================================================================================================

LVM EXTEND:

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

=======================================================================================
LOGS PDC NO MESSENGER DA WEBSERVICE E ALGUNS EVENTOS NO BANCO DSA WEBSVCDB
=======================================================================================
Refiz o shell com:

root@vhost19:/virtual/linux.scholar.com.br# chsh -s $(which sh) linuxscholar

=======================================================================================
RENOVANDO SSL ZIMBRA:
=======================================================================================
cd /opt/zimbra/ssl/zimbra/commercial

mv commercial.crt{,.old}  
mv commercial_ca.crt{,.old}

cp /home/operacoes/rcastro/Infolink/* .

mv 377a385f8b80041a.crt commercial.crt

mv gd_bundle-g2-g1.crt commercial_ca.crt

/opt/zimbra/bin/zmcertmgr verifycrt comm ./commercial.key ./commercial.crt ./commercial_ca.crt

/opt/zimbra/bin/zmcertmgr deploycrt comm ./commercial.crt ./commercial_ca.crt

/opt/zimbra/bin/zmcertmgr viewdeployedcrt
=======================================================================================
# wget https://support.plesk.com/hc/article_attachments/115004518545/poodle.zip
# unzip poodle.zip
# chmod +x poodle.sh
# for i in `echo 21 587 443 465 7081 8443 993 995 `; do /bin/sh /root/poodle.sh <IP> $i; done

=======================================================================================
Removendo Kernels antigos UBUNTU :

dpkg -l 'linux-*' | sed '/^ii/!d;/'"$(uname -r | sed "s/\(.*\)-\([^0-9]\+\)/\1/")"'/d;s/^[^ ]* [^ ]* \([^ ]*\).*/\1/;/[0-9]/!d' | xargs sudo apt-get -y purge
=======================================================================================

cat /infolink/etc/zabbix/datastore_vcenter02 | awk 'BEGIN{print "Storage","Uso"} ; BEGIN{print "---------- ----------"}; { print $1,$2/1073741824}' | column -t
=======================================================================================

cat  /var/log/nginx/access.log | awk 'BEGIN{print "Qtde","StatusCode"};$7 ~ /^[0-9]+$/ && $7 !~ /MISS/ { tot[$7]++ } END { for (i in tot) print tot[i],i } '  | column -t



FM8N3-J889P-DVDW8-B9VRV-6XT9Y

=======================================================================================
Senhores,
 
Uma breve explicação do que aconselhamos anteriormente e que costumamos implementar operacionalmente:
 
innodb_file_per_table: não fornece qualquer benefício de desempenho é apenas uma boa prática para agilizar a administração e um eventual crash recovery. A idéia aqui é termos uma opção de usar um arquivo InnoDB por tabela e permitir uma liberação de espaço sob demanda mais eficiente; seja por um truncate ou rebuild de tables.Também é necessário para alguns recursos avançados, como a compressão. 
 
innodb_buffer_pool_size: Esta será a principal mudança. Montaremos pool de buffers para os índices serem armazenados em cache. A idéia é configura-lo tão grande quanto possível, garantindo a utilização de memória e não discos físicos para a maioria das operações de leitura.
 
Slow Log: esta opção serve para vocês analisarem e otimizarem suas queries. Muito útil para achar eventuais gargalos no MySQL.
 
skip_name_resolve: Desejamos que o servidor evite consultar tabelas DNS desnecessariamente, pois assim isolamos uma eventual fonte de timeouts em casos de resolução lenta. O único impacto será de nossa administração, pois deveremos refazer os grants de seus usuários para os IPs do servidor. 
 
Outras configurações que executamos de tuning geralmente são:
 
innodb_log_file_size: Ajustamos o tamanho potencial dos logs "redo". Os logs de redo são usados para se certificar de que as gravações são rápidas e duradouras e (muito importante!) na recuperação de falhas. 
 
max_connections: Geralmente implementamos algumas limitações de conexões por usuários, evitando que um site impacte em outro no mesmo servidor. Justamente o seu cenário, pois como sabemos é muito freqüente o caso onde suas aplicações não fecham as conexões com o banco de dados.
 
innodb_flush_log_at_trx_commit: Aqui o intuito é maximizar a resiliência dos dados comitados no banco. É muito importante quando temos preocupação principal na segurança dos dados.
 
log_bin: Nosso pensamento é de que o binlog do MySQL deveria ser mandatório e não opcional e máquinas que não são meras réplicas de um master. Esta opção nos dám uma segurança extra para atuarmos em eventos de crash recovery, além de evitar uma eprda de dados por um estouroo de pilha, por exemplo.
 

=======================================================================================

git clone http://gitlab.infolink.com.br/valexandre/nginx.git
cd nginx
chmod 755 nginx_commands
./nginx_commands


=======================================================================================
Ver envio em GB ftp service :

for Mes in $(echo "Jul Aug Sep") ; do cat /var/log/proftpd/xfer | awk -v Mes=$Mes '{if ( $2 == Mes ) print $8 }' | awk -v Mes=$Mes '{Soma+=$1}END{print Mes,"=",Soma/1000000/1024 "GB"}'; done


=======================================================================================
    -> Listagem das políticas: 
/infolink/bin/check_sql_policy | egrep -v "backup|\#" | grep -v ^$ | tr -t '\n' ' ' | tr -d '\r' | sed -e "s/Servidor : /\n/g"  | awk '{if ( $2 == "Configurações" ) print $1,$6}' | sed -e "s/Está/SQLServer/g" | column -t

-> Listagem de servidores com SQL: 
salt-key -l acc | perl -pe 's/\x1b\[[0-9;]*[mG]//g' | while read Servidor ; do if salt $Servidor service.get_all | perl -pe 's/\x1b\[[0-9;]*[mG]//g' | egrep -i "mysql|mssql" > /dev/null 2>&1 ; then echo $Servidor ; fi ; done

=======================================================================================
# Configração Linux  /etc/salt/minion                                                                                                                                                                              
                                                                                                                                                                                                                   
sock_dir: /var/run/salt/minion                                                                                                                                                                                     
acceptance_wait_time: 60                                                                                                                                                                                           
recon_default: 10000                                                                                                                                                                                               
user: root                                                                                                                                                                                                         
                                                                                                                                                                                                                
master:                                                                                                                                                                                                            
- 192.168.254.41                                                                                                                                                                                                   
                                                                                                                                                                                                                   
loop_interval: 60                                                                                                                                                                                                  
                                                                                                                                                                                                                   
startup_states:                                                                                                                                                                                                    
- sls                                                                                                                                                                                                              
                                                                                                                                                                                                                 
log_level: debug                                                                                                                                                                                                   
#log_level: warning"                                                                                                                                                                                               
id: NOMEDOSERVIDOR  

=======================================================================================


SIGMA
Usuário: opadmin
Senha: Q2we<E9t

=======================================================================================

INF MDA06
Load de CPU 20  20 Out 2017 02:16:27  2m 10s   
Máquina estava com I/O alto.
Dropei o cache de memória existente afim de liberar recursos para escrita de novo cache:
root@mda06:~# free -m   
             total       used       free     shared    buffers     cached                       
Mem:          7978       7860        118          2        425        586                       
-/+ buffers/cache:       6848       1130        
Swap:         1881         32       1849        
root@mda06:~# sync && echo 3 > /proc/sys/vm/drop_caches                                         
root@mda06:~# free -m   
             total       used       free     shared    buffers     cached                       
Mem:          7978       6714       1263          2         10         30                       
-/+ buffers/cache:       6674       1304        
Swap:         1881         32       1849        
root@mda06:~#  

Parei o dovecot e verifiquei que muitas das conexões ainda estavam presas, portanto, tive que matar os processos manualmente:

root@mda06:~# ps aux | grep dovecot | grep -v grep | awk '{print $2}' | xargs -n1 kill -9      

Depois de parar todos os processo, iniciei novamente o dovecot.

As ações acima geraram um alarme esperado de POP e IMAP na monitoria, porém normalizados após a inicialização do DOVECOT.

Fiz um flush da fila do postfix local para forçar a entrega dos emails que ficaram em HOLD devido a parada do DOVECOT.

Foi identificado que uma conta catchall estava ocasionando uma grande espera na fila devido a cota estourada:
root@mda06:/etc/sysctl.d# postqueue -p | grep catchall@studiozero.com.br | wc -l                
103                     
root@mda06:/etc/sysctl.d#   

Fiz uma limpeza de emails na pasta de spam para liberar a entrega de novos emails.
A conta catchall@cormackshipping.com.br também teve sua pasta de Spam limpa.

Com isso o load voltou à sua normalidade.

=======================================================================================

select concat('KILL ',id,';') from information_schema.processlist where Command='Sleep' into outfile '/tmp/sleep.log'
source /tmp/arquivo.txt

=======================================================================================
Outra questão é a quantidade de erros de acesso ao MySQL (banco de dados) de seu servidor, o qual está aberto para o mundo e constrantemente recebe tentativas de brute force:
root@cloud847 ~]# grep "Access denied for user" /var/lib/mysql/mysql-error.log | awk '{print $9}' | cut -d\@ -f2 | sort | uniq -c | sort -nk1

=======================================================================================

Prezado Mauro,

Infelizmente no horário informado houve instabilidade em alguns servidores de nossa estrutura que afetou diretamente o seu Cloud e demais. A situação foi normalizada.

Poderia nos dizer se ainda há algum problema?

Reiteramos nosso compromisso com a qualidade técnica e de atendimento. Estamos buscando incessantemente melhoria em nossos sistemas/infra para que estes tipos de incidentes sejam reduzido sensivelmente.

Lamentamos o transtorno.

=======================================================================================

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


=======================================================================================
LIMPAR SPAM MDAS:

find /maildir/ -maxdepth 2 -type d | awk -F'/' '{print $4 "@" $3}' | grep -v ^@ | while read Conta ; do doveadm expunge -u $Conta mailbox Spam savedbefore 4w ; done

find /maildir/ -maxdepth 2 -type d | awk -F'/' '{print $4 "@" $3}' | grep -v ^@ | while read Conta ; do doveadm expunge -u $Conta mailbox Lixeira savedbefore 4w ; done

=======================================================================================

Verificar espaco storage via salt:

cat /infolink/etc/zabbix/datastore_{vcs,vcenter02} | sort -u | awk 'BEGIN{print "Storage","|","Livres(GB)"} ; BEGIN{print "---------- | ----------"}; { print $1,"|",$2/1073741824}' | column -t | grep "NAS01"
NAS01 | 0

=======================================================================================

grep 2017-12-05 /var/log/fail2ban.log | grep -vi already| awk '{print $8}' | sort | uniq -c | sort -nk1 | awk '{ if ( $1 >= 100) system("geoiplookup " $2)}'

=======================================================================================

ssh -t vivek@server1.cyberciti.biz << EOF
 sync
 sync
 sudo /sbin/shutdown -h 0
EOF
=======================================================================================

Verificar validade de Certificado:

 openssl x509 -in www.cursointellectus.com.br.crt -text -noout | egrep -i 'before|after'

 =======================================================================================
 REVERSO INFOLINK:

 70.187.200.in-addr.arpa

 =======================================================================================
Ver dominios:

 salt-ssh 'vhost19*' cmd.run 'apachectl -S' | perl -pe 's/\x1b\[[0-9;]*[mG]//g' | grep "port 80" | awk '{print $4}' | sed -e "s/www.//g" | egrep -v "novavhost|rel-vhost|utils-vhost|vhost1|infolink.com|infolinkti.com|w3br" 

=======================================================================================
INFOS de Memoria / CPU : 

 salt 'backup*' cmd.run "echo -n 'CPU: ' ; cat /proc/cpuinfo | grep processor | wc -l ; free -m | head -n+2 |tail -1 | awk '{print \"Memória:\" , \$2/1024, \"GB\"}'"  >> Backup_Info.txt
==================================================================================================================================================================================
*** dbhost04 ****
mysql> select * from mailcontrol_logs where destinatario='eliosantos@zard.com.br' and acao='remocao';
+--------+------------------------+------+---------+------------------------------------------------------------+------+-------+---------+
| id     | destinatario           | tipo | acao    | texto                                                      | alvo | ;l | ts                  |
+--------+------------------------+------+---------+------------------------------------------------------------+------+-------+---------+
| 218284 | eliosantos@zard.com.br | W    | remocao | Santos, Ana <aplsantos@carlsonwagonlit.com.br> 0.0.0.0/0 0 | E    | TODOS | 2014-12-01 15:23:44 |
+--------+------------------------+------+---------+------------------------------------------------------------+------+-------+----------+

imapsync  --host1 mda08.infolink.com.br --user1 informatica@rtsrio.com.br --password1  Star1010 --host2 exchange.infolink.com.br --user2 informatica@rtsrio.com.br --password2 Star1010
==================================================================================================================================================================================
O cliente pode fazer controle de cache em suas aplicações usando o web.config. Por exemplo:

<outputCacheSettings>
  <outputCacheProfiles>
    <add name="CacheProfile1" duration="60" />
  </outputCacheProfiles>
</outputCacheSettings>
Mais informações aqui: https://msdn.microsoft.com/pt-br/library/ms178606(v=vs.100).aspx
==================================================================================================================================================================================
Dism.exe /online /Cleanup-Image /StartComponentCleanup
==================================================================================================================================================================================
LVM EXTEND:
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
==================================================================================================================================================================================
LOGS PDC NO MESSENGER DA WEBSERVICE E ALGUNS EVENTOS NO BANCO DSA WEBSVCDB
==================================================================================================================================================================================
Removendo Kernels antigos UBUNTU :
dpkg -l 'linux-*' | sed '/^ii/!d;/'"$(uname -r | sed "s/\(.*\)-\([^0-9]\+\)/\1/")"'/d;s/^[^ ]* [^ ]* \([^ ]*\).*/\1/;/[0-9]/!d' | xargs sudo apt-get -y purge
==================================================================================================================================================================================
FM8N3-J889P-DVDW8-B9VRV-6XT9Y
==================================================================================================================================================================================
Senhores,
 
Uma breve explicação do que aconselhamos anteriormente e que costumamos implementar operacionalmente:
 
innodb_file_per_table: não fornece qualquer benefício de desempenho é apenas uma boa prática para agilizar a administração e um eventual crash recovery. A idéia aqui é termos uma opção de usar um arquivo InnoDB por tabela e permitir uma liberação de espaço sob demanda mais eficiente; seja por um truncate ou rebuild de tables.Também é necessário para alguns recursos avançados, como a compressão. 
 
innodb_buffer_pool_size: Esta será a principal mudança. Montaremos pool de buffers para os índices serem armazenados em cache. A idéia é configura-lo tão grande quanto possível, garantindo a utilização de memória e não discos físicos para a maioria das operações de leitura.
 
Slow Log: esta opção serve para vocês analisarem e otimizarem suas queries. Muito útil para achar eventuais gargalos no MySQL.
 
skip_name_resolve: Desejamos que o servidor evite consultar tabelas DNS desnecessariamente, pois assim isolamos uma eventual fonte de timeouts em casos de resolução lenta. O único impacto será de nossa administração, pois deveremos refazer os grants de seus usuários para os IPs do servidor. 
 
Outras configurações que executamos de tuning geralmente são:
 
innodb_log_file_size: Ajustamos o tamanho potencial dos logs "redo". Os logs de redo são usados para se certificar de que as gravações são rápidas e duradouras e (muito importante!) na recuperação de falhas. 
 
max_connections: Geralmente implementamos algumas limitações de conexões por usuários, evitando que um site impacte em outro no mesmo servidor. Justamente o seu cenário, pois como sabemos é muito freqüente o caso onde suas aplicações não fecham as conexões com o banco de dados.
 
innodb_flush_log_at_trx_commit: Aqui o intuito é maximizar a resiliência dos dados comitados no banco. É muito importante quando temos preocupação principal na segurança dos dados.
 
log_bin: Nosso pensamento é de que o binlog do MySQL deveria ser mandatório e não opcional e máquinas que não são meras réplicas de um master. Esta opção nos dám uma segurança extra para atuarmos em eventos de crash recovery, além de evitar uma eprda de dados por um estouroo de pilha, por exemplo.
==================================================================================================================================================================================
select concat('KILL ',id,';') from information_schema.processlist where Command='Sleep' into outfile '/tmp/sleep.log'
source /tmp/arquivo.txt
==================================================================================================================================================================================
FSCK LVM:

Then type few lines below to fixed it.
$vgchange --ignorelockingfailure -ay
$lvscan --ignorelockingfailure
$fsck -y /dev/VolumeGroup/LVname
############################################################################
 for i in $(cat /etc/passwd | cut -d ':' -f1); do echo "Crontab de $i"; crontab -l -u $i; done
==================================================================================================================================================================================
doveadm who | awk '{s+=$2} END {print s}'
 doveadm who | awk '{s+=$2} END {print s}'
==================================================================================================================================================================================
find ./20110*/mx*/ -type f -name "*maillog*" | sort | while read Arquivo ; do for MailId in $(zgrep "[from|to]=<paulomeloacao@infolink.com.br" $Arquivo | grep -v NOQUE | awk '{print $6}') ; do zgrep $MailId $Arquivo ; done ; done >> /home/mcotrim/Downloads/2011/RECEBIDOS/PAULOMELOACAO_FEVEREIRO.0.txt

find ./20110*/smtp-0*/ -type f -name "*smtp-0*" | sort | while read Arquivo ; do for MailId in $(zgrep "[from|to]=<andreiacn@infolink.com.br" $Arquivo | grep -v NOQUE | awk '{print $6}') ; do zgrep $MailId $Arquivo ; done ; done >> /home/mcotrim/Downloads/2011/ENVIADOS/ANDREIACN_FEVEREIRO.0.txt
==================================================================================================================================================================================
root@cloud627 [/home/microsites/mail/microsites.com.br/inaz_concursos/.FAILED/cur]# find . -type f -mtime -30 -exec grep -i Return {} \; | awk '{print $2}' | sort | uniq -c | sort -nk1 | awk '{print $2}' | sed -e 's/<//g' | sed -e 's/>//g' >> /home/operacoes/mcotrim/teste2.txt

find . -type f -mtime -30 -exec grep -i X-Failed-Recipients {} \; | awk '{print $2}' | sort | uniq -c | sort -nk1 | awk '{print $2}' | sed -e 's/<//g' | sed -e 's/>//g'

==================================================================================================================================================================================n

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


Policy - Blacklist / Whitelist --> dbhost02 --> mysql.4.1.10a --> banco email_infolink_com_br 


verificar emails
for i in $(zgrep "from=<rh@ibbca.com.br" /var/log/maillog-20160108 | grep "Jan  7" | awk '{print $6}') ; do zgrep $i /var/log/maillog-20160108 ; done


http://wiki.corp.infolink.com.br/doku.php/infraestrutura:correio:bloqueio_recebimento_e_envio


verificar uso por pasta --> for dirs in $(ls --color=never -l | grep "^d" | awk '{print $9}'); do du -hs $dirs;done

LIMPAR CACHE NGINX --> rm -rf /var/lib/nginx/cache/*

===============================================================================================================================

Compacta logs com mais de 100mb --> find /var/www/vhosts -type f -name "*log" -exec du {} \; | awk '{ if ( $1 >= 102400 ) print $2}' | xargs gzip -9 -f

FILTRA QUEM ESTA QTD MAIL POR USER NO DOMINIO
postqueue -c /etc/postfix-bounce -p | grep `date +%b`| rev | awk '{print $1}' | rev | sort | uniq -c | sort -nk1  | awk '{ if ( $1 >= 10 ) print }' | grep infolink

VER CONTEUDO
sudo postqueue -c /etc/postfix-bounce -p|grep "dominio.com"

SCRIPT DEL

for i in $(postqueue -c /etc/postfix-bounce -p | grep `date +%b`| rev | awk '{print $1}' | rev | cut -d@ -f2 | sort | uniq -c | sort -nk1  | awk '{ if ( $1 >= 50 ) print $2}') ; do pfdel *@$i /etc/postfix-bounce ; done
===============================================================================================================================
Verificar ADM dominio exchange
Get-RoleGroup -Organization domain.com -Identity "Organization Management" | Get-RoleGroupMember


INSERT dominios(matricula,dominio,login,senha,txtrans,uid,gid,home,shell,permitelogin,count,quota_type,per_session,limit_type,bytes_in_avail) values('31729','vcadv.com.br','vcadv','ftp@VCA@2015',0,1000,102,'/whost03/vcadv.com.br',NULL,0,0,'user','false','hard','3.072e+10';


update mysql.user set password=PASSWORD('Nog1ftp!') where user='alvoradaimov';
select User,Host from mysql.user;


*** dbhost04 ****
mysql> select * from mailcontrol_logs where destinatario='eliosantos@zard.com.br' and acao='remocao';
+--------+------------------------+------+---------+------------------------------------------------------------+------+-------+---------+
| id     | destinatario           | tipo | acao    | texto                                                      | alvo | ;l | ts                  |
+--------+------------------------+------+---------+------------------------------------------------------------+------+-------+---------+
| 218284 | eliosantos@zard.com.br | W    | remocao | Santos, Ana <aplsantos@carlsonwagonlit.com.br> 0.0.0.0/0 0 | E    | TODOS | 2014-12-01 15:23:44 |
+--------+------------------------+------+---------+------------------------------------------------------------+------+-------+----------+

imapsync  --host1 mda08.infolink.com.br --user1 informatica@rtsrio.com.br --password1  Star1010 --host2 exchange.infolink.com.br --user2 informatica@rtsrio.com.br --password2 Star1010

=================================================================================================================
O cliente pode fazer controle de cache em suas aplicações usando o web.config. Por exemplo:

<outputCacheSettings>
  <outputCacheProfiles>
    <add name="CacheProfile1" duration="60" />
  </outputCacheProfiles>
</outputCacheSettings>
Mais informações aqui: https://msdn.microsoft.com/pt-br/library/ms178606(v=vs.100).aspx

================================================================================================================================
Política de Recursos/Performance PHP

memory_limit = 128 MB
max_execution_time = 30 segundos
max_input_time = 60 segundos
post_max_size = 64 MB
upload_max_filesize = 64 MB
max_file_uploads = 20
Política de Recursos/Performance Plataforma de Hospedagem

Tempo de CPU: 120 à 180 segundos
Arquivos abertos: até 40 simultaneamente
Processos: até 10 simultaneamente
SSH: shell limitado, em esquema chrooted jail e sem /proc
===================================================================================================================
  PADRAO CONF APACHE RLIMIT:
  RLimitNPROC 5 10
  RLimitMEM 256000000 256000000
  RLimitCPU 120 180
====================================================================================================================================
Deve existir no WP

RewriteEngine On
  AddType application/x-httpd-php .php
  DirectoryIndex index.php
  <Directory />
        Options SymLinksIfOwnerMatch
        AllowOverride All
  </Directory>

====================================================================================================================================## Limitar conexoes por ip

iptables -I INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 30 --connlimit-mask 32 -j REJECT --reject-with tcp-reset

====================================================================================================================================

Verificar DDOS


netstat -n | grep EST | awk '{ print $5 }' | cut -d: -f1 | sort | uniq -c | sort -nr | perl -an -e 'use Socket; ($hostname, @trash) = gethostbyaddr(inet_aton($F[1]), AF_INET); print "$F[0]\t$F[1]\t$hostname\n";'

====================================================================================================================================

Verificar email to  from:

zgrep "@cenibra.com.br" /var/log/mail.log.4[2-4].gz | grep "to=<" | awk '{print $6}' | grep -v NOQUEU | while read Email ; do grep $Email | grep "@paradvogados.com.br" ; done


====================================================================================================================================

(13:56:59) Vega: find /maildir/ -maxdepth 5 -type d -name ".Spam" | while read SpamFolder ; do find $SpamFolder -type f -name "*mda04*" -mtime +30 -exec rm -v {} \; ; done
(13:57:01) Vega: find /maildir/ -maxdepth 4 -type d -name catchall | while read Catchall ; do find $Catchall -type f -name "*mda04*" -mtime +30 -exec rm -fv {} \; ; done
(13:57:08) Vega: Prá liberar espaço nas mdas.

====================================================================================================================================
TOP SENDER DOMINIO ---> 

zgrep qmgr mail.log.1.gz | grep "from=<.*@glcomunicacao.com.br" | awk '{print $7}' | cut -d"=" -f2 | cut -d"<" -f2 | cut -d">" -f1 | tr '[A-Z]' '[a-z]' | sort | uniq -c | sort -rn


Qtd por dominio :
X=`egrep "from=<.*@glcomunicacao.com.br" /var/log/mail.log | grep queue | awk '{print $9}' | cut -d"=" -f2` ; A=0 ; for I in $X ; do A=`expr $A + $I`; done ; echo $A

====================================================================================================================================

#   <Location />                                    
#    Order Deny,Allow                               
#    Deny from all                                  
#    Allow from 200.187.69.175 192.168.0.0/16 200.165.200.106                                            
#  </Location>          

sudo ifdown --exclude=lo -a && sudo ifup --exclude=lo -a



grep "message-id=<201" /var/log/mail.log | grep "5B@" | awk '{print $6}' | while read Check ; do grep $Check /var/log/mail.log ; done  | grep nrcpt | grep vinicius.voi@ago.com.br

====================================================================================================================================
Dism.exe /online /Cleanup-Image /StartComponentCleanup

killall -9 lmtp;invoke-rc.d dovecot stop;fuser -9 -k 143/tcp;sync && echo 3 > /proc/sys/vm/drop_caches; invoke-rc.d dovecot start;postsuper -r ALL

====================================================================================================================================Extensions wp:

php5-cli
php5-dev
php5-fpm
php5-cgi
php5-mysql
php5-xmlrpc
php5-curl
php5-gd
php-apc (not required, but recommended)
php-pear
php5-imap
php5-mcrypt
php5-pspell

====================================================================================================================================
Killar conexoes mysql :
use mysql;
select concat('KILL ',id,';') from information_schema.processlist where user='dominio' into outfile '/tmp/dominio.txt';
source /tmp/dominio.txt


insert into dominioscomservidorproprio (Dominio)values ('abac-br.org.br');

=====================================================================================================================================================================

Visudo zimbra zols :

%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmstat-fd *
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmslapd
%zimbra ALL=NOPASSWD:/opt/zimbra/postfix/sbin/postfix, /opt/zimbra/postfix/sbin/postalias, /opt/zimbra/postfix/sbin/qshape.pl, /opt/zimbra/postfix/sbin/postconf,/opt/zimbra/postfix/sbin/postsuper
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmqstat,/opt/zimbra/libexec/zmmtastatus
%zimbra ALL=NOPASSWD:/opt/zimbra/amavisd/sbin/amavis-mc
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmunbound
%zimbra ALL=NOPASSWD:/sbin/resolvconf *
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmmailboxdmgr
%zimbra ALL=NOPASSWD:/opt/zimbra/bin/zmcertmgr
%zimbra ALL=NOPASSWD:/opt/zimbra/nginx/sbin/nginx

=====================================================================================================================================================================                                            
15 3 * * * /usr/bin/certbot renew --quiet'

salt -C 'G@os_family:debian or G@os_family:redhat' cmd.run 'ls -1tr /usr/sbin/r1soft/conf/server.allow | tail -1'

cat output.txt  | tr '\n' ' ' | tr ' ' '\n'  | grep -v "^$" | tr '\n' ': ' | sed -e "s/::/ /g" | tr ':' '\n' | awk '$1 !~ /backup/ {print}' | egrep "backup|192"
=====================================================================================================================================================================

30 2 * * 1 /root/letsencrypt/letsencrypt-auto renew --email operacoes@infolink.com.br --agree-tos ; /etc/init.d/nginx restart >> /var/lo
g/letsencrypt.log
====================================================================================================================================salt -C 'G@os_family:debian or G@os_family:redhat' cmd.run "if [ $(ls -1tr /usr/sbin/r1soft/conf/server.allow | wc -l) > 1 ] ; then ls -1tr /usr/sbin/r1soft/conf/server.allow | sed -e '\$d' ; fi | while read BackupServer ; do r1soft-setup --remove-key \$BackupServer ; done "
====================================================================================================================================

LVM EXTEND:

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

=======================================================================================
LOGS PDC NO MESSENGER DA WEBSERVICE E ALGUNS EVENTOS NO BANCO DSA WEBSVCDB
=======================================================================================
Refiz o shell com:

root@vhost19:/virtual/linux.scholar.com.br# chsh -s $(which sh) linuxscholar

=======================================================================================
RENOVANDO SSL ZIMBRA:
=======================================================================================
cd /opt/zimbra/ssl/zimbra/commercial

mv commercial.crt{,.old}  
mv commercial_ca.crt{,.old}

cp /home/operacoes/rcastro/Infolink/* .

mv 377a385f8b80041a.crt commercial.crt

mv gd_bundle-g2-g1.crt commercial_ca.crt

/opt/zimbra/bin/zmcertmgr verifycrt comm ./commercial.key ./commercial.crt ./commercial_ca.crt

/opt/zimbra/bin/zmcertmgr deploycrt comm ./commercial.crt ./commercial_ca.crt

/opt/zimbra/bin/zmcertmgr viewdeployedcrt
=======================================================================================
# wget https://support.plesk.com/hc/article_attachments/115004518545/poodle.zip
# unzip poodle.zip
# chmod +x poodle.sh
# for i in `echo 21 587 443 465 7081 8443 993 995 `; do /bin/sh /root/poodle.sh <IP> $i; done

=======================================================================================
Removendo Kernels antigos UBUNTU :

dpkg -l 'linux-*' | sed '/^ii/!d;/'"$(uname -r | sed "s/\(.*\)-\([^0-9]\+\)/\1/")"'/d;s/^[^ ]* [^ ]* \([^ ]*\).*/\1/;/[0-9]/!d' | xargs sudo apt-get -y purge
=======================================================================================

cat /infolink/etc/zabbix/datastore_vcenter02 | awk 'BEGIN{print "Storage","Uso"} ; BEGIN{print "---------- ----------"}; { print $1,$2/1073741824}' | column -t
=======================================================================================

cat  /var/log/nginx/access.log | awk 'BEGIN{print "Qtde","StatusCode"};$7 ~ /^[0-9]+$/ && $7 !~ /MISS/ { tot[$7]++ } END { for (i in tot) print tot[i],i } '  | column -t



FM8N3-J889P-DVDW8-B9VRV-6XT9Y

=======================================================================================
Senhores,
 
Uma breve explicação do que aconselhamos anteriormente e que costumamos implementar operacionalmente:
 
innodb_file_per_table: não fornece qualquer benefício de desempenho é apenas uma boa prática para agilizar a administração e um eventual crash recovery. A idéia aqui é termos uma opção de usar um arquivo InnoDB por tabela e permitir uma liberação de espaço sob demanda mais eficiente; seja por um truncate ou rebuild de tables.Também é necessário para alguns recursos avançados, como a compressão. 
 
innodb_buffer_pool_size: Esta será a principal mudança. Montaremos pool de buffers para os índices serem armazenados em cache. A idéia é configura-lo tão grande quanto possível, garantindo a utilização de memória e não discos físicos para a maioria das operações de leitura.
 
Slow Log: esta opção serve para vocês analisarem e otimizarem suas queries. Muito útil para achar eventuais gargalos no MySQL.
 
skip_name_resolve: Desejamos que o servidor evite consultar tabelas DNS desnecessariamente, pois assim isolamos uma eventual fonte de timeouts em casos de resolução lenta. O único impacto será de nossa administração, pois deveremos refazer os grants de seus usuários para os IPs do servidor. 
 
Outras configurações que executamos de tuning geralmente são:
 
innodb_log_file_size: Ajustamos o tamanho potencial dos logs "redo". Os logs de redo são usados para se certificar de que as gravações são rápidas e duradouras e (muito importante!) na recuperação de falhas. 
 
max_connections: Geralmente implementamos algumas limitações de conexões por usuários, evitando que um site impacte em outro no mesmo servidor. Justamente o seu cenário, pois como sabemos é muito freqüente o caso onde suas aplicações não fecham as conexões com o banco de dados.
 
innodb_flush_log_at_trx_commit: Aqui o intuito é maximizar a resiliência dos dados comitados no banco. É muito importante quando temos preocupação principal na segurança dos dados.
 
log_bin: Nosso pensamento é de que o binlog do MySQL deveria ser mandatório e não opcional e máquinas que não são meras réplicas de um master. Esta opção nos dám uma segurança extra para atuarmos em eventos de crash recovery, além de evitar uma eprda de dados por um estouroo de pilha, por exemplo.
 

=======================================================================================

git clone http://gitlab.infolink.com.br/valexandre/nginx.git
cd nginx
chmod 755 nginx_commands
./nginx_commands


=======================================================================================
Ver envio em GB ftp service :

for Mes in $(echo "Jul Aug Sep") ; do cat /var/log/proftpd/xfer | awk -v Mes=$Mes '{if ( $2 == Mes ) print $8 }' | awk -v Mes=$Mes '{Soma+=$1}END{print Mes,"=",Soma/1000000/1024 "GB"}'; done


=======================================================================================
    -> Listagem das políticas: 
/infolink/bin/check_sql_policy | egrep -v "backup|\#" | grep -v ^$ | tr -t '\n' ' ' | tr -d '\r' | sed -e "s/Servidor : /\n/g"  | awk '{if ( $2 == "Configurações" ) print $1,$6}' | sed -e "s/Está/SQLServer/g" | column -t

-> Listagem de servidores com SQL: 
salt-key -l acc | perl -pe 's/\x1b\[[0-9;]*[mG]//g' | while read Servidor ; do if salt $Servidor service.get_all | perl -pe 's/\x1b\[[0-9;]*[mG]//g' | egrep -i "mysql|mssql" > /dev/null 2>&1 ; then echo $Servidor ; fi ; done

=======================================================================================
# Configração Linux  /etc/salt/minion                                                                                                                                                                              
                                                                                                                                                                                                                   
sock_dir: /var/run/salt/minion                                                                                                                                                                                     
acceptance_wait_time: 60                                                                                                                                                                                           
recon_default: 10000                                                                                                                                                                                               
user: root                                                                                                                                                                                                         
                                                                                                                                                                                                                
master:                                                                                                                                                                                                            
- 192.168.254.41                                                                                                                                                                                                   
                                                                                                                                                                                                                   
loop_interval: 60                                                                                                                                                                                                  
                                                                                                                                                                                                                   
startup_states:                                                                                                                                                                                                    
- sls                                                                                                                                                                                                              
                                                                                                                                                                                                                 
log_level: debug                                                                                                                                                                                                   
#log_level: warning"                                                                                                                                                                                               
id: NOMEDOSERVIDOR  

=======================================================================================


SIGMA
Usuário: opadmin
Senha: Q2we<E9t

=======================================================================================

INF MDA06
Load de CPU 20  20 Out 2017 02:16:27  2m 10s   
Máquina estava com I/O alto.
Dropei o cache de memória existente afim de liberar recursos para escrita de novo cache:
root@mda06:~# free -m   
             total       used       free     shared    buffers     cached                       
Mem:          7978       7860        118          2        425        586                       
-/+ buffers/cache:       6848       1130        
Swap:         1881         32       1849        
root@mda06:~# sync && echo 3 > /proc/sys/vm/drop_caches                                         
root@mda06:~# free -m   
             total       used       free     shared    buffers     cached                       
Mem:          7978       6714       1263          2         10         30                       
-/+ buffers/cache:       6674       1304        
Swap:         1881         32       1849        
root@mda06:~#  

Parei o dovecot e verifiquei que muitas das conexões ainda estavam presas, portanto, tive que matar os processos manualmente:

root@mda06:~# ps aux | grep dovecot | grep -v grep | awk '{print $2}' | xargs -n1 kill -9      

Depois de parar todos os processo, iniciei novamente o dovecot.

As ações acima geraram um alarme esperado de POP e IMAP na monitoria, porém normalizados após a inicialização do DOVECOT.

Fiz um flush da fila do postfix local para forçar a entrega dos emails que ficaram em HOLD devido a parada do DOVECOT.

Foi identificado que uma conta catchall estava ocasionando uma grande espera na fila devido a cota estourada:
root@mda06:/etc/sysctl.d# postqueue -p | grep catchall@studiozero.com.br | wc -l                
103                     
root@mda06:/etc/sysctl.d#   

Fiz uma limpeza de emails na pasta de spam para liberar a entrega de novos emails.
A conta catchall@cormackshipping.com.br também teve sua pasta de Spam limpa.

Com isso o load voltou à sua normalidade.

=======================================================================================

select concat('KILL ',id,';') from information_schema.processlist where Command='Sleep' into outfile '/tmp/sleep.log'
source /tmp/arquivo.txt

=======================================================================================
Outra questão é a quantidade de erros de acesso ao MySQL (banco de dados) de seu servidor, o qual está aberto para o mundo e constrantemente recebe tentativas de brute force:
root@cloud847 ~]# grep "Access denied for user" /var/lib/mysql/mysql-error.log | awk '{print $9}' | cut -d\@ -f2 | sort | uniq -c | sort -nk1

=======================================================================================

Prezado Mauro,

Infelizmente no horário informado houve instabilidade em alguns servidores de nossa estrutura que afetou diretamente o seu Cloud e demais. A situação foi normalizada.

Poderia nos dizer se ainda há algum problema?

Reiteramos nosso compromisso com a qualidade técnica e de atendimento. Estamos buscando incessantemente melhoria em nossos sistemas/infra para que estes tipos de incidentes sejam reduzido sensivelmente.

Lamentamos o transtorno.

=======================================================================================

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


=======================================================================================
LIMPAR SPAM MDAS:

find /maildir/ -maxdepth 2 -type d | awk -F'/' '{print $4 "@" $3}' | grep -v ^@ | while read Conta ; do doveadm expunge -u $Conta mailbox Spam savedbefore 4w ; done

find /maildir/ -maxdepth 2 -type d | awk -F'/' '{print $4 "@" $3}' | grep -v ^@ | while read Conta ; do doveadm expunge -u $Conta mailbox Lixeira savedbefore 4w ; done

=======================================================================================

Verificar espaco storage via salt:

cat /infolink/etc/zabbix/datastore_{vcs,vcenter02} | sort -u | awk 'BEGIN{print "Storage","|","Livres(GB)"} ; BEGIN{print "---------- | ----------"}; { print $1,"|",$2/1073741824}' | column -t | grep "NAS01"
NAS01 | 0

=======================================================================================

grep 2017-12-05 /var/log/fail2ban.log | grep -vi already| awk '{print $8}' | sort | uniq -c | sort -nk1 | awk '{ if ( $1 >= 100) system("geoiplookup " $2)}'

=======================================================================================

ssh -t vivek@server1.cyberciti.biz << EOF
 sync
 sync
 sudo /sbin/shutdown -h 0
EOF
=======================================================================================

Verificar validade de Certificado:

 openssl x509 -in www.cursointellectus.com.br.crt -text -noout | egrep -i 'before|after'

 =======================================================================================
 REVERSO INFOLINK:

 70.187.200.in-addr.arpa

 =======================================================================================
Ver dominios:

 salt-ssh 'vhost19*' cmd.run 'apachectl -S' | perl -pe 's/\x1b\[[0-9;]*[mG]//g' | grep "port 80" | awk '{print $4}' | sed -e "s/www.//g" | egrep -v "novavhost|rel-vhost|utils-vhost|vhost1|infolink.com|infolinkti.com|w3br" 

=======================================================================================
INFOS de Memoria / CPU : 

 salt 'backup*' cmd.run "echo -n 'CPU: ' ; cat /proc/cpuinfo | grep processor | wc -l ; free -m | head -n+2 |tail -1 | awk '{print \"Memória:\" , \$2/1024, \"GB\"}'"  >> Backup_Info.txt
=======================================================================================
FSCK LVM:

Then type few lines below to fixed it.
$vgchange --ignorelockingfailure -ay
$lvscan --ignorelockingfailure
$fsck -y /dev/VolumeGroup/LVname

=========================================================================================

SSL01 Config Cert:

fullchain --> .crt + bundle

privkey -->  .key

=========================================================================================

Liberar ip nas shareds:

foi necessario a adição do range no arquivo  : /infolink/etc/BRASIL_CIDR_ALLOW


E depois executar o script  : /infolink/bin/block_cidr

=========================================================================================
Apagar spam em mdas:


find /maildir/ -mindepth 2 -maxdepth 2 -name "catchall" -print | awk -F'/' '{print $4 "@" $3}' | while read Catchall ; do doveadm expunge -u $Conta mailbox % savedbefore 2w ; done

=========================================================================================

BANCO ONDE FICA APONTAMENTOS DE MDAS

 mysql -h 192.168.254.29 -u autenticador -p'gm5y937o' autenticador 

=========================================================================================
 for i in $(cat /etc/passwd | cut -d ':' -f1); do echo "Crontab de $i"; crontab -l -u $i; done

 =========================================================================================
doveadm who | awk '{s+=$2} END {print s}'
 doveadm who | awk '{s+=$2} END {print s}'

=========================================================================================


Note que a incidência é grande perto dos horários entre 6:00 e 9:59, depois entre 10:00 e 12:59 horas e de 13 a 18:59h.
root@mda14:/maildir# grep 85.93.20.106 /var/log/dovecot*.log | grep "Mar 27 1[0-2]" | wc -l
1804
root@mda14:/maildir# grep 85.93.20.106 /var/log/dovecot*.log | grep "Mar 27 1[3-8]" | wc -l
3260
root@mda14:/maildir# grep 85.93.20.106 /var/log/dovecot*.log | grep "Mar 27 0[6-9]" | wc -l
2358
root@mda14:/maildir#


Note que os IPs que mais tiveram erros foram internacionais:
root@mda14:/maildir# grep "auth failed" /var/log/dovecot*.log | awk '{print $17}' | sort | uniq -c | sort -nrk1 | head -10
7888 rip=85.93.20.106,
2267 method=PLAIN,
1057 rip=185.222.211.30,
56 rip=192.168.30.61,
55 rip=192.168.30.63,
55 rip=192.168.30.60,
35 rip=192.168.30.62,
26 rip=189.24.17.98,
23 rip=189.122.154.205,
16 rip=187.14.36.140,
root@mda14:/maildir#


##################### O que pode ser feito #####################

- Remover domínios que não apontam para nosso servidor da estrutura:
root@mda14:/maildir# ls -1 | while read Dom ; do if host pop.$(echo $Dom) | grep "has address" | grep 200.187.64.103 >> /dev/null 2>&1; then echo " " >> /dev/null ; else echo $Dom ; fi ; done | wc -l
116
root@mda14:/maildir# ls -1 | wc -l
802
root@mda14:/maildir#

 iptables   
 -I PREROUTING -t raw 85.93.20.0/24 -j DROP

==============================================================================================================


 root@lhost11 httpd]# find /var/log/httpd/logs/ -type f -mtime +30  -exec gzip -9 {} \;
rsync --remove-source-files -Phravu /var/log/httpd/logs/*2016* root@loghistory02.infolink.com.br:/backup/drobo/lhost11/var/log/httpd/logs/

Dados acesso FTP:
Usuário: texacohave
Senha: eVQw2ycFbtmUIKClGXQ9B

Dados Mysql:
Base: aplicativotexacohaveonline_com_br
Usuário: texacohave
Senha: I1ltirOOBbVkflS5U6MwWv
Comandos uteis:


Policy - Blacklist / Whitelist --> dbhost02 --> mysql.4.1.10a --> banco email_infolink_com_br 


verificar emails
for i in $(zgrep "from=<rh@ibbca.com.br" /var/log/maillog-20160108 | grep "Jan  7" | awk '{print $6}') ; do zgrep $i /var/log/maillog-20160108 ; done


http://wiki.corp.infolink.com.br/doku.php/infraestrutura:correio:bloqueio_recebimento_e_envio


verificar uso por pasta --> for dirs in $(ls --color=never -l | grep "^d" | awk '{print $9}'); do du -hs $dirs;done

LIMPAR CACHE NGINX --> rm -rf /var/lib/nginx/cache/*

===============================================================================================================================

Compacta logs com mais de 100mb --> find /var/www/vhosts -type f -name "*log" -exec du {} \; | awk '{ if ( $1 >= 102400 ) print $2}' | xargs gzip -9 -f

FILTRA QUEM ESTA QTD MAIL POR USER NO DOMINIO
postqueue -c /etc/postfix-bounce -p | grep `date +%b`| rev | awk '{print $1}' | rev | sort | uniq -c | sort -nk1  | awk '{ if ( $1 >= 10 ) print }' | grep infolink

VER CONTEUDO
sudo postqueue -c /etc/postfix-bounce -p|grep "dominio.com"

SCRIPT DEL

for i in $(postqueue -c /etc/postfix-bounce -p | grep `date +%b`| rev | awk '{print $1}' | rev | cut -d@ -f2 | sort | uniq -c | sort -nk1  | awk '{ if ( $1 >= 50 ) print $2}') ; do pfdel *@$i /etc/postfix-bounce ; done
===============================================================================================================================
Verificar ADM dominio exchange
Get-RoleGroup -Organization domain.com -Identity "Organization Management" | Get-RoleGroupMember


INSERT dominios(matricula,dominio,login,senha,txtrans,uid,gid,home,shell,permitelogin,count,quota_type,per_session,limit_type,bytes_in_avail) values('31729','vcadv.com.br','vcadv','ftp@VCA@2015',0,1000,102,'/whost03/vcadv.com.br',NULL,0,0,'user','false','hard','3.072e+10';


update mysql.user set password=PASSWORD('Nog1ftp!') where user='alvoradaimov';
select User,Host from mysql.user;


*** dbhost04 ****
mysql> select * from mailcontrol_logs where destinatario='eliosantos@zard.com.br' and acao='remocao';
+--------+------------------------+------+---------+------------------------------------------------------------+------+-------+---------+
| id     | destinatario           | tipo | acao    | texto                                                      | alvo | ;l | ts                  |
+--------+------------------------+------+---------+------------------------------------------------------------+------+-------+---------+
| 218284 | eliosantos@zard.com.br | W    | remocao | Santos, Ana <aplsantos@carlsonwagonlit.com.br> 0.0.0.0/0 0 | E    | TODOS | 2014-12-01 15:23:44 |
+--------+------------------------+------+---------+------------------------------------------------------------+------+-------+----------+

imapsync  --host1 mda08.infolink.com.br --user1 informatica@rtsrio.com.br --password1  Star1010 --host2 exchange.infolink.com.br --user2 informatica@rtsrio.com.br --password2 Star1010

=================================================================================================================
O cliente pode fazer controle de cache em suas aplicações usando o web.config. Por exemplo:

<outputCacheSettings>
  <outputCacheProfiles>
    <add name="CacheProfile1" duration="60" />
  </outputCacheProfiles>
</outputCacheSettings>
Mais informações aqui: https://msdn.microsoft.com/pt-br/library/ms178606(v=vs.100).aspx

================================================================================================================================
Política de Recursos/Performance PHP

memory_limit = 128 MB
max_execution_time = 30 segundos
max_input_time = 60 segundos
post_max_size = 64 MB
upload_max_filesize = 64 MB
max_file_uploads = 20
Política de Recursos/Performance Plataforma de Hospedagem

Tempo de CPU: 120 à 180 segundos
Arquivos abertos: até 40 simultaneamente
Processos: até 10 simultaneamente
SSH: shell limitado, em esquema chrooted jail e sem /proc
===================================================================================================================
  PADRAO CONF APACHE RLIMIT:
  RLimitNPROC 5 10
  RLimitMEM 256000000 256000000
  RLimitCPU 120 180
====================================================================================================================================
Deve existir no WP

RewriteEngine On
  AddType application/x-httpd-php .php
  DirectoryIndex index.php
  <Directory />
        Options SymLinksIfOwnerMatch
        AllowOverride All
  </Directory>

====================================================================================================================================## Limitar conexoes por ip

iptables -I INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 30 --connlimit-mask 32 -j REJECT --reject-with tcp-reset

====================================================================================================================================

Verificar DDOS


netstat -n | grep EST | awk '{ print $5 }' | cut -d: -f1 | sort | uniq -c | sort -nr | perl -an -e 'use Socket; ($hostname, @trash) = gethostbyaddr(inet_aton($F[1]), AF_INET); print "$F[0]\t$F[1]\t$hostname\n";'

====================================================================================================================================

Verificar email to  from:

zgrep "@cenibra.com.br" /var/log/mail.log.4[2-4].gz | grep "to=<" | awk '{print $6}' | grep -v NOQUEU | while read Email ; do grep $Email | grep "@paradvogados.com.br" ; done


====================================================================================================================================

(13:56:59) Vega: find /maildir/ -maxdepth 5 -type d -name ".Spam" | while read SpamFolder ; do find $SpamFolder -type f -name "*mda04*" -mtime +30 -exec rm -v {} \; ; done
(13:57:01) Vega: find /maildir/ -maxdepth 4 -type d -name catchall | while read Catchall ; do find $Catchall -type f -name "*mda04*" -mtime +30 -exec rm -fv {} \; ; done
(13:57:08) Vega: Prá liberar espaço nas mdas.

====================================================================================================================================
TOP SENDER DOMINIO ---> 

zgrep qmgr mail.log.1.gz | grep "from=<.*@glcomunicacao.com.br" | awk '{print $7}' | cut -d"=" -f2 | cut -d"<" -f2 | cut -d">" -f1 | tr '[A-Z]' '[a-z]' | sort | uniq -c | sort -rn


Qtd por dominio :
X=`egrep "from=<.*@glcomunicacao.com.br" /var/log/mail.log | grep queue | awk '{print $9}' | cut -d"=" -f2` ; A=0 ; for I in $X ; do A=`expr $A + $I`; done ; echo $A

====================================================================================================================================

#   <Location />                                    
#    Order Deny,Allow                               
#    Deny from all                                  
#    Allow from 200.187.69.175 192.168.0.0/16 200.165.200.106                                            
#  </Location>          

sudo ifdown --exclude=lo -a && sudo ifup --exclude=lo -a



grep "message-id=<201" /var/log/mail.log | grep "5B@" | awk '{print $6}' | while read Check ; do grep $Check /var/log/mail.log ; done  | grep nrcpt | grep vinicius.voi@ago.com.br

====================================================================================================================================
Dism.exe /online /Cleanup-Image /StartComponentCleanup

killall -9 lmtp;invoke-rc.d dovecot stop;fuser -9 -k 143/tcp;sync && echo 3 > /proc/sys/vm/drop_caches; invoke-rc.d dovecot start;postsuper -r ALL

====================================================================================================================================Extensions wp:

php5-cli
php5-dev
php5-fpm
php5-cgi
php5-mysql
php5-xmlrpc
php5-curl
php5-gd
php-apc (not required, but recommended)
php-pear
php5-imap
php5-mcrypt
php5-pspell

====================================================================================================================================
Killar conexoes mysql :
use mysql;
select concat('KILL ',id,';') from information_schema.processlist where user='dominio' into outfile '/tmp/dominio.txt';
source /tmp/dominio.txt


insert into dominioscomservidorproprio (Dominio)values ('abac-br.org.br');

=====================================================================================================================================================================

Visudo zimbra zols :

%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmstat-fd *
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmslapd
%zimbra ALL=NOPASSWD:/opt/zimbra/postfix/sbin/postfix, /opt/zimbra/postfix/sbin/postalias, /opt/zimbra/postfix/sbin/qshape.pl, /opt/zimbra/postfix/sbin/postconf,/opt/zimbra/postfix/sbin/postsuper
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmqstat,/opt/zimbra/libexec/zmmtastatus
%zimbra ALL=NOPASSWD:/opt/zimbra/amavisd/sbin/amavis-mc
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmunbound
%zimbra ALL=NOPASSWD:/sbin/resolvconf *
%zimbra ALL=NOPASSWD:/opt/zimbra/libexec/zmmailboxdmgr
%zimbra ALL=NOPASSWD:/opt/zimbra/bin/zmcertmgr
%zimbra ALL=NOPASSWD:/opt/zimbra/nginx/sbin/nginx

=====================================================================================================================================================================                                            
15 3 * * * /usr/bin/certbot renew --quiet'

salt -C 'G@os_family:debian or G@os_family:redhat' cmd.run 'ls -1tr /usr/sbin/r1soft/conf/server.allow | tail -1'

cat output.txt  | tr '\n' ' ' | tr ' ' '\n'  | grep -v "^$" | tr '\n' ': ' | sed -e "s/::/ /g" | tr ':' '\n' | awk '$1 !~ /backup/ {print}' | egrep "backup|192"
=====================================================================================================================================================================

30 2 * * 1 /root/letsencrypt/letsencrypt-auto renew --email operacoes@infolink.com.br --agree-tos ; /etc/init.d/nginx restart >> /var/lo
g/letsencrypt.log
====================================================================================================================================salt -C 'G@os_family:debian or G@os_family:redhat' cmd.run "if [ $(ls -1tr /usr/sbin/r1soft/conf/server.allow | wc -l) > 1 ] ; then ls -1tr /usr/sbin/r1soft/conf/server.allow | sed -e '\$d' ; fi | while read BackupServer ; do r1soft-setup --remove-key \$BackupServer ; done "
====================================================================================================================================

LVM EXTEND:

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

=======================================================================================
LOGS PDC NO MESSENGER DA WEBSERVICE E ALGUNS EVENTOS NO BANCO DSA WEBSVCDB
=======================================================================================
Refiz o shell com:

root@vhost19:/virtual/linux.scholar.com.br# chsh -s $(which sh) linuxscholar

=======================================================================================
RENOVANDO SSL ZIMBRA:
=======================================================================================
cd /opt/zimbra/ssl/zimbra/commercial

mv commercial.crt{,.old}  
mv commercial_ca.crt{,.old}

cp /home/operacoes/rcastro/Infolink/* .

mv 377a385f8b80041a.crt commercial.crt

mv gd_bundle-g2-g1.crt commercial_ca.crt

/opt/zimbra/bin/zmcertmgr verifycrt comm ./commercial.key ./commercial.crt ./commercial_ca.crt

/opt/zimbra/bin/zmcertmgr deploycrt comm ./commercial.crt ./commercial_ca.crt

/opt/zimbra/bin/zmcertmgr viewdeployedcrt
=======================================================================================
# wget https://support.plesk.com/hc/article_attachments/115004518545/poodle.zip
# unzip poodle.zip
# chmod +x poodle.sh
# for i in `echo 21 587 443 465 7081 8443 993 995 `; do /bin/sh /root/poodle.sh <IP> $i; done

=======================================================================================
Removendo Kernels antigos UBUNTU :

dpkg -l 'linux-*' | sed '/^ii/!d;/'"$(uname -r | sed "s/\(.*\)-\([^0-9]\+\)/\1/")"'/d;s/^[^ ]* [^ ]* \([^ ]*\).*/\1/;/[0-9]/!d' | xargs sudo apt-get -y purge
=======================================================================================

cat /infolink/etc/zabbix/datastore_vcenter02 | awk 'BEGIN{print "Storage","Uso"} ; BEGIN{print "---------- ----------"}; { print $1,$2/1073741824}' | column -t
=======================================================================================

cat  /var/log/nginx/access.log | awk 'BEGIN{print "Qtde","StatusCode"};$7 ~ /^[0-9]+$/ && $7 !~ /MISS/ { tot[$7]++ } END { for (i in tot) print tot[i],i } '  | column -t



FM8N3-J889P-DVDW8-B9VRV-6XT9Y

=======================================================================================
Senhores,
 
Uma breve explicação do que aconselhamos anteriormente e que costumamos implementar operacionalmente:
 
innodb_file_per_table: não fornece qualquer benefício de desempenho é apenas uma boa prática para agilizar a administração e um eventual crash recovery. A idéia aqui é termos uma opção de usar um arquivo InnoDB por tabela e permitir uma liberação de espaço sob demanda mais eficiente; seja por um truncate ou rebuild de tables.Também é necessário para alguns recursos avançados, como a compressão. 
 
innodb_buffer_pool_size: Esta será a principal mudança. Montaremos pool de buffers para os índices serem armazenados em cache. A idéia é configura-lo tão grande quanto possível, garantindo a utilização de memória e não discos físicos para a maioria das operações de leitura.
 
Slow Log: esta opção serve para vocês analisarem e otimizarem suas queries. Muito útil para achar eventuais gargalos no MySQL.
 
skip_name_resolve: Desejamos que o servidor evite consultar tabelas DNS desnecessariamente, pois assim isolamos uma eventual fonte de timeouts em casos de resolução lenta. O único impacto será de nossa administração, pois deveremos refazer os grants de seus usuários para os IPs do servidor. 
 
Outras configurações que executamos de tuning geralmente são:
 
innodb_log_file_size: Ajustamos o tamanho potencial dos logs "redo". Os logs de redo são usados para se certificar de que as gravações são rápidas e duradouras e (muito importante!) na recuperação de falhas. 
 
max_connections: Geralmente implementamos algumas limitações de conexões por usuários, evitando que um site impacte em outro no mesmo servidor. Justamente o seu cenário, pois como sabemos é muito freqüente o caso onde suas aplicações não fecham as conexões com o banco de dados.
 
innodb_flush_log_at_trx_commit: Aqui o intuito é maximizar a resiliência dos dados comitados no banco. É muito importante quando temos preocupação principal na segurança dos dados.
 
log_bin: Nosso pensamento é de que o binlog do MySQL deveria ser mandatório e não opcional e máquinas que não são meras réplicas de um master. Esta opção nos dám uma segurança extra para atuarmos em eventos de crash recovery, além de evitar uma eprda de dados por um estouroo de pilha, por exemplo.
 

=======================================================================================

git clone http://gitlab.infolink.com.br/valexandre/nginx.git
cd nginx
chmod 755 nginx_commands
./nginx_commands


=======================================================================================
Ver envio em GB ftp service :

for Mes in $(echo "Jul Aug Sep") ; do cat /var/log/proftpd/xfer | awk -v Mes=$Mes '{if ( $2 == Mes ) print $8 }' | awk -v Mes=$Mes '{Soma+=$1}END{print Mes,"=",Soma/1000000/1024 "GB"}'; done


=======================================================================================
    -> Listagem das políticas: 
/infolink/bin/check_sql_policy | egrep -v "backup|\#" | grep -v ^$ | tr -t '\n' ' ' | tr -d '\r' | sed -e "s/Servidor : /\n/g"  | awk '{if ( $2 == "Configurações" ) print $1,$6}' | sed -e "s/Está/SQLServer/g" | column -t

-> Listagem de servidores com SQL: 
salt-key -l acc | perl -pe 's/\x1b\[[0-9;]*[mG]//g' | while read Servidor ; do if salt $Servidor service.get_all | perl -pe 's/\x1b\[[0-9;]*[mG]//g' | egrep -i "mysql|mssql" > /dev/null 2>&1 ; then echo $Servidor ; fi ; done

=======================================================================================
# Configração Linux  /etc/salt/minion                                                                                                                                                                              
                                                                                                                                                                                                                   
sock_dir: /var/run/salt/minion                                                                                                                                                                                     
acceptance_wait_time: 60                                                                                                                                                                                           
recon_default: 10000                                                                                                                                                                                               
user: root                                                                                                                                                                                                         
                                                                                                                                                                                                                
master:                                                                                                                                                                                                            
- 192.168.254.41                                                                                                                                                                                                   
                                                                                                                                                                                                                   
loop_interval: 60                                                                                                                                                                                                  
                                                                                                                                                                                                                   
startup_states:                                                                                                                                                                                                    
- sls                                                                                                                                                                                                              
                                                                                                                                                                                                                 
log_level: debug                                                                                                                                                                                                   
#log_level: warning"                                                                                                                                                                                               
id: NOMEDOSERVIDOR  

=======================================================================================


SIGMA
Usuário: opadmin
Senha: Q2we<E9t

=======================================================================================

INF MDA06
Load de CPU 20  20 Out 2017 02:16:27  2m 10s   
Máquina estava com I/O alto.
Dropei o cache de memória existente afim de liberar recursos para escrita de novo cache:
root@mda06:~# free -m   
             total       used       free     shared    buffers     cached                       
Mem:          7978       7860        118          2        425        586                       
-/+ buffers/cache:       6848       1130        
Swap:         1881         32       1849        
root@mda06:~# sync && echo 3 > /proc/sys/vm/drop_caches                                         
root@mda06:~# free -m   
             total       used       free     shared    buffers     cached                       
Mem:          7978       6714       1263          2         10         30                       
-/+ buffers/cache:       6674       1304        
Swap:         1881         32       1849        
root@mda06:~#  

Parei o dovecot e verifiquei que muitas das conexões ainda estavam presas, portanto, tive que matar os processos manualmente:

root@mda06:~# ps aux | grep dovecot | grep -v grep | awk '{print $2}' | xargs -n1 kill -9      

Depois de parar todos os processo, iniciei novamente o dovecot.

As ações acima geraram um alarme esperado de POP e IMAP na monitoria, porém normalizados após a inicialização do DOVECOT.

Fiz um flush da fila do postfix local para forçar a entrega dos emails que ficaram em HOLD devido a parada do DOVECOT.

Foi identificado que uma conta catchall estava ocasionando uma grande espera na fila devido a cota estourada:
root@mda06:/etc/sysctl.d# postqueue -p | grep catchall@studiozero.com.br | wc -l                
103                     
root@mda06:/etc/sysctl.d#   

Fiz uma limpeza de emails na pasta de spam para liberar a entrega de novos emails.
A conta catchall@cormackshipping.com.br também teve sua pasta de Spam limpa.

Com isso o load voltou à sua normalidade.

=======================================================================================

select concat('KILL ',id,';') from information_schema.processlist where Command='Sleep' into outfile '/tmp/sleep.log'
source /tmp/arquivo.txt

=======================================================================================
Outra questão é a quantidade de erros de acesso ao MySQL (banco de dados) de seu servidor, o qual está aberto para o mundo e constrantemente recebe tentativas de brute force:
root@cloud847 ~]# grep "Access denied for user" /var/lib/mysql/mysql-error.log | awk '{print $9}' | cut -d\@ -f2 | sort | uniq -c | sort -nk1

=======================================================================================

Prezado Mauro,

Infelizmente no horário informado houve instabilidade em alguns servidores de nossa estrutura que afetou diretamente o seu Cloud e demais. A situação foi normalizada.

Poderia nos dizer se ainda há algum problema?

Reiteramos nosso compromisso com a qualidade técnica e de atendimento. Estamos buscando incessantemente melhoria em nossos sistemas/infra para que estes tipos de incidentes sejam reduzido sensivelmente.

Lamentamos o transtorno.

=======================================================================================

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


=======================================================================================
LIMPAR SPAM MDAS:

find /maildir/ -maxdepth 2 -type d | awk -F'/' '{print $4 "@" $3}' | grep -v ^@ | while read Conta ; do doveadm expunge -u $Conta mailbox Spam savedbefore 4w ; done

find /maildir/ -maxdepth 2 -type d | awk -F'/' '{print $4 "@" $3}' | grep -v ^@ | while read Conta ; do doveadm expunge -u $Conta mailbox Lixeira savedbefore 4w ; done

=======================================================================================

Verificar espaco storage via salt:

cat /infolink/etc/zabbix/datastore_{vcs,vcenter02} | sort -u | awk 'BEGIN{print "Storage","|","Livres(GB)"} ; BEGIN{print "---------- | ----------"}; { print $1,"|",$2/1073741824}' | column -t | grep "NAS01"
NAS01 | 0

=======================================================================================

grep 2017-12-05 /var/log/fail2ban.log | grep -vi already| awk '{print $8}' | sort | uniq -c | sort -nk1 | awk '{ if ( $1 >= 100) system("geoiplookup " $2)}'

=======================================================================================

ssh -t vivek@server1.cyberciti.biz << EOF
 sync
 sync
 sudo /sbin/shutdown -h 0
EOF
=======================================================================================

Verificar validade de Certificado:

 openssl x509 -in www.cursointellectus.com.br.crt -text -noout | egrep -i 'before|after'

 =======================================================================================
 REVERSO INFOLINK:

 70.187.200.in-addr.arpa

 =======================================================================================
Ver dominios:

 salt-ssh 'vhost19*' cmd.run 'apachectl -S' | perl -pe 's/\x1b\[[0-9;]*[mG]//g' | grep "port 80" | awk '{print $4}' | sed -e "s/www.//g" | egrep -v "novavhost|rel-vhost|utils-vhost|vhost1|infolink.com|infolinkti.com|w3br" 

=======================================================================================
INFOS de Memoria / CPU : 

 salt 'backup*' cmd.run "echo -n 'CPU: ' ; cat /proc/cpuinfo | grep processor | wc -l ; free -m | head -n+2 |tail -1 | awk '{print \"Memória:\" , \$2/1024, \"GB\"}'"  >> Backup_Info.txt
=======================================================================================
FSCK LVM:

Then type few lines below to fixed it.
$vgchange --ignorelockingfailure -ay
$lvscan --ignorelockingfailure
$fsck -y /dev/VolumeGroup/LVname

=========================================================================================

SSL01 Config Cert:

fullchain --> .crt + bundle

privkey -->  .key

=========================================================================================

Liberar ip nas shareds:

foi necessario a adição do range no arquivo  : /infolink/etc/BRASIL_CIDR_ALLOW


E depois executar o script  : /infolink/bin/block_cidr

=========================================================================================
Apagar spam em mdas:


find /maildir/ -mindepth 2 -maxdepth 2 -name "catchall" -print | awk -F'/' '{print $4 "@" $3}' | while read Catchall ; do doveadm expunge -u $Conta mailbox % savedbefore 2w ; done

=========================================================================================

BANCO ONDE FICA APONTAMENTOS DE MDAS

 mysql -h 192.168.254.29 -u autenticador -p'gm5y937o' autenticador 

=========================================================================================
 for i in $(cat /etc/passwd | cut -d ':' -f1); do echo "Crontab de $i"; crontab -l -u $i; done

 =========================================================================================
doveadm who | awk '{s+=$2} END {print s}'
 doveadm who | awk '{s+=$2} END {print s}'
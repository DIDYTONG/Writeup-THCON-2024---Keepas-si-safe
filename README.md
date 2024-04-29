# Keepas-si-safe


### Writeup THCON 2024 

**Difficulty**: 500 points | 6 solves

**Description**: We believe the bad guys got a hold of a memory dump on one of our machines. Looking through our logs, we also realized they were able to access this Database file. The person responsible for this machine says there is no way they could have gained access to his password manager - could you have a look ?
NB: The exploitation is feasible on a Chromium-based browser.

**Author**: Spyrovic

## 1. Investiagtion 

Once the challenge has been downloaded and extracted from its archive, we are left with two :

```
kali@kali ~/D/T/keepass-chall> ls
Database.kdbx  adupont.dmp
```

The first is a .kdbx file. 
When we try to open it, it asks us for a password that we don't have (The flag is inside?).

The second file is .dmp, which corresponds to a machine memory dump.

## 2. A deep dive into the memory dump  
Since this is a memory dump, we'll be working with the forensic tool [Volatility3](https://github.com/volatilityfoundation/volatility3)
First, we'll try to enumerate the dump. One of the first commands we can do with Volatility in this kind of situation is to enumerate the processes. We're going to use the command ``ẁindows.pslist`` which will allow us to display all the machine's processes.

```
kali@kali ~/D/T/volatility3 (develop)> python3 vol.py -f ../keepass-chall/adupont.dmp windows.pslist
Volatility 3 Framework 2.7.0
Progress:  100.00		PDB scanning finished                        
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

[...]

5612	5188	msedge.exe	0xab1c5040	13	-	1	False	2023-05-17 09:12:46.000000 	N/A	Disabled
5632	5188	msedge.exe	0xad747680	15	-	1	False	2023-05-17 09:12:47.000000 	N/A	Disabled
5648	5188	msedge.exe	0x8c1bb600	7	-	1	False	2023-05-17 09:12:47.000000 	N/A	Disabled
6008	5248	thunderbird.ex	0xad6d4840	15	-	1	False	2023-05-17 09:12:50.000000 	N/A	Disabled
1996	720	FileCoAuth.exe	0xab167840	4	-	1	False	2023-05-17 09:13:06.000000 	N/A	Disabled
3332	5188	msedge.exe	0x9530c040	15	-	1	False	2023-05-17 09:13:19.000000 	N/A	Disabled
3592	5188	msedge.exe	0x8d521040	14	-	1	False	2023-05-17 09:13:22.000000 	N/A	Disabled

```
Once the command has been executed, volatility returns a set of the machine's active processes. Most of these are relatively common and not 'suspicious', but in the middle of them is the Thunderbird process. Under normal circumstances, this process wouldn't be suspicious, but in the context of a CTF this is different, and would seem to be a possible lead for the future. 

## 3. Thunderbird investigation

After a little research into Thunderbird's investigation, two main things come to mind: 
-  Finding SQLite databases of Thunderbird**
- Finding data in mails

### Finding SQLite databases 

We'll look for this with the ``` windows.filescan```and ```grep``` :

``` 
kali@kali ~/D/T/volatility3 (develop)> python3 vol.py -f ../keepass-chall/adupont.dmp windows.filescan | grep sqlite
0x95376358 100.0\Windows\System32\winsqlite3.dll	128
0xa06472c0	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\cookies.sqlite	128
0xa6f02c38	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\storage\permanent\chrome\idb\3870112724rsegmnoittet-es.sqlite	128
0xa6f02ec0	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\calendar-data\local.sqlite-wal	128
0xa6f03070	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\calendar-data\local.sqlite-shm	128
0xa6f032f8	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\storage.sqlite	128
0xa6f03580	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\calendar-data\local.sqlite	128
0xa6f03730	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\storage\ls-archive.sqlite	128
0xa6f04810	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\places.sqlite-wal	128
0xa6f048e8	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\places.sqlite-shm	128
0xa6f04a98	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\favicons.sqlite	128
0xa6f053e0	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\places.sqlite	128
0xa6f058f0	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\favicons.sqlite-wal	128
0xa6f059c8	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\favicons.sqlite-shm	128
0xa6f05aa0	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\places.sqlite	128
0xa6f05b78	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\places.sqlite-wal	128
0xa6f05d28	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\favicons.sqlite	128
0xa6f05ed8	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\favicons.sqlite-wal	128
0xa6f06820	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\history.sqlite	128
0xa6f068f8	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\history.sqlite-wal	128
0xa6f069d0	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\abook.sqlite	128
0xa6f06b80	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\history.sqlite-shm	128
0xa6f06c58	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\openpgp.sqlite	128
0xa6f06d30	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\abook.sqlite-wal	128
0xa6f06e08	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\abook.sqlite-shm	128
0xa6fcb298	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\permissions.sqlite	128
0xa6fd4718	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\cookies.sqlite-shm	128
0xa6fd4a78	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\cookies.sqlite	128
0xa6fd4dd8	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\cookies.sqlite-wal	128
```
Unfortunately, after searching through several of these SQLite databases, nothing interesting came up. 

### Finding data in mails

To find data in Thunderbird mails, we will try to enumerate the files on the machine containing the word "Thunderbird": 

```
kali@kali ~/D/T/volatility3 (develop)> python3 vol.py -f ../keepass-chall/adupont.dmp windows.filescan | grep Thunderbird

```

We then find ourselves with a large number of files, and if we look at them one by one, many of them may seem interesting:

```
0xa6f04738 100.0\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\Mail\pop.gmail.com\Sent	128
0xa6f04d20	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\Mail\pop.gmail.com\Sent.msf	128
0xa6f07c60	\Users\adupont\AppData\Roaming\Thunderbird\Profiles\sv9bcuck.default-release\Mail\pop.gmail.com\Sent.msf	128
```
We extract the first file:

```
kali@kali ~/D/T/volatility3 (develop)> python3 vol.py -f ../keepass-chall/adupont.dmp -o . windows.dumpfiles.DumpFiles --virtaddr 0xa6f04738
```
Great! We find a plain-text e-mail:

```
kali@kali ~/D/T/volatility3 (develop)> cat file.0xa6f04738.0xa7777f08.DataSectionObject.Sent.dat 
From - Wed, 17 May 2023 08:25:40 GMT
X-Mozilla-Status: 0003
X-Mozilla-Status2: 10800000
Content-Type: multipart/mixed; boundary="------------XJLZoYn0bXsIJ4JsrDDa7k5Y"
Message-ID: <40c10fc0-b6fb-4765-a80b-17940bece79a@gmail.com>
Date: Wed, 17 May 2023 08:25:40 GMT +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Content-Language: en-US
To: fgalthier.repadmin@gmail.com
From: Antoine Dupont <adupont.rep@gmail.com>
Subject: Recovery file for password manager

This is a multi-part message in MIME format.
--------------XJLZoYn0bXsIJ4JsrDDa7k5Y
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 7bit

Hey Fabien,

Here is the recovery file for my keepass db. For good measure I've 
ciphered it using open ssl with aes cbc 256 and 2048 iterations. I'll 
come to your desk to tell you the password, which I'll store securely in 
the db.

Cheers

Antoine

--------------XJLZoYn0bXsIJ4JsrDDa7k5Y
Content-Type: application/pdf; name="savecipher.pdf"
Content-Disposition: attachment; filename="savecipher.pdf"
Content-Transfer-Encoding: base64

U2FsdGVkX1/JDDCaToEZSYAf+sRcFFcQaVGazRcrtiUf6ekqqw+YakTx7JieultS4vSf9XTQ
BRGVX6NXgYX7VZhBpg/xJNHvvdv7hR8z1i4Tjml06TGcYP7FeHKEk5/LcS43X9rF/XA/XwjD
f1E/d/VOnZBymg93rYm0NIeTIOVzuLp8nhjLmvu2A45XxdnP8UcoqKngS1yuprV05JVzmJiJ
kNWMjS9wj8lZYG7BGQxSSa13wikVCrSUD0nmR71TRSoddTkPz9dvodvc/VZsmoAUanlwj3TA
ZCwpx3GRoxTAjlXC75JgD8WmFMHkhjtKRROBGLd0Ay2sIDLZqfe70dot5iQiN8kxaus3kRbC
CuQJhIO8xi9lwxxjMnsVF3lcZ0InJKzWPoIjO0O+i7UyvDpyKJDZuXlUvEj2nNO1k4Gj3C2W
4c45tEwtrKDY11Wx2MmWmcCI7mxulj67B1Fowubl/jTtpIyozWT2wLCORjoVgbeTrWowxSAL
pX+umrbTz+N9JxalHHnBY4RWQjHisti9jjfvIvEMlGHlIztky0AzqmxBXUhba02vin7UaODR
NbHua0n34Sg8MasUySdgLAO9FZxlueMhk6NKwvQU3H79+QAW6qXMrRwZ/2Sej6VoBdTVCpIv
HiH4wwFVx/EBNTRFiuMJ0+a90s8XMM57p+N4BSeuu5BjXP2a/J50vMcUOzlYaLTjcEtzdjsb
c4Kp7MLEoHVXhpuTwDxgAoFLxEuAfUt7OXgjIMZHVYnwLuSJd/NWPQwg4olRdCuSj2g2XdqT
WP0MpvbFJ8tCGtQ+ylbj4iaNNhZACWmfk1b9rordA6mb+V/v/Jc8NAxVPJWcnYZiL1yo2H1W
uub54+Ccq6KKn+saRQ7g/C8MKHjUx/d+snejtgZ9zA9YX/ue4bGbouO/zmiInwl3x/hNnA+y

[...]

krxQlfj40m3rKKffWfVu10EzwQpSnp9olJnPuJBHin5lLOlC0tFde387TYQqYRDTbN58QRag
8heoDRCxz16TiWMHDtAMo5vZZG/xiuSHa/5h8YtuwGzTaDce8qamfVBIGx3G/yWbjg+PCAH2
2J+TyecfnunPjAUnc9DgQmQLMUEkwjMsBwsfjGcJQtCsbXjO1IGVLzr52DCSMBYH5jAyoerI
3AuJGru5WQc0LzL3dy1uruiMkoSMFNupXI9qO09+vMBhsfQaLRWTkhvSbS41BBEKVCP//vRR
t6g=

--------------XJLZoYn0bXsIJ4JsrDDa7k5Y--

From - Wed, 17 May 2023 09:25:38 GMT
X-Mozilla-Status: 0001
X-Mozilla-Status2: 00800000
Message-ID: <5e0ed26c-8667-4b6e-9f8b-c56ba02516d6@gmail.com>
Date: Wed, 17 May 2023 08:25:40 GMT +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: Recovery file for password manager
Content-Language: en-US
From: Antoine Dupont <adupont.rep@gmail.com>
To: fgalthier.repadmin@gmail.com
References: <40c10fc0-b6fb-4765-a80b-17940bece79a@gmail.com>
In-Reply-To: <40c10fc0-b6fb-4765-a80b-17940bece79a@gmail.com>
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 7bit

I forgot to mention - my softwares are up to date as of today. Unless 
there's like a big cve or something we should be safe aha

On 17/05/2023 08:25, Antoine Dupont wrote:
> Hey Fabien,
>
> Here is the recovery file for my keepass db. For good measure I've 
> ciphered it using open ssl with aes cbc 256 and 2048 iterations. I'll 
> come to your desk to tell you the password, which I'll store securely 
> in the db.
>
> Cheers
>
> Antoine

```

So we have an e-mail that talks about the keepass file we were given at the beginning. In addition, there's a pdf file in base64 that's obviously encrypted with open ssl with aes cbc 256 and 2048 iterations and a password. Finally, one of the people mentioned a CVE in an e-mail (a new lead?).




## 4. CVE-2023-32784

As seen above, we're told about a CVE. After a few Google searches (keepass + memory dump) we come across this CVE : [CVE-2023-32784](https://nvd.nist.gov/vuln/detail/cve-2023-32784). 

We make a memory dump of the keepass process:

```
kali@kali ~/D/T/keepass-chall> python3 vol.py -f ../keepass-chall/adupont.dmp windows.memmap.Memmap ‑dump ‑pid 6008
```

[POC - CVE-2023-32784](https://github.com/dawnl3ss/CVE-2023-32784)

```
	
kali@kali ~/D/T/keepass-chall> sudo python3 keepass-dump-masterkey/poc.py -d pid.2896.dmp 
2024-04-06 12:50:52,120 [.] [main] Opened pid.2896.dmp 
Possible password: ●ysuper_s4F3pwd78224DB 
Possible password: ●ysuper_s4F3pwd78224DC 
Possible password: ●%super_s4F3pwd78224DB 
Possible password: ●%super_s4F3pwd78224DC 
Possible password: ●'super_s4F3pwd78224DB 
Possible password: ●'super_s4F3pwd78224DC
```

This password is not complete thanks to the POC, but it is possible to obtain it in full by greping the strings in the memory dump:

```
kali@kali ~/D/T/keepass-chall> strings adupont.dmp > adupont 
kali@kali ~/D/T/keepass-chall> strings adupont | grep mysuper
<ConsoleApplication2.pdbdownload/football.txtmysuperstackoverflow156.245.19.127
mysuperdupersecretkeyTrojan:Win64/Zenpack.EM!MTB
mysuper*s4F3pwd78224DB
kali@kali ~/D/T/keepass-chall> 

```

## 5. Deciphering

Now we have the password (which we assume to be the password for the pdf), as well as the pdf that was in the e-mail. 

We will then do what the person tells us to do in the email in order to decipher the pdf:

```
kali@kali ~/D/T/volatility3 (develop) [1]> openssl enc -d -aes-256-cbc -md sha256 -in file.pdf -out decrypted.pdf -pass "pass:mysuper*s4F3pwd78224DB" -pbkdf2 -iter 2048
```
It works! 

This generates the deciphered pdf. Once opened, we get the keepass password: `` satellitespwd4ISSc&c``

We open the keepass and finally obtain the flag : 

Flag : ```THCON{p4ssw0rDS_4re_mY_favourite_things!}```


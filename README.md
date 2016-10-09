# virustotalIntellgence

This scanning tool supports detecting virus/malware by using VirusTotal.

Feaures including
- Check whether a computer has infected by malware
- Show malware reports which contain:
  + Malware detection labels from various anti-virus vendors 
  + Malware indicators such as IP addresses, Domain names which can be integrated into IDS. 
- Calculate malware score base on the detection rates of antivirus vendors. To do that, we
 + define a list of trusted AV which are ten famous antivirus productes such as: Kaspersky, Symantect,...
 + the score ranges from 1 to 10 where the score of 1 indicates that the malware is dectected by only one AV and the score of 10 shows that the malicious of malware is confirmed by ten AV.
 
Requirements:
- You need Python and the requests module to run this tool. (other basic modules are available when you install Python by default) 

How to use this tool:
At this time, we need to supply two arguments as the inputs:
+ (-f) : Path to file
+ (-a) : Name of an antivirus, for example: Microsoft

Run the file: main.py

C:\Users\Lab\Documents\GitHub\virustotalIntellgence>python main.py -f samples/zeus.bin -a Microsoft

Result:
Report
Number of AVs: 56
Number of Positive AVs: 52
AV Microsoft: Detected
Virus name: PWS:Win32/Zbot!ZA
Scan date: 2016-10-09 04:09:44
Malware score: 9

On-going Features:
+ Supporting file scan
+ Getting more malware information 

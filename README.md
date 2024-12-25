# Know-Normal-S1
This is a custom machine learning algorith that helps SOC analysts and security folks understand what is normal for their environment, and show anomalies to focus analysis on. That's LinkedIn translation for it's a set of scrips aimed at "Knowing Normal" by comparing artifacts from an alert (specifically the process generating the alert) then compares it against the enterprise. Based on SANS 508 / Eric Zimmerman's technique (Digital Forensics).
So far the artifacts it looks at are:
-Parent Process
-Process Image Path
-Process Signature
-DNS requests for that process
-IP Connections for that process
-Network Ports for that process
-Indicators

Note that the last half of indicators could be indicative of malware living in the memory space of a legitamite process, so it is important to perform memory analysis if any of these anomalies occur.

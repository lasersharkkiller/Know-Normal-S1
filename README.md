# Know-Normal-S1
This is a custom machine learning algorith that helps SOC analysts and security folks understand what is normal for their environment, and show anomalies to focus analysis on. That's LinkedIn translation for it's a set of scrips aimed at "Knowing Normal" by comparing artifacts from an alert (specifically the process generating the alert) then compares it against the enterprise. Based on SANS 508 / Eric Zimmerman's technique (Digital Forensics). </br>
So far the artifacts it looks at are:</br>
-Parent Process</br>
-Process Image Path</br>
-Process Signature</br>
-DNS requests for that process</br>
-IP Connections for that process</br>
-Network Ports for that process</br>
-Indicators</br></br>

Note that the last half of indicators could be indicative of malware living in the memory space of a legitamite process, so it is important to perform memory analysis if any of these anomalies occur.

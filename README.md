# Know-Normal-S1
The first module is a custom machine learning algorith that helps SOC analysts and security folks understand what is normal for their environment, and show anomalies to focus analysis on. That's LinkedIn translation for it's a set of scrips aimed at "Knowing Normal" by comparing artifacts from an alert (specifically the process generating the alert) then compares it against the enterprise. Based on SANS 508 / Eric Zimmerman's technique (Digital Forensics). </br>
So far the artifacts it looks at are:</br>
-Parent Process</br>
-Process Image Path</br>
-Process Signature</br>
-DNS requests for that process</br>
-IP Connections for that process</br>
-Network Ports for that process</br>
-Indicators</br></br>

Note that the last half of indicators could be indicative of malware living in the memory space of a legitamite process, so it is important to perform memory analysis if any of these anomalies occur.

The second module aims to baseline processes in your entire enterprise environment, and analyze those processes in this case with Intezer integration (VT does not work well with private samples). Intezer takes knowing normal normal a step further and analyzes various samples within the binaries like strings and the assembly breakdown to understand the components within those binaries.

The third module pulls the strings from the processes that were baselined from the second module. This is in beta, but will allow for regexing IOCs (Intezer misses some regex'ing I've noticed), but also allows for yara hunting of multiple strings across your entire environment. You might think why not use EDR, but for example you might want to hunt based on API calls. Of course this is only a static hunt for now and would not account for dynamic libraries loaded but it's a start. This hunting technique will be flushed out further. 

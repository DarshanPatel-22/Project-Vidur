# **Setup & Installation**

This tool is designed for Kali Linux or other Debian-based Linux
distributions.

Step 1: Clone the Repository

Open your terminal and clone this project:

```
git clone
\[https://github.com/DarshanPatel-22/Project-Vidur.git\](https://github.com/DarshanPatel-22/Project-Vidur.git)

cd Project-Vidur
```

Step 2: Install Core Dependencies (Zeek & Tshark)

You must install the underlying tools that the script uses.

```
sudo apt update
sudo apt install tshark zeek
```

(Note: If zeek is not available, you may need to add its official
repository. Follow the instructions at zeek.org)

Step 3: Install Python Libraries

Install the required Python libraries.

```
pip install pandas
pip install requests
```

How to Use

Run the single Vidur.py script. It will automatically detect the mode
you want.

1\. Automated Analysis (Live Capture)

To capture live traffic from your network, run the script with no
arguments:

```
python3 Vidur.py
```

On your very first run: The script will run its one-time setup:

It will automatically find your zeek executable path.

It will ask you for your VirusTotal API key (this is optional but highly
recommended).

It will save these settings to a config.ini file so you are never asked
again.

2\. Manual Analysis (From a File)

To test the tool on a known malware sample, pass the .pcap file as an
argument:

```
python3 Vidur.py /path/to/your/malware-capture.pcap
```

Sample Report Output

The tool generates a correlated report, grouping all threats by the
infected host.

==================== ANALYSIS REPORT ==================== \# Malware
Analysis Report for 2022-06-28-IcedID.pcap (2025-10-14 00:50:10)

\## Incident Reports by Host 🚩

\### Host Under Investigation: \`10.6.21.10\` This host is considered
suspicious due to the following correlated activities:

\- \*\*Potential C2 Beaconing Detected\*\*: - Connected to
\`194.37.97.139 (solvesalesoft.com)\` \*\*168\*\* times with a regular
interval (\*\*4.40s\*\* std dev). - \*\*VT Score: 7 vendors flagged as
malicious.\*\*

\- \*\*Malicious TLS Fingerprint(s) Detected\*\*: - Malicious
Fingerprint (JA3): \`e7643725fcff971e3051fe0e47fc2c71\` to Destination:
194.37.97.139

\- \*\*Malicious File Transfer(s) Detected\*\*: - File: \`lsass\` \|
MD5: \`a6f0c1c6c68be19e0a1d7dc7aa836f9a\` \| VT Score: 29 malicious
detections.

\- \*\*Suspicious DNS Queries (High Entropy)\*\*: - \`plomiberka.com\`
(Entropy: 3.52)

\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--

\## Safe / Suppressed Findings ✅

\### Benign Beaconing Activity (Suppressed) The following connections
looked like beaconing but were suppressed because the destination IP has
a VirusTotal score of 0: - \*\*Host\*\*: 10.6.21.10 -\>
\*\*Destination\*\*: 51.116.253.168 \| \*\*Connections\*\*: 18

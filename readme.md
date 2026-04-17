Network Traffic Anomaly Detector
A Python program that watches live network traffic and flags anything suspicious.
What It Does
The program listens to packets coming through your network. It learns what normal traffic looks like from the first 100 packets. After that it scores every new packet. If a packet looks unusual it fires an alert in the terminal and on a web page at http://localhost:5000.
It catches two things:

Port scans: one IP hitting many different ports fast
DDoS floods: one IP sending a huge number of packets to the same port

What You Need

Windows with WSL (Ubuntu)
Python 3.12
Root access (sudo)

Setup
Run these in your WSL terminal:
bashsudo apt update
sudo apt install python3-pip libpcap-dev nmap -y
bashsudo /usr/bin/python3 -m pip install scapy scikit-learn numpy flask --target=/usr/lib/python3/dist-packages --break-system-packages
How to Run
bashsudo /usr/bin/python3 detector.py
Open http://localhost:5000 in your browser to see the dashboard.
How to Test It
Open a second WSL terminal and run:
bashsudo nmap -sS -p 1-1000 YOUR_WSL_IP
Get your WSL IP by running hostname -I. Alerts will show up on the dashboard within seconds.
Files
anomaly-detector/
├── detector.py
└── README.md
Built With

Scapy: captures packets using raw sockets
Isolation Forest: machine learning model that detects unusual traffic
Flask: serves the alert dashboard
Python 3.12

Course
CPAN226: Network Programming
Humber College, Winter/Summer 2026
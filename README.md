# lanpd
Local area network  Arp poison detector 

# ARP Spoof Detector

You've created an ARP Spoof Detector using the libpcap tool. This tool leverages libpcap, a library for packet capture, to monitor network traffic. ARP spoofing, also known as ARP poisoning, is a technique used by attackers to intercept network traffic by sending falsified ARP (Address Resolution Protocol) messages.

Your detector likely works by continuously capturing ARP packets on the network interface using libpcap. It then analyzes these packets to detect any inconsistencies or anomalies that might indicate ARP spoofing attacks. Common indicators of ARP spoofing include multiple devices claiming the same IP address or irregular ARP reply patterns.

By implementing this detector, you've built a valuable tool for network security that helps to protect against ARP spoofing attacks, enhancing the overall security posture of networks where it is deployed.




## how to run the program

#### install libssl 
```http
  sudo apt install libssl-dev
```
#### install libpcap library

```http
  sudo apt install libpcap-dev
```
#### git clone
```http
  git clone https://github.com/sridharanitharan/lanpd.git
```


#### compile the program

```http
  gcc lanpd.c -o lanpd -lpcap -lssl -lcrypto
```
#### run the program

```http
  ./lanpd -i eth0 
```



## Screenshots

![App Screenshot](/console.JPG )


## Authors

- [@7h3_h4k3r](https://www.instagram.com/7h3_h4k3r/)


## 🚀 About Me
I'm a black hat hacker sridharanitharan...


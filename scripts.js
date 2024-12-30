// Flashcards array containing objects with acronyms and definitions
const flashcards = [
	{
		acronym: 'AAA - Authentication, Authorization, and Accounting',
		definition:
			'AAA is a security framework ensuring users are authenticated, authorized for specific actions, and their activities logged.\n\nPurpose: It ensures secure access to systems and resources by verifying identity and logging usage.\nDeployment: Implemented using RADIUS or TACACS+ servers, especially in network environments.\nContext: Found in enterprise environments for access control to network resources and auditing.',
	},
	{
		acronym: 'ACL - Access Control List',
		definition:
			'ACL is a set of rules used to filter traffic and restrict access to networks.\n\nPurpose: To define permissions for who or what can access network resources.\nDeployment: Configured on firewalls, routers, or operating systems.\nContext: Used in securing networks by filtering traffic at various entry points.',
	},
	{
		acronym: 'AES - Advanced Encryption Standard',
		definition:
			'AES is a symmetric encryption algorithm widely used for securing sensitive data.\n\nPurpose: Provides high security with fast encryption for protecting data.\nDeployment: Implemented in software and hardware across applications like VPNs and file encryption.\nContext: Common in data encryption standards, replacing older algorithms like DES.',
	},
	{
		acronym: 'AES-256 - Advanced Encryption Standard 256-bit',
		definition:
			'AES-256 is a version of AES with a 256-bit key length, offering robust encryption.\n\nPurpose: Provides stronger security to resist brute-force attacks.\nDeployment: Used in secure communications like HTTPS, file encryption, and secure file sharing.\nContext: Standard for encrypting classified information.',
	},
	{
		acronym: 'AH - Authentication Header',
		definition:
			'AH is a protocol in IPsec for ensuring data integrity and authenticity of packets.\n\nPurpose: Adds a layer of security by verifying data integrity and source authentication.\nDeployment: Configured in IPsec settings in network devices and systems.\nContext: Used in secure network communication.',
	},
	{
		acronym: 'AI - Artificial Intelligence',
		definition:
			'AI involves machine-driven intelligence processes, such as learning and problem-solving.\n\nPurpose: Enhances cybersecurity through automated threat detection and response.\nDeployment: Found in advanced threat detection platforms and analytics tools.\nContext: Used for behavior analysis, anomaly detection, and automating responses to threats.',
	},
	{
		acronym: 'AIS - Automated Indicator Sharing',
		definition:
			'AIS is a system for sharing cybersecurity threat indicators between organizations in real-time.\n\nPurpose: Enables faster response to emerging threats by sharing actionable intelligence.\nDeployment: Managed through platforms supported by agencies like CISA.\nContext: Used in government and private sector collaborations.',
	},
	{
		acronym: 'ALE - Annualized Loss Expectancy',
		definition:
			'ALE quantifies the expected monetary loss for a specific risk over a year.\n\nPurpose: Helps organizations assess the financial impact of risks.\nDeployment: Used in risk management calculations alongside SLE and ARO.\nContext: Found in frameworks like ISO 27001 for risk analysis.',
	},
	{
		acronym: 'AP - Access Point',
		definition:
			'An AP connects wireless devices to a wired network, extending network coverage.\n\nPurpose: Provides wireless connectivity within networks.\nDeployment: Installed as part of Wi-Fi infrastructure, managed locally or through controllers.\nContext: Found in homes, businesses, and public Wi-Fi setups.',
	},
	{
		acronym: 'API - Application Programming Interface',
		definition:
			'API defines protocols for building and interacting with software applications.\n\nPurpose: Enables seamless integration and communication between different software systems.\nDeployment: Used in web services, cloud platforms, and software tools.\nContext: Found in modern application development for resource sharing.',
	},
	{
		acronym: 'APT - Advanced Persistent Threat',
		definition:
			'APT represents prolonged, targeted attacks by sophisticated adversaries.\n\nPurpose: Used by attackers to gain and maintain unauthorized access for data theft.\nDeployment: Detected and mitigated through SIEM, threat intelligence, and endpoint protection.\nContext: Common in nation-state and corporate espionage scenarios.',
	},
	{
		acronym: 'ARO - Annualized Rate of Occurrence',
		definition:
			'ARO estimates how often a specific risk is expected to occur annually.\n\nPurpose: Helps quantify risk frequency for ALE calculations.\nDeployment: Included in risk assessment processes using historical data.\nContext: Found in frameworks like NIST and ISO 31000.',
	},
	{
		acronym: 'ARP - Address Resolution Protocol',
		definition:
			'ARP resolves IP addresses to MAC addresses on local networks.\n\nPurpose: Ensures proper delivery of packets within LANs.\nDeployment: Operates in Layer 2 of the OSI model, configured in networking devices.\nContext: Found in all IP-based networks.',
	},
	{
		acronym: 'ASLR - Address Space Layout Randomization',
		definition:
			'ASLR randomizes memory address space locations to prevent exploitation.\n\nPurpose: Protects against memory-based attacks like buffer overflows.\nDeployment: Enabled in operating systems and modern software.\nContext: Found in modern OS security mechanisms.',
	},
	{
		acronym: 'ATT&CK - Adversarial Tactics, Techniques, and Common Knowledge',
		definition:
			'ATT&CK is a framework for understanding adversary tactics and techniques.\n\nPurpose: Provides a standardized knowledge base for analyzing cyberattacks.\nDeployment: Integrated into threat detection tools and cybersecurity operations.\nContext: Widely used by security professionals and organizations.',
	},
	{
		acronym: 'AUP - Acceptable Use Policy',
		definition:
			'AUP outlines rules for acceptable use of organizational resources.\n\nPurpose: Ensures proper use and security of IT systems.\nDeployment: Distributed as part of onboarding or compliance training.\nContext: Found in all organizations with IT resources.',
	},
	{
		acronym: 'AV - Antivirus',
		definition:
			'Antivirus software detects, prevents, and removes malware from systems.\n\nPurpose: Protects devices from malware infections and attacks.\nDeployment: Installed on endpoints, managed individually or centrally.\nContext: Common in all computing environments.',
	},
	{
		acronym: 'BASH - Bourne Again Shell',
		definition:
			'BASH is a Unix-based command-line shell and scripting language.\n\nPurpose: Facilitates task automation and system management.\nDeployment: Found in Linux/Unix systems and macOS terminals.\nContext: Used by system administrators and developers.',
	},
	{
		acronym: 'BCP - Business Continuity Planning',
		definition:
			'BCP involves strategies for maintaining operations during disruptions.\n\nPurpose: Ensures business resilience and minimizes downtime.\nDeployment: Documented plans tested periodically through simulations.\nContext: Found in enterprise risk management frameworks.',
	},
	{
		acronym: 'BGP - Border Gateway Protocol',
		definition:
			'BGP routes traffic between networks on the internet.\n\nPurpose: Ensures efficient, reliable routing of packets across networks.\nDeployment: Configured in routers and ISPs.\nContext: Found in global internet infrastructure.',
	},
	{
		acronym: 'BIA - Business Impact Analysis',
		definition:
			'BIA identifies critical operations and assesses the impact of disruptions.\n\nPurpose: Guides recovery priorities and strategies.\nDeployment: Conducted as part of risk assessments and DRP planning.\nContext: Used in business continuity frameworks.',
	},
	{
		acronym: 'BIOS - Basic Input/Output System',
		definition:
			'BIOS is firmware that initializes hardware during the booting process.\n\nPurpose: Provides essential instructions to start the operating system.\nDeployment: Embedded in the motherboard and configurable via setup utilities.\nContext: Common in traditional computing systems, now often replaced by UEFI.',
	},
	{
		acronym: 'BPA - Business Partners Agreement',
		definition:
			'BPA is a legal document defining responsibilities between business partners.\n\nPurpose: Clarifies roles, obligations, and risk-sharing between parties.\nDeployment: Signed during partnerships or collaborations.\nContext: Found in long-term business arrangements.',
	},
	{
		acronym: 'BPDU - Bridge Protocol Data Unit',
		definition:
			'BPDU is a message exchanged by network switches to maintain spanning tree topology.\n\nPurpose: Prevents loops in Layer 2 networks by ensuring optimal path selection.\nDeployment: Configured in switches running Spanning Tree Protocol (STP).\nContext: Found in managed network environments.',
	},
	{
		acronym: 'BYOD - Bring Your Own Device',
		definition:
			'BYOD is a policy allowing employees to use personal devices for work.\n\nPurpose: Enhances flexibility and productivity by leveraging employee-owned devices.\nDeployment: Managed through mobile device management (MDM) solutions.\nContext: Common in modern workplace settings.',
	},
	{
		acronym: 'CA - Certificate Authority',
		definition:
			'An entity that issues digital certificates, which are used to verify the authenticity of public keys in secure communications.',
	},
	{
		acronym:
			'CAPTCHA - Completely Automated Public Turing Test to Tell Computers and Humans Apart',
		definition:
			'A challenge-response test used to determine if a user is human, helping to prevent automated attacks such as bots.',
	},
	{
		acronym: 'CAR - Corrective Action Report',
		definition:
			'A document that outlines steps to fix issues or deficiencies identified during an incident or audit.',
	},
	{
		acronym: 'CASB - Cloud Access Security Broker',
		definition:
			'A security tool that provides visibility and control over data and applications used in the cloud.',
	},
	{
		acronym: 'CBC - Cipher Block Chaining',
		definition:
			'An encryption mode where each plaintext block is XORed with the previous ciphertext block before being encrypted.',
	},
	{
		acronym: 'CCMP - Counter Mode/CBC-MAC Protocol',
		definition:
			'An encryption protocol used in WPA2 to provide data confidentiality and integrity for wireless networks.',
	},
	{
		acronym: 'CCTV - Closed-Circuit Television',
		definition:
			'A video surveillance system used for monitoring and security purposes.',
	},
	{
		acronym: 'CERT - Computer Emergency Response Team',
		definition:
			'A group responsible for responding to cybersecurity incidents, often providing coordination and guidance during an attack.',
	},
	{
		acronym: 'CFB - Cipher Feedback',
		definition:
			'An encryption mode that encrypts smaller units of plaintext, such as individual bits or bytes, making it suitable for streaming data.',
	},
	{
		acronym: 'CHAP - Challenge Handshake Authentication Protocol',
		definition:
			'An authentication protocol that uses a three-way handshake to verify the identity of a user or device.',
	},
	{
		acronym: 'CIA - Confidentiality, Integrity, Availability',
		definition:
			'The three core principles of cybersecurity, ensuring data is protected, accurate, and accessible to authorized users.',
	},
	{
		acronym: 'CIO - Chief Information Officer',
		definition:
			'An executive responsible for managing an organization’s IT strategy, infrastructure, and security.',
	},
	{
		acronym: 'CIRT - Computer Incident Response Team',
		definition:
			'A team that handles cybersecurity incidents, such as breaches or malware outbreaks, to mitigate damage and restore operations.',
	},
	{
		acronym: 'CMS - Content Management System',
		definition:
			'Software used for creating, managing, and publishing digital content, often for websites or applications.',
	},
	{
		acronym: 'COOP - Continuity of Operations Planning',
		definition:
			'A strategy to ensure essential functions and operations continue during and after a disaster.',
	},
	{
		acronym: 'COPE - Corporate Owned, Personally Enabled',
		definition:
			'A mobile device deployment model where the organization owns the device but allows personal use.',
	},
	{
		acronym: 'CRC - Cyclical Redundancy Check',
		definition:
			'An error-detecting code used to check the integrity of data during transmission or storage.',
	},
	{
		acronym: 'CRL - Certificate Revocation List',
		definition:
			'A list of digital certificates that have been revoked by a Certificate Authority and are no longer valid.',
	},
	{
		acronym: 'CSO - Chief Security Officer',
		definition:
			"An executive responsible for an organization's physical and cybersecurity strategies and operations.",
	},
	{
		acronym: 'CSP - Cloud Service Provider',
		definition:
			'A company that offers cloud computing services such as storage, software, or infrastructure over the internet.',
	},
	{
		acronym: 'CSR - Certificate Signing Request',
		definition:
			'A message sent to a Certificate Authority to request the issuance of a digital certificate.',
	},
	{
		acronym: 'CSRF - Cross-site Request Forgery',
		definition:
			'A web security vulnerability that tricks users into performing unwanted actions on a trusted website while authenticated.',
	},
	{
		acronym: 'CSU - Channel Service Unit',
		definition:
			'A device used to connect a digital circuit to a data terminal, ensuring compatibility and proper signal transmission.',
	},
	{
		acronym: 'CTM - Counter Mode',
		definition:
			'An encryption mode that turns a block cipher into a stream cipher, encrypting plaintext by XORing it with a counter value.',
	},
	{
		acronym: 'CTO - Chief Technology Officer',
		definition:
			'An executive responsible for overseeing the development and dissemination of technology in an organization.',
	},
	{
		acronym: 'CVE - Common Vulnerabilities and Exposures',
		definition:
			'A public database of known cybersecurity vulnerabilities used to identify and mitigate risks in software or systems.',
	},
	{
		acronym: 'CVSS - Common Vulnerability Scoring System',
		definition:
			'A standardized method for assessing the severity of cybersecurity vulnerabilities to prioritize remediation.',
	},
	{
		acronym: 'CYOD - Choose Your Own Device',
		definition:
			'A mobile device policy allowing employees to select their device from a list of pre-approved options.',
	},
	{
		acronym: 'DAC - Discretionary Access Control',
		definition:
			'A security model where access is determined by the resource owner, who decides which users can access specific resources.',
	},
	{
		acronym: 'DBA - Database Administrator',
		definition:
			'A professional responsible for the maintenance, configuration, and security of database systems.',
	},
	{
		acronym: 'DDoS - Distributed Denial of Service',
		definition:
			'An attack that overwhelms a network or server with excessive traffic from multiple sources, disrupting normal operations.',
	},
	{
		acronym: 'DEP - Data Execution Prevention',
		definition:
			'A security feature that prevents the execution of code from non-executable memory regions, protecting against certain exploits.',
	},
	{
		acronym: 'DES - Digital Encryption Standard',
		definition:
			'A symmetric-key encryption algorithm that was widely used for securing data but is now considered obsolete due to its small key size.',
	},
	{
		acronym: 'DHCP - Dynamic Host Configuration Protocol',
		definition:
			'A protocol that automatically assigns IP addresses and other network configurations to devices on a network.',
	},
	{
		acronym: 'DHE - Diffie-Hellman Ephemeral',
		definition:
			'A key exchange protocol that provides forward secrecy by using temporary, ephemeral keys for each session.',
	},
	{
		acronym: 'DKIM - DomainKeys Identified Mail',
		definition:
			'An email authentication method that uses cryptographic signatures to verify the sender and ensure message integrity.',
	},
	{
		acronym: 'DLL - Dynamic Link Library',
		definition:
			'A file that contains code and data used by multiple programs in Windows to perform common functions.',
	},
	{
		acronym: 'DLP - Data Loss Prevention',
		definition:
			'Technology that prevents sensitive data from leaving an organization through unauthorized channels.',
	},
	{
		acronym: 'DMARC - Domain Message Authentication Reporting and Conformance',
		definition:
			'An email authentication protocol that helps prevent phishing and spoofing by validating email senders.',
	},
	{
		acronym: 'DNAT - Destination Network Address Translation',
		definition:
			'A type of NAT that modifies the destination address of incoming packets to redirect traffic to an internal network.',
	},
	{
		acronym: 'DNS - Domain Name System',
		definition:
			'A system that translates human-readable domain names into IP addresses to facilitate network communication.',
	},
	{
		acronym: 'DoS - Denial of Service',
		definition:
			'An attack that disrupts the availability of a system or service by overwhelming it with traffic or requests.',
	},
	{
		acronym: 'DPO - Data Privacy Officer',
		definition:
			'A role responsible for overseeing data protection strategies and ensuring compliance with privacy regulations.',
	},
	{
		acronym: 'DRP - Disaster Recovery Plan',
		definition:
			'A set of procedures and tools designed to recover IT systems and data after a disaster or disruption.',
	},
	{
		acronym: 'DSA - Digital Signature Algorithm',
		definition:
			'A standard for digital signatures that ensures the authenticity and integrity of electronic documents.',
	},
	{
		acronym: 'DSL - Digital Subscriber Line',
		definition:
			'A technology for high-speed internet access over traditional telephone lines.',
	},
	{
		acronym: 'EAP - Extensible Authentication Protocol',
		definition:
			'A framework used in wireless networks to support various authentication methods, such as EAP-TLS or EAP-PEAP.',
	},
	{
		acronym: 'ECB - Electronic Code Book',
		definition:
			'An encryption mode that encrypts each block of plaintext independently, making it less secure due to pattern repetition.',
	},
	{
		acronym: 'ECC - Elliptic Curve Cryptography',
		definition:
			'A cryptographic approach using elliptic curves to provide strong encryption with smaller key sizes.',
	},
	{
		acronym: 'ECDHE - Elliptic Curve Diffie-Hellman Ephemeral',
		definition:
			'A variant of the Diffie-Hellman protocol using elliptic curves for secure key exchange with forward secrecy.',
	},
	{
		acronym: 'ECDSA - Elliptic Curve Digital Signature Algorithm',
		definition:
			'A cryptographic algorithm used to generate digital signatures with elliptic curve technology.',
	},
	{
		acronym: 'EDR - Endpoint Detection and Response',
		definition:
			'A security solution that monitors endpoints for malicious activities and provides tools for threat detection and response.',
	},
	{
		acronym: 'EFS - Encrypted File System',
		definition:
			'A feature of NTFS that allows files and directories to be encrypted to protect sensitive data.',
	},
	{
		acronym: 'ERP - Enterprise Resource Planning',
		definition:
			'Software that integrates and manages core business processes, such as finance, HR, and supply chain operations.',
	},
	{
		acronym: 'ESN - Electronic Serial Number',
		definition:
			'A unique identifier assigned to mobile devices for identification on cellular networks.',
	},
	{
		acronym: 'ESP - Encapsulated Security Payload',
		definition:
			'A protocol used in IPsec to provide confidentiality, integrity, and authentication for IP packets.',
	},
	{
		acronym: 'FACL - File System Access Control List',
		definition:
			'A list of permissions attached to a file or directory, specifying which users or groups can access the resource and what actions they can perform.',
	},
	{
		acronym: 'FDE - Full Disk Encryption',
		definition:
			'A technology that encrypts all data on a storage device to protect it from unauthorized access.',
	},
	{
		acronym: 'FIM - File Integrity Management',
		definition:
			'A security process that ensures files are not tampered with or altered without authorization.',
	},
	{
		acronym: 'FPGA - Field Programmable Gate Array',
		definition:
			'An integrated circuit that can be programmed and reconfigured for specific tasks after manufacturing.',
	},
	{
		acronym: 'FRR - False Rejection Rate',
		definition:
			'A biometric security metric that measures how often legitimate users are incorrectly denied access.',
	},
	{
		acronym: 'FTP - File Transfer Protocol',
		definition:
			'A protocol used to transfer files between a client and a server over a network, lacking encryption by default.',
	},
	{
		acronym: 'FTPS - Secured File Transfer Protocol',
		definition:
			'An extension of FTP that adds support for SSL/TLS encryption to secure file transfers.',
	},
	{
		acronym: 'GCM - Galois Counter Mode',
		definition:
			'A cryptographic mode that provides both encryption and authentication for secure data transmission.',
	},
	{
		acronym: 'GDPR - General Data Protection Regulation',
		definition:
			'A comprehensive data protection law in the European Union that governs the collection, processing, and storage of personal data.',
	},
	{
		acronym: 'GPG - Gnu Privacy Guard',
		definition:
			'An encryption software that provides tools for secure communication and data encryption, based on the OpenPGP standard.',
	},
	{
		acronym: 'GPO - Group Policy Object',
		definition:
			'A feature in Windows that allows administrators to manage and configure user and computer settings across a network.',
	},
	{
		acronym: 'GPS - Global Positioning System',
		definition:
			'A satellite-based navigation system used for determining geographic locations.',
	},
	{
		acronym: 'GPU - Graphics Processing Unit',
		definition:
			'A specialized processor designed for rendering images, animations, and video.',
	},
	{
		acronym: 'GRE - Generic Routing Encapsulation',
		definition:
			'A tunneling protocol used to encapsulate a wide variety of network layer protocols inside virtual point-to-point links.',
	},
	{
		acronym: 'HA - High Availability',
		definition:
			'A system design approach ensuring a high level of operational performance and uptime.',
	},
	{
		acronym: 'HDD - Hard Disk Drive',
		definition:
			'A traditional data storage device that uses spinning magnetic disks to read and write data.',
	},
	{
		acronym: 'HIDS - Host-based Intrusion Detection System',
		definition:
			'A system that monitors and analyzes activities on a specific host for malicious or unauthorized behavior.',
	},
	{
		acronym: 'HIPS - Host-based Intrusion Prevention System',
		definition:
			'A system that proactively blocks detected threats on a host before they can execute.',
	},
	{
		acronym: 'HMAC - Hashed Message Authentication Code',
		definition:
			'A cryptographic technique that ensures the integrity and authenticity of a message using a secret key and a hash function.',
	},
	{
		acronym: 'HOTP - HMAC-based One-time Password',
		definition:
			'A one-time password algorithm that generates a password based on a secret key and a counter.',
	},
	{
		acronym: 'HSM - Hardware Security Module',
		definition:
			'A physical device that securely manages, processes, and stores cryptographic keys.',
	},
	{
		acronym: 'HTML - Hypertext Markup Language',
		definition:
			'The standard language used to create and structure content on the web.',
	},
	{
		acronym: 'HTTP - Hypertext Transfer Protocol',
		definition:
			'A protocol used for transmitting hypertext documents over the web, facilitating communication between servers and browsers.',
	},
	{
		acronym: 'HTTPS - Hypertext Transfer Protocol Secure',
		definition:
			'A secure version of HTTP that uses encryption protocols such as SSL/TLS to protect data in transit.',
	},
	{
		acronym: 'HVAC - Heating, Ventilation, and Air Conditioning',
		definition:
			'A system used to regulate the temperature, humidity, and air quality in a building.',
	},
	{
		acronym: 'IaaS - Infrastructure as a Service',
		definition:
			'A cloud computing model that provides virtualized computing resources over the internet.',
	},
	{
		acronym: 'IaC - Infrastructure as Code',
		definition:
			'A practice of managing and provisioning infrastructure through code rather than manual processes.',
	},
	{
		acronym: 'IAM - Identity and Access Management',
		definition:
			'A framework of policies and technologies ensuring the right individuals access the right resources at the right times.',
	},
	{
		acronym: 'ICMP - Internet Control Message Protocol',
		definition:
			'A network protocol used for error reporting and operational information, often associated with tools like ping.',
	},
	{
		acronym: 'ICS - Industrial Control Systems',
		definition:
			'A system that manages industrial processes such as manufacturing, power generation, and transportation.',
	},
	{
		acronym: 'IDEA - International Data Encryption Algorithm',
		definition:
			'A symmetric encryption algorithm used for secure data transmission.',
	},
	{
		acronym: 'IDF - Intermediate Distribution Frame',
		definition:
			'A cable rack that interconnects and manages telecommunication wiring between the Main Distribution Frame (MDF) and endpoints.',
	},
	{
		acronym: 'IdP - Identity Provider',
		definition:
			'A system that creates, maintains, and manages identity information while providing authentication services.',
	},
	{
		acronym: 'IDS - Intrusion Detection System',
		definition:
			'A system designed to monitor and analyze network or system activity for malicious behavior or policy violations.',
	},
	{
		acronym: 'IEEE - Institute of Electrical and Electronics Engineers',
		definition:
			'An organization that develops standards for electronic and electrical technologies, including networking and communications.',
	},
	{
		acronym: 'IKE - Internet Key Exchange',
		definition:
			'A protocol used in IPsec for negotiating, establishing, and managing secure communication sessions.',
	},
	{
		acronym: 'IM - Instant Messaging',
		definition:
			'A form of communication over the internet that allows real-time text exchanges between users.',
	},
	{
		acronym: 'IMAP - Internet Message Access Protocol',
		definition:
			'A protocol for retrieving email messages from a server, allowing synchronization across multiple devices.',
	},
	{
		acronym: 'IoC - Indicators of Compromise',
		definition:
			'Artifacts or evidence found on a network or system indicating a potential breach or malicious activity.',
	},
	{
		acronym: 'IoT - Internet of Things',
		definition:
			'A network of interconnected devices that communicate and exchange data, often used in smart homes and industries.',
	},
	{
		acronym: 'IP - Internet Protocol',
		definition:
			'A set of rules governing the format of data sent over the internet or a local network.',
	},
	{
		acronym: 'IPS - Intrusion Prevention System',
		definition:
			'A system that monitors network traffic for malicious activities and blocks identified threats in real-time.',
	},
	{
		acronym: 'IPSec - Internet Protocol Security',
		definition:
			'A suite of protocols designed to secure internet communication by authenticating and encrypting each IP packet.',
	},
	{
		acronym: 'IR - Incident Response',
		definition:
			'A process for detecting, investigating, and mitigating cybersecurity incidents to minimize impact.',
	},
	{
		acronym: 'IRC - Internet Relay Chat',
		definition:
			'A protocol that allows text-based communication in real-time, often used in group discussions.',
	},
	{
		acronym: 'IRP - Incident Response Plan',
		definition:
			'A documented strategy for handling cybersecurity incidents effectively to minimize damage.',
	},
	{
		acronym: 'ISO - International Standards Organization',
		definition:
			'An international organization that develops and publishes standards for technology, manufacturing, and other industries.',
	},
	{
		acronym: 'ISP - Internet Service Provider',
		definition:
			'A company that provides individuals and businesses with access to the internet.',
	},
	{
		acronym: 'ISSO - Information Systems Security Officer',
		definition:
			'A professional responsible for implementing and managing an organization’s cybersecurity policies and systems.',
	},
	{
		acronym: 'IV - Initialization Vector',
		definition:
			'A random value used in encryption to ensure that identical plaintext results in different ciphertext.',
	},
	{
		acronym: 'KDC - Key Distribution Center',
		definition:
			'A service that provides cryptographic keys for secure communication in systems like Kerberos.',
	},
	{
		acronym: 'KEK - Key Encryption Key',
		definition:
			'A key used to encrypt and protect other cryptographic keys, ensuring their secure storage and transmission.',
	},
	{
		acronym: 'L2TP - Layer 2 Tunneling Protocol',
		definition:
			'A VPN tunneling protocol often used with IPSec to provide secure remote access.',
	},
	{
		acronym: 'LAN - Local Area Network',
		definition:
			'A network that connects devices within a limited area, such as a home, school, or office building.',
	},
	{
		acronym: 'LDAP - Lightweight Directory Access Protocol',
		definition:
			'A protocol used to access and maintain distributed directory information, such as user credentials and network resource locations.',
	},
	{
		acronym: 'LEAP - Lightweight Extensible Authentication Protocol',
		definition:
			'A wireless authentication protocol developed by Cisco, now considered outdated due to security vulnerabilities.',
	},
	{
		acronym: 'MaaS - Monitoring as a Service',
		definition:
			'A cloud-based model for monitoring IT infrastructure and applications, providing real-time insights and alerts.',
	},
	{
		acronym: 'MAC - Mandatory Access Control',
		definition:
			'A security model where access permissions are determined by a central authority based on classifications.',
	},
	{
		acronym: 'MAC - Media Access Control',
		definition:
			'A unique identifier assigned to network interfaces for communication on the physical network segment.',
	},
	{
		acronym: 'MAC - Message Authentication Code',
		definition:
			'A cryptographic code that verifies the integrity and authenticity of a message.',
	},
	{
		acronym: 'MAN - Metropolitan Area Network',
		definition:
			'A network that connects devices across a city or large campus, larger than a LAN but smaller than a WAN.',
	},
	{
		acronym: 'MBR - Master Boot Record',
		definition:
			'A special type of boot sector at the beginning of storage devices that contains information about disk partitions and a boot loader.',
	},
	{
		acronym: 'MD5 - Message Digest 5',
		definition:
			'A cryptographic hash function used to verify data integrity, though considered insecure due to vulnerabilities.',
	},
	{
		acronym: 'MDF - Main Distribution Frame',
		definition:
			'A physical frame used to connect and manage telecommunication cables in a network.',
	},
	{
		acronym: 'MDM - Mobile Device Management',
		definition:
			'A software solution used to manage and secure mobile devices within an organization.',
	},
	{
		acronym: 'MFA - Multifactor Authentication',
		definition:
			'A security mechanism requiring multiple forms of verification, such as passwords, biometrics, or hardware tokens.',
	},
	{
		acronym: 'MFD - Multifunction Device',
		definition:
			'An office device that combines functions such as printing, scanning, copying, and faxing.',
	},
	{
		acronym: 'MFP - Multifunction Printer',
		definition:
			'A printer that also offers additional capabilities like scanning, copying, and faxing.',
	},
	{
		acronym: 'ML - Machine Learning',
		definition:
			'A subset of artificial intelligence focused on building systems that learn from and adapt to data.',
	},
	{
		acronym: 'MMS - Multimedia Message Service',
		definition:
			'A messaging service that enables the transmission of multimedia content such as images, audio, and video.',
	},
	{
		acronym: 'MOA - Memorandum of Agreement',
		definition:
			'A formal document outlining the terms and details of a partnership or agreement between parties.',
	},
	{
		acronym: 'MOU - Memorandum of Understanding',
		definition:
			'A non-binding agreement that outlines the intentions and roles of parties in a collaboration.',
	},
	{
		acronym: 'MPLS - Multi-protocol Label Switching',
		definition:
			'A routing technique in high-performance telecommunications networks that directs data based on short path labels.',
	},
	{
		acronym: 'MSA - Master Service Agreement',
		definition:
			'A contract that defines the terms and conditions for future agreements between two parties.',
	},
	{
		acronym: 'MSCHAP - Microsoft Challenge Handshake Authentication Protocol',
		definition:
			'An authentication protocol used for validating user credentials in Microsoft networks.',
	},
	{
		acronym: 'MSP - Managed Service Provider',
		definition:
			"A third-party company that remotely manages a customer's IT infrastructure and end-user systems.",
	},
	{
		acronym: 'MSSP - Managed Security Service Provider',
		definition:
			'A company that provides outsourced monitoring and management of security systems and devices.',
	},
	{
		acronym: 'MTBF - Mean Time Between Failures',
		definition:
			'A reliability metric that measures the average time between failures of a system or component.',
	},
	{
		acronym: 'MTTF - Mean Time to Failure',
		definition:
			'A metric that estimates the average time until a system or component fails.',
	},
	{
		acronym: 'MTTR - Mean Time to Recover',
		definition:
			'The average time it takes to restore a system to normal operation after a failure.',
	},
	{
		acronym: 'MTU - Maximum Transmission Unit',
		definition:
			'The largest size of a packet or frame that can be transmitted in a network.',
	},
	{
		acronym: 'NAC - Network Access Control',
		definition:
			'A security solution that enforces policies to manage access to network resources based on identity and compliance.',
	},
	{
		acronym: 'NAT - Network Address Translation',
		definition:
			'A method used to remap private IP addresses into a single public IP address for internet communication.',
	},
	{
		acronym: 'NDA - Non-disclosure Agreement',
		definition:
			'A legal contract that protects sensitive or proprietary information from being disclosed to unauthorized parties.',
	},
	{
		acronym: 'NFC - Near Field Communication',
		definition:
			'A short-range wireless communication technology used for tasks like contactless payments and device pairing.',
	},
	{
		acronym: 'NGFW - Next-generation Firewall',
		definition:
			'An advanced firewall that includes features such as deep packet inspection, intrusion prevention, and application control.',
	},
	{
		acronym: 'NIDS - Network-based Intrusion Detection System',
		definition:
			'A system that monitors and analyzes network traffic for malicious activities or violations of policies.',
	},
	{
		acronym: 'NIPS - Network-based Intrusion Prevention System',
		definition:
			'A system that actively blocks detected threats by analyzing and filtering network traffic in real-time.',
	},
	{
		acronym: 'NIST - National Institute of Standards & Technology',
		definition:
			'A U.S. government agency that develops cybersecurity standards, guidelines, and best practices.',
	},
	{
		acronym: 'NTFS - New Technology File System',
		definition:
			'A file system used by Windows operating systems that supports large files, file compression, and access control.',
	},
	{
		acronym: 'NTLM - New Technology LAN Manager',
		definition:
			'A suite of Microsoft security protocols used for authentication and maintaining the integrity of communication.',
	},
	{
		acronym: 'NTP - Network Time Protocol',
		definition:
			'A protocol used to synchronize the clocks of devices across a network to a standard time source.',
	},
	{
		acronym: 'OAUTH - Open Authorization',
		definition:
			'An open standard for token-based authentication that enables secure access to resources without sharing credentials.',
	},
	{
		acronym: 'OCSP - Online Certificate Status Protocol',
		definition:
			'A protocol used to determine the revocation status of digital certificates in real-time.',
	},
	{
		acronym: 'OID - Object Identifier',
		definition:
			'A globally unique identifier used to name objects in a hierarchical structure, often used in security certificates.',
	},
	{
		acronym: 'OS - Operating System',
		definition:
			'Software that manages hardware resources and provides services for computer programs.',
	},
	{
		acronym: 'OSINT - Open-source Intelligence',
		definition:
			'The collection and analysis of publicly available information to gather intelligence for cybersecurity or investigative purposes.',
	},
	{
		acronym: 'OSPF - Open Shortest Path First',
		definition:
			'A routing protocol used in IP networks to determine the most efficient path for data transmission.',
	},
	{
		acronym: 'OT - Operational Technology',
		definition:
			'Hardware and software systems used to monitor and control industrial processes and infrastructure.',
	},
	{
		acronym: 'OTA - Over the Air',
		definition:
			'A method of wirelessly delivering updates or patches to devices, commonly used in mobile and IoT devices.',
	},
	{
		acronym: 'OVAL - Open Vulnerability Assessment Language',
		definition:
			'A standard for assessing and reporting the security vulnerabilities of computer systems.',
	},
	{
		acronym: 'P12 - PKCS #12',
		definition:
			'A file format used to store and transport cryptographic keys and certificates securely.',
	},
	{
		acronym: 'P2P - Peer to Peer',
		definition:
			'A decentralized network model where devices communicate directly with each other without a central server.',
	},
	{
		acronym: 'PaaS - Platform as a Service',
		definition:
			'A cloud computing model that provides developers with a platform to build, deploy, and manage applications.',
	},
	{
		acronym: 'PAC - Proxy Auto Configuration',
		definition:
			'A file used by web browsers to automatically determine the appropriate proxy server for a given URL.',
	},
	{
		acronym: 'PAM - Privileged Access Management',
		definition:
			'A security solution that controls and monitors access to critical systems and data by privileged users.',
	},
	{
		acronym: 'PAM - Pluggable Authentication Modules',
		definition:
			'A flexible framework for authentication that allows system administrators to integrate multiple authentication methods.',
	},
	{
		acronym: 'PAP - Password Authentication Protocol',
		definition:
			'A simple authentication protocol that sends passwords in plaintext, making it less secure compared to alternatives.',
	},
	{
		acronym: 'PAT - Port Address Translation',
		definition:
			'A type of NAT that maps multiple private IP addresses to a single public IP address using unique port numbers.',
	},
	{
		acronym: 'PBKDF2 - Password-based Key Derivation Function 2',
		definition:
			'A key stretching algorithm used to strengthen passwords by increasing computational effort during brute-force attacks.',
	},
	{
		acronym: 'PBX - Private Branch Exchange',
		definition:
			'A private telephone network used within an organization, allowing internal and external communication.',
	},
	{
		acronym: 'PCAP - Packet Capture',
		definition:
			'A file format used to record and analyze network traffic for troubleshooting or security purposes.',
	},
	{
		acronym: 'PCI DSS - Payment Card Industry Data Security Standard',
		definition:
			'A set of security standards designed to protect cardholder data during transactions and storage.',
	},
	{
		acronym: 'PDU - Power Distribution Unit',
		definition:
			'A device used in data centers to distribute electrical power to connected equipment.',
	},
	{
		acronym: 'PEAP - Protected Extensible Authentication Protocol',
		definition:
			'A wireless network authentication protocol that provides encryption and protection for transmitted credentials.',
	},
	{
		acronym: 'PED - Personal Electronic Device',
		definition:
			'A device such as a smartphone, tablet, or laptop used for personal or work-related tasks.',
	},
	{
		acronym: 'PEM - Privacy Enhanced Mail',
		definition:
			'A file format for storing and transmitting cryptographic keys and certificates in a base64-encoded text format.',
	},
	{
		acronym: 'PFS - Perfect Forward Secrecy',
		definition:
			'A cryptographic feature that ensures session keys are unique and not derived from long-term keys, protecting past communications.',
	},
	{
		acronym: 'PGP - Pretty Good Privacy',
		definition:
			'A data encryption program used to secure emails and files, ensuring confidentiality and integrity.',
	},
	{
		acronym: 'PHI - Personal Health Information',
		definition:
			'Medical information that is protected under privacy laws such as HIPAA in the United States.',
	},
	{
		acronym: 'PII - Personally Identifiable Information',
		definition:
			'Any data that can identify an individual, such as names, Social Security numbers, or biometric data.',
	},
	{
		acronym: 'PIV - Personal Identity Verification',
		definition:
			'A smart card used by federal employees for secure access to government systems and facilities.',
	},
	{
		acronym: 'PKCS - Public Key Cryptography Standards',
		definition:
			'A set of standards for public key cryptography to ensure interoperability between cryptographic systems.',
	},
	{
		acronym: 'PKI - Public Key Infrastructure',
		definition:
			'A framework for managing digital certificates and cryptographic keys to secure electronic communications.',
	},
	{
		acronym: 'POP - Post Office Protocol',
		definition:
			'A protocol used for retrieving emails from a mail server, typically downloading them for local storage.',
	},
	{
		acronym: 'POTS - Plain Old Telephone Service',
		definition:
			'The traditional analog voice telephone service used for communication over copper wires.',
	},
	{
		acronym: 'PPP - Point-to-Point Protocol',
		definition:
			'A protocol used to establish a direct connection between two network nodes, commonly used in dial-up internet.',
	},
	{
		acronym: 'PPTP - Point-to-Point Tunneling Protocol',
		definition:
			'A VPN protocol that allows secure data transfer over public networks, now considered outdated due to security vulnerabilities.',
	},
	{
		acronym: 'PSK - Pre-shared Key',
		definition:
			'A shared secret key used for authentication in wireless networks, commonly associated with WPA/WPA2 security.',
	},
	{
		acronym: 'PTZ - Pan-tilt-zoom',
		definition:
			'A camera feature that allows remote control of camera movement and zoom capabilities, often used in surveillance.',
	},
	{
		acronym: 'PUP - Potentially Unwanted Program',
		definition:
			'Software that is not necessarily malicious but may be unwanted by the user, often bundled with other applications.',
	},
	{
		acronym: 'RA - Recovery Agent',
		definition:
			'A user or system with permissions to recover encrypted data in case of key loss.',
	},
	{
		acronym: 'RA - Registration Authority',
		definition:
			'An entity in a PKI that verifies user identities and forwards certificate requests to a Certificate Authority (CA).',
	},
	{
		acronym:
			'RACE - Research and Development in Advanced Communications Technologies in Europe',
		definition:
			'An initiative focused on advancing telecommunications and information technologies in Europe.',
	},
	{
		acronym: 'RAD - Rapid Application Development',
		definition:
			'A software development methodology emphasizing quick prototyping and iterative testing.',
	},
	{
		acronym: 'RADIUS - Remote Authentication Dial-in User Service',
		definition:
			'A protocol that provides centralized authentication, authorization, and accounting for network access.',
	},
	{
		acronym: 'RAID - Redundant Array of Inexpensive Disks',
		definition:
			'A data storage technology that combines multiple physical disks into a single logical unit to improve performance and reliability.',
	},
	{
		acronym: 'RAS - Remote Access Server',
		definition:
			'A server that provides remote users with access to a network over the internet or other connections.',
	},
	{
		acronym: 'RAT - Remote Access Trojan',
		definition:
			"A type of malware that allows attackers to remotely control a victim's computer.",
	},
	{
		acronym: 'RBAC - Role-based Access Control',
		definition:
			"An access control model that restricts access based on users' roles within an organization.",
	},
	{
		acronym: 'RBAC - Rule-based Access Control',
		definition:
			'An access control model that uses rules to determine access permissions based on conditions like time of day or location.',
	},
	{
		acronym: 'RC4 - Rivest Cipher version 4',
		definition:
			'A stream cipher that was widely used in protocols like SSL but is now considered insecure.',
	},
	{
		acronym: 'RDP - Remote Desktop Protocol',
		definition:
			'A protocol developed by Microsoft that allows users to connect to and control another computer remotely.',
	},
	{
		acronym: 'RFID - Radio Frequency Identifier',
		definition:
			'A technology that uses radio waves to identify and track objects, often used in inventory management and access control.',
	},
	{
		acronym: 'RIPEMD - RACE Integrity Primitives Evaluation Message Digest',
		definition:
			'A cryptographic hash function designed to ensure data integrity.',
	},
	{
		acronym: 'ROI - Return on Investment',
		definition:
			'A performance measure used to evaluate the efficiency or profitability of an investment.',
	},
	{
		acronym: 'RPO - Recovery Point Objective',
		definition:
			'The maximum acceptable amount of data loss measured in time during a disaster recovery scenario.',
	},
	{
		acronym: 'RSA - Rivest, Shamir, & Adleman',
		definition:
			'An asymmetric cryptographic algorithm widely used for secure data transmission.',
	},
	{
		acronym: 'RTBH - Remotely Triggered Black Hole',
		definition:
			'A network security technique used to mitigate DDoS attacks by dropping malicious traffic.',
	},
	{
		acronym: 'RTO - Recovery Time Objective',
		definition:
			'The target time for restoring IT systems and operations after a disruption.',
	},
	{
		acronym: 'RTOS - Real-time Operating System',
		definition:
			'An operating system designed to process data and execute tasks within a strict time frame.',
	},
	{
		acronym: 'RTP - Real-time Transport Protocol',
		definition:
			'A protocol used for delivering audio and video over IP networks in real-time.',
	},
	{
		acronym: 'S/MIME - Secure/Multipurpose Internet Mail Extensions',
		definition:
			'A protocol used for securing email communications through encryption and digital signatures.',
	},
	{
		acronym: 'SaaS - Software as a Service',
		definition:
			'A cloud computing model that delivers software applications over the internet, eliminating the need for local installation.',
	},
	{
		acronym: 'SAE - Simultaneous Authentication of Equals',
		definition:
			'A secure key exchange protocol used in WPA3 to protect against offline dictionary attacks.',
	},
	{
		acronym: 'SAML - Security Assertions Markup Language',
		definition:
			'An open standard for exchanging authentication and authorization data between parties, often used for single sign-on (SSO).',
	},
	{
		acronym: 'SAN - Storage Area Network',
		definition:
			'A high-speed network that provides access to consolidated storage resources.',
	},
	{
		acronym: 'SAN - Subject Alternative Name',
		definition:
			'An extension to X.509 certificates that allows multiple domains to be secured with a single certificate.',
	},
	{
		acronym: 'SASE - Secure Access Service Edge',
		definition:
			'A security framework that combines network and security services in a single cloud-delivered solution.',
	},
	{
		acronym: 'SCADA - Supervisory Control and Data Acquisition',
		definition:
			'A system used to monitor and control industrial processes such as manufacturing, energy, and water treatment.',
	},
	{
		acronym: 'SCAP - Security Content Automation Protocol',
		definition:
			'A suite of standards for automating vulnerability management and compliance.',
	},
	{
		acronym: 'SCEP - Simple Certificate Enrollment Protocol',
		definition:
			'A protocol used to streamline the issuance and management of digital certificates.',
	},
	{
		acronym: 'SD-WAN - Software-defined Wide Area Network',
		definition:
			'A networking approach that uses software to control connectivity, management, and services between data centers and remote locations.',
	},
	{
		acronym: 'SDK - Software Development Kit',
		definition:
			'A set of tools and libraries that developers use to create applications for specific platforms or systems.',
	},
	{
		acronym: 'SDLC - Software Development Lifecycle',
		definition:
			'A process used for planning, creating, testing, and deploying information systems.',
	},
	{
		acronym: 'SDLM - Software Development Lifecycle Methodology',
		definition:
			'A structured approach to software development, focusing on each phase of the development lifecycle.',
	},
	{
		acronym: 'SDN - Software-defined Networking',
		definition:
			'A network architecture approach that enables centralized control of network traffic through software applications.',
	},
	{
		acronym: 'SE Linux - Security-enhanced Linux',
		definition:
			'A Linux kernel security module that provides a mechanism for supporting access control policies.',
	},
	{
		acronym: 'SED - Self-encrypting Drives',
		definition:
			'Storage devices that automatically encrypt data stored on the drive using a built-in encryption engine.',
	},
	{
		acronym: 'SEH - Structured Exception Handler',
		definition:
			'A mechanism used in programming to handle exceptions or errors that occur during execution.',
	},
	{
		acronym: 'SFTP - Secured File Transfer Protocol',
		definition:
			'A secure version of the File Transfer Protocol (FTP) that uses SSH for encryption.',
	},
	{
		acronym: 'SHA - Secure Hashing Algorithm',
		definition:
			'A family of cryptographic hash functions designed to ensure data integrity and security.',
	},
	{
		acronym: 'SHTTP - Secure Hypertext Transfer Protocol',
		definition:
			'An obsolete protocol used to provide security for HTTP communications.',
	},
	{
		acronym: 'SIEM - Security Information and Event Management',
		definition:
			'A system that collects, analyzes, and correlates security data from multiple sources to provide real-time threat detection and response.',
	},
	{
		acronym: 'SIM - Subscriber Identity Module',
		definition:
			'A smart card used in mobile devices to store user identity, authentication, and network information.',
	},
	{
		acronym: 'SLA - Service-level Agreement',
		definition:
			'A formal agreement between a service provider and a customer defining the level of service expected.',
	},
	{
		acronym: 'SLE - Single Loss Expectancy',
		definition:
			'The monetary value of a single loss, calculated as Asset Value × Exposure Factor.',
	},
	{
		acronym: 'SMS - Short Message Service',
		definition:
			'A text messaging service that allows short messages to be sent between mobile devices.',
	},
	{
		acronym: 'SMTP - Simple Mail Transfer Protocol',
		definition:
			'A protocol used to send emails between servers on the internet.',
	},
	{
		acronym: 'SMTPS - Simple Mail Transfer Protocol Secure',
		definition:
			'A secure version of SMTP that uses SSL/TLS to encrypt email communications.',
	},
	{
		acronym: 'SNMP - Simple Network Management Protocol',
		definition:
			'A protocol used to manage and monitor network devices and their performance.',
	},
	{
		acronym: 'SOAP - Simple Object Access Protocol',
		definition:
			'A protocol used for exchanging structured information in web services.',
	},
	{
		acronym: 'SOAR - Security Orchestration, Automation, and Response',
		definition:
			'A platform that integrates and automates security tools and processes to improve incident response.',
	},
	{
		acronym: 'SoC - System on Chip',
		definition:
			'An integrated circuit that consolidates all components of a computer or electronic system onto a single chip.',
	},
	{
		acronym: 'SOC - Security Operations Center',
		definition:
			'A centralized unit that monitors, detects, and responds to cybersecurity threats and incidents within an organization.',
	},
	{
		acronym: 'SOW - Statement of Work',
		definition:
			'A formal document that outlines the scope, deliverables, and timelines for a project or contract.',
	},
	{
		acronym: 'SPF - Sender Policy Framework',
		definition:
			"An email authentication protocol that helps prevent email spoofing by verifying the sender's IP address.",
	},
	{
		acronym: 'SPIM - Spam over Internet Messaging',
		definition:
			'Unsolicited messages sent over instant messaging services, similar to email spam.',
	},
	{
		acronym: 'SQL - Structured Query Language',
		definition:
			'A standard language used for managing and manipulating relational databases.',
	},
	{
		acronym: 'SQLi - SQL Injection',
		definition:
			'A type of cyberattack where malicious SQL code is injected into a query to manipulate or access a database.',
	},
	{
		acronym: 'SRTP - Secure Real-Time Protocol',
		definition:
			'An extension of the Real-Time Protocol (RTP) that provides encryption, message authentication, and integrity for real-time communications.',
	},
	{
		acronym: 'SSD - Solid State Drive',
		definition:
			'A data storage device that uses flash memory for faster read and write speeds compared to traditional hard drives.',
	},
	{
		acronym: 'SSH - Secure Shell',
		definition:
			'A cryptographic network protocol used to securely access and manage devices over an unsecured network.',
	},
	{
		acronym: 'SSL - Secure Sockets Layer',
		definition:
			'A deprecated protocol used to secure communications over a computer network, replaced by TLS.',
	},
	{
		acronym: 'SSO - Single Sign-on',
		definition:
			'An authentication method that allows users to access multiple applications with one set of login credentials.',
	},
	{
		acronym: 'STIX - Structured Threat Information eXchange',
		definition:
			'A standardized format for sharing threat intelligence data across organizations.',
	},
	{
		acronym: 'SWG - Secure Web Gateway',
		definition:
			'A security solution that filters and monitors web traffic to protect against threats and enforce policies.',
	},
	{
		acronym: 'TACACS+ - Terminal Access Controller Access Control System Plus',
		definition:
			'A protocol used to provide centralized authentication and authorization for network devices.',
	},
	{
		acronym: 'TAXII - Trusted Automated eXchange of Indicator Information',
		definition:
			'A protocol for securely sharing threat intelligence data between organizations.',
	},
	{
		acronym: 'TCP/IP - Transmission Control Protocol/Internet Protocol',
		definition:
			'A suite of communication protocols used to interconnect network devices on the internet.',
	},
	{
		acronym: 'TGT - Ticket Granting Ticket',
		definition:
			'A temporary credential issued by the Kerberos authentication system, used to obtain access to services.',
	},
	{
		acronym: 'TKIP - Temporal Key Integrity Protocol',
		definition:
			'A security protocol used in WPA to provide improved encryption for wireless networks, now deprecated.',
	},
	{
		acronym: 'TLS - Transport Layer Security',
		definition:
			'A cryptographic protocol that provides secure communication over a network, replacing SSL.',
	},
	{
		acronym: 'TOC - Time-of-check',
		definition:
			'A concept in software testing and security that ensures operations are performed as intended at a specific point in time.',
	},
	{
		acronym: 'TOTP - Time-based One-time Password',
		definition:
			'A temporary passcode generated using the current time and a shared secret, commonly used in two-factor authentication.',
	},
	{
		acronym: 'TOU - Time-of-use',
		definition:
			'A concept in energy management or billing that varies charges based on the time of day energy is used.',
	},
	{
		acronym: 'TPM - Trusted Platform Module',
		definition:
			'A hardware-based security module used to secure cryptographic operations and store sensitive data like encryption keys.',
	},
	{
		acronym: 'TTP - Tactics, Techniques, and Procedures',
		definition:
			'The behavior patterns of cyber adversaries used to describe their methods, actions, and strategies.',
	},
	{
		acronym: 'TSIG - Transaction Signature',
		definition:
			'A mechanism used to secure DNS messages by providing message integrity and authentication.',
	},
	{
		acronym: 'UAT - User Acceptance Testing',
		definition:
			'The final phase of software testing where end-users validate that the system meets their requirements.',
	},
	{
		acronym: 'UAV - Unmanned Aerial Vehicle',
		definition:
			'A drone or aircraft controlled remotely or autonomously without a human pilot onboard.',
	},
	{
		acronym: 'UDP - User Datagram Protocol',
		definition:
			'A connectionless protocol used in networking that prioritizes speed over reliability, often used in video streaming and gaming.',
	},
	{
		acronym: 'UEFI - Unified Extensible Firmware Interface',
		definition:
			'A modern firmware interface between the operating system and platform firmware, replacing BIOS with more features and security.',
	},
	{
		acronym: 'UEM - Unified Endpoint Management',
		definition:
			'A framework for managing and securing all endpoint devices in an organization, such as desktops, laptops, and mobile devices.',
	},
	{
		acronym: 'UPS - Uninterruptable Power Supply',
		definition:
			'A device that provides backup power and surge protection for electronic equipment during power outages.',
	},
	{
		acronym: 'URI - Uniform Resource Identifier',
		definition:
			'A string of characters used to identify a resource on the internet, such as a URL or URN.',
	},
	{
		acronym: 'URL - Universal Resource Locator',
		definition:
			'The address used to access a specific resource on the internet, such as a website or file.',
	},
	{
		acronym: 'USB - Universal Serial Bus',
		definition:
			'A standard interface for connecting peripheral devices to a computer, such as keyboards, mice, and external drives.',
	},
	{
		acronym: 'USB OTG - USB On the Go',
		definition:
			'A feature that allows a USB device to act as a host, enabling other USB devices to connect to it.',
	},
	{
		acronym: 'UTM - Unified Threat Management',
		definition:
			'A comprehensive security solution that integrates multiple security features, such as firewalls, antivirus, and intrusion prevention.',
	},
	{
		acronym: 'UTP - Unshielded Twisted Pair',
		definition:
			'A type of cabling commonly used in Ethernet networks, consisting of pairs of wires twisted together to reduce electromagnetic interference.',
	},
	{
		acronym: 'VBA - Visual Basic for Applications',
		definition:
			'A programming language developed by Microsoft used for automating tasks and customizing functionality in applications like Excel.',
	},
	{
		acronym: 'VDE - Virtual Desktop Environment',
		definition:
			'A virtualized computing environment that allows users to access their desktop and applications remotely.',
	},
	{
		acronym: 'VDI - Virtual Desktop Infrastructure',
		definition:
			'A virtualization technology that hosts desktop environments on a centralized server and provides remote access to them.',
	},
	{
		acronym: 'VLAN - Virtual Local Area Network',
		definition:
			'A logical grouping of network devices that allows for segmentation and isolation within a physical network.',
	},
	{
		acronym: 'VLSM - Variable Length Subnet Masking',
		definition:
			'A technique that allows different subnet masks within the same network, improving IP address allocation efficiency.',
	},
	{
		acronym: 'VM - Virtual Machine',
		definition:
			'A software-based emulation of a physical computer that runs an operating system and applications.',
	},
	{
		acronym: 'VoIP - Voice over IP',
		definition:
			'A technology that enables voice communication and multimedia sessions over the internet instead of traditional phone lines.',
	},
	{
		acronym: 'VPC - Virtual Private Cloud',
		definition:
			"A secure, isolated section of a cloud provider's network where users can deploy resources and run applications.",
	},
	{
		acronym: 'VPN - Virtual Private Network',
		definition:
			'A technology that creates a secure and encrypted connection over a less secure network, such as the internet.',
	},
	{
		acronym: 'VTC - Video Teleconferencing',
		definition:
			'A technology that allows people in different locations to communicate via video and audio in real-time.',
	},
	{
		acronym: 'WAF - Web Application Firewall',
		definition:
			'A security solution that monitors, filters, and blocks HTTP traffic to and from a web application to protect against attacks.',
	},
	{
		acronym: 'WAP - Wireless Access Point',
		definition:
			'A networking device that allows wireless devices to connect to a wired network using Wi-Fi.',
	},
	{
		acronym: 'WEP - Wired Equivalent Privacy',
		definition:
			'An outdated wireless network security protocol that has been replaced by WPA due to vulnerabilities.',
	},
	{
		acronym: 'WIDS - Wireless Intrusion Detection System',
		definition:
			'A system that monitors wireless networks for malicious activities or policy violations.',
	},
	{
		acronym: 'WIPS - Wireless Intrusion Prevention System',
		definition:
			'A system that proactively detects and prevents unauthorized access to or attacks on a wireless network.',
	},
	{
		acronym: 'WO - Work Order',
		definition:
			'A document that outlines the tasks and details of a job or project to be completed.',
	},
	{
		acronym: 'WPA - Wi-Fi Protected Access',
		definition:
			'A security protocol designed to secure wireless networks, providing stronger encryption than WEP.',
	},
	{
		acronym: 'WPS - Wi-Fi Protected Setup',
		definition:
			'A network security standard that allows users to quickly and securely connect devices to a wireless network.',
	},
	{
		acronym: 'WTLS - Wireless TLS',
		definition:
			'A security protocol used to provide encryption and secure communication for wireless networks.',
	},
	{
		acronym: 'XDR - Extended Detection and Response',
		definition:
			'A cybersecurity solution that integrates and correlates data from multiple security tools for enhanced threat detection and response.',
	},
	{
		acronym: 'XML - Extensible Markup Language',
		definition:
			'A markup language used for encoding and structuring data in a format that is both human-readable and machine-readable.',
	},
	{
		acronym: 'XOR - Exclusive Or',
		definition:
			'A logical operation that outputs true only when the inputs are different, commonly used in cryptographic algorithms.',
	},
	{
		acronym: 'XSRF - Cross-site Request Forgery',
		definition:
			'A web security vulnerability where an attacker tricks a user into performing actions on a website without their consent.',
	},
	{
		acronym: 'XSS - Cross-site Scripting',
		definition:
			'A web application vulnerability that allows attackers to inject malicious scripts into webpages viewed by other users.',
	},
];

// console.log('Flashcards loaded:', flashcards.length);
// console.log('First card:', flashcards[0]);

let currentIndex = 0;
let isFlipped = false;
let cards = [...flashcards];
let isPlaying = false;
let touchStartX = 0;
let touchStartY = 0;
let touchEndX = 0;
let touchEndY = 0;
let isTouchMove = false;

// DOM Elements
const cardElement = document.getElementById('card');
const cardAcronym = document.getElementById('cardAcronym');
const cardDefinition = document.getElementById('cardDefinition');
const currentCardElement = document.getElementById('currentCard');
const totalCardsElement = document.getElementById('totalCards');
const resetBtn = document.getElementById('resetBtn');
const shuffleBtn = document.getElementById('shuffleBtn');
const jumpInput = document.getElementById('jumpInput');
const jumpBtn = document.getElementById('jumpBtn');
const searchInput = document.getElementById('searchInput');
const searchBtn = document.getElementById('searchBtn');
const searchResults = document.getElementById('searchResults');
const searchFeedback = document.getElementById('searchFeedback');
const audioBtn = document.getElementById('audioBtn');

function sanitizeHTML(str) {
	const div = document.createElement('div');
	div.textContent = str;
	return div.innerHTML;
}

function isMobileDevice() {
	return window.innerWidth <= 767;
}

function updateCard() {
	// Add debug logging
	console.log('Current index:', currentIndex);
	console.log('Current card:', cards[currentIndex]);

	const acronymParts = cards[currentIndex].acronym.split(' - ');
	if (acronymParts.length > 1) {
		const sanitizedAcronym = sanitizeHTML(acronymParts[0]);
		const sanitizedTitle = sanitizeHTML(acronymParts[1]);
		cardAcronym.innerHTML = `<h2>${sanitizedAcronym}</h2><br><h1>${sanitizedTitle}</h1>`;
	} else {
		cardAcronym.textContent = acronymParts[0];
	}

	const tempDiv = document.createElement('div');
	tempDiv.innerHTML = cards[currentIndex].definition;
	const allowedTags = ['br', 'b'];

	const sanitizedDefinition = tempDiv.innerHTML.replace(/<[^>]*>/g, (match) => {
		const tag = match.replace(/[<>/]/g, '').split(' ')[0];
		return allowedTags.includes(tag) ? match : '';
	});

	cardDefinition.innerHTML = sanitizedDefinition;
	currentCardElement.textContent = currentIndex + 1;
	totalCardsElement.textContent = cards.length;
}

function updateCardContent(card) {
	const cardAcronym = document.getElementById('cardAcronym');
	const cardDefinition = document.getElementById('cardDefinition');

	cardAcronym.textContent = card.acronym;
	cardDefinition.innerHTML = card.definition.replace(/\n/g, '<br>');
}

function shuffleCards() {
	cards = [...cards].sort(() => Math.random() - 0.5);
	currentIndex = 0;
	isFlipped = false;
	cardElement.classList.remove('flipped');
	updateCard();
}

function resetDeck() {
	localStorage.removeItem('flashcardProgress');
	cards = [...flashcards]; // Reset to original array
	currentIndex = 0;
	isFlipped = false;
	cardElement.classList.remove('flipped');
	updateCard();
	console.log('Deck reset with', cards.length, 'cards'); // Debug log
}

function jumpToCard() {
	const jumpIndex = parseInt(jumpInput.value) - 1;
	if (isNaN(jumpIndex) || jumpIndex < 0 || jumpIndex >= cards.length) {
		// Add error feedback
		const feedback = document.createElement('div');
		feedback.className = 'error-feedback';
		feedback.textContent = `Please enter a number between 1 and ${cards.length}`;
		jumpInput.parentNode.appendChild(feedback);
		setTimeout(() => feedback.remove(), 3000);
		return;
	}
	currentIndex = jumpIndex;
	isFlipped = false;
	cardElement.classList.remove('flipped');
	updateCard();
	jumpInput.value = '';
}

function searchCards() {
	const searchTerm = sanitizeHTML(searchInput.value.trim().toLowerCase());
	searchResults.innerHTML = '';

	if (searchTerm === '') {
		searchResults.classList.remove('active');
		searchFeedback.textContent = 'Please enter a search term';
		return;
	}

	const matches = cards.filter(
		(card) =>
			sanitizeHTML(card.acronym.toLowerCase()).includes(searchTerm) ||
			sanitizeHTML(card.definition.toLowerCase()).includes(searchTerm)
	);

	if (matches.length > 0) {
		searchResults.classList.add('active');
		matches.forEach((card, index) => {
			const div = document.createElement('div');
			div.className = 'search-result-item';
			const previewText = sanitizeHTML(
				`${card.acronym}: ${card.definition.substring(0, 60)}...`
			);
			div.textContent = previewText;
			div.addEventListener('click', () => {
				currentIndex = cards.findIndex((c) => c.acronym === card.acronym);
				isFlipped = false;
				cardElement.classList.remove('flipped');
				updateCard();
				searchInput.value = '';
				searchResults.classList.remove('active');
				searchFeedback.textContent = `Showing card for ${card.acronym}`;
			});
			searchResults.appendChild(div);
		});
		searchFeedback.textContent = `Found ${matches.length} matches`;
	} else {
		searchResults.classList.remove('active');
		searchFeedback.textContent = 'No matches found';
	}
}

// Audio Script
let currentAudio = null;

function stopAudio() {
	if (currentAudio) {
		currentAudio.pause();
		currentAudio.currentTime = 0;
	}
	isPlaying = false;
	audioBtn.textContent = 'Start Audio Playback';
	audioBtn.classList.remove('playing');
}

async function getAudioForText(text) {
	try {
		const selectedVoice = document.getElementById('voiceSelect').value;
		if (!text || typeof text !== 'string') {
			throw new Error('Invalid text input');
		}

		const response = await fetch('http://localhost:3000/api/text-to-speech', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				text: text.trim(),
				voice: selectedVoice,
			}),
		});

		if (!response.ok) {
			throw new Error(`HTTP error! status: ${response.status}`);
		}

		const data = await response.json();
		if (!data.audio) {
			throw new Error('No audio data received');
		}

		return `data:audio/mpeg;base64,${data.audio}`;
	} catch (error) {
		console.error('Error getting audio:', error);
		// Add visual feedback for errors
		const audioBtn = document.getElementById('audioBtn');
		audioBtn.classList.add('error');
		audioBtn.textContent = 'Error: Try Again';
		setTimeout(() => {
			audioBtn.classList.remove('error');
			audioBtn.textContent = 'Start Audio Playback';
		}, 3000);
		stopAudio();
		return null;
	}
}

async function playCurrentCard() {
	if (!isPlaying) return;

	try {
		if (!navigator.onLine) {
			throw new Error('No internet connection');
		}
		// Ensure card is showing front side
		cardElement.classList.remove('flipped');
		isFlipped = false;

		// Split the acronym and prepare text
		const acronymParts = cards[currentIndex].acronym.split(' - ');
		const acronymText = acronymParts.join('. ');

		// Get front audio
		const frontAudioSrc = await getAudioForText(acronymText);
		if (!frontAudioSrc) return;

		// Create and play front audio
		currentAudio = new Audio(frontAudioSrc);

		// When front audio ends, flip card and play back
		currentAudio.onended = async () => {
			if (!isPlaying) return;

			// Flip card to back
			cardElement.classList.add('flipped');
			isFlipped = true;

			// Clean up any HTML tags and prepare back text
			const backText = cards[currentIndex].definition
				.replace(/<br><br>/g, '. ')
				.replace(/<[^>]*>/g, '')
				.trim();

			const backAudioSrc = await getAudioForText(backText);
			if (!backAudioSrc) return;

			currentAudio = new Audio(backAudioSrc);

			// When back audio ends, move to next card
			currentAudio.onended = () => {
				if (!isPlaying) return;

				// Move to next card
				currentIndex = (currentIndex + 1) % cards.length;
				updateCard();

				// Start playing next card
				setTimeout(() => {
					if (isPlaying) {
						playCurrentCard();
					}
				}, 1000); // Add a brief pause between cards
			};

			try {
				await currentAudio.play();
			} catch (error) {
				console.error('Error playing back audio:', error);
				stopAudio();
			}
		};

		try {
			await currentAudio.play();
		} catch (error) {
			console.error('Error playing front audio:', error);
			stopAudio();
		}
	} catch (error) {
		console.error('Error in playCurrentCard:', error);
		const errorMessage =
			error.message === 'No internet connection'
				? 'Please check your internet connection'
				: 'An error occurred while playing audio';
		showError(errorMessage);
		stopAudio();
	}
}

function showError(message) {
	const errorDiv = document.createElement('div');
	errorDiv.className = 'error-message';
	errorDiv.textContent = message;
	document.querySelector('.audio-controls').appendChild(errorDiv);
	setTimeout(() => errorDiv.remove(), 3000);
}

// Function to handle card flipping
function handleCardFlip() {
	if (!isFlipped) {
		cardElement.classList.add('flipped');
		isFlipped = true;
	} else {
		cardElement.classList.add('switching');

		setTimeout(() => {
			currentIndex = (currentIndex + 1) % cards.length;
			updateCard();
			cardElement.classList.remove('flipped');

			setTimeout(() => {
				cardElement.classList.remove('switching');
				isFlipped = false;
			}, 50);
		}, 300);
	}
}

// Event Listeners
cardElement.addEventListener('click', (e) => {
	// Only handle click if it's not from a touch event
	if (e.sourceCapabilities && e.sourceCapabilities.firesTouchEvents) {
		return;
	}

	if (!isMobileDevice()) {
		stopAudio();
	}

	handleCardFlip();
});

// Improve audio button handling for mobile
audioBtn.addEventListener('click', (e) => {
	// Remove the mobile check to allow audio on capable mobile devices
	if (isPlaying) {
		stopAudio();
	} else {
		isPlaying = true;
		audioBtn.textContent = 'Stop Audio Playback';
		audioBtn.classList.add('playing');
		playCurrentCard();
	}
});

resetBtn.addEventListener('click', () => {
	stopAudio();
	resetDeck();
});

shuffleBtn.addEventListener('click', () => {
	stopAudio();
	shuffleCards();
});

jumpBtn.addEventListener('click', () => {
	stopAudio();
	jumpToCard();
});

jumpInput.addEventListener('keypress', (e) => {
	if (e.key === 'Enter') jumpToCard();
});

searchBtn.addEventListener('click', searchCards);

// Add visibility change handling to properly stop audio
document.addEventListener('visibilitychange', () => {
	if (document.hidden && isPlaying) {
		stopAudio();
	}
});

// Add debouncing for search function to prevent excessive filtering
function debounce(func, wait) {
	let timeout;
	return function executedFunction(...args) {
		const later = () => {
			clearTimeout(timeout);
			func(...args);
		};
		clearTimeout(timeout);
		timeout = setTimeout(later, wait);
	};
}

// Use debounced search
const debouncedSearch = debounce(searchCards, 300);
searchInput.addEventListener('keyup', debouncedSearch);

// Hide search results when clicking outside
document.addEventListener('click', (e) => {
	if (!searchResults.contains(e.target) && e.target !== searchInput) {
		searchResults.classList.remove('active');
	}
});

// Initialize the flashcard
updateCard();

// Add keyboard controls
document.addEventListener('keydown', (e) => {
	if (e.key === 'ArrowRight' || e.key === 'Space') {
		// Next card
		currentIndex = (currentIndex + 1) % cards.length;
		isFlipped = false;
		cardElement.classList.remove('flipped');
		updateCard();
	} else if (e.key === 'ArrowLeft') {
		// Previous card
		currentIndex = (currentIndex - 1 + cards.length) % cards.length;
		isFlipped = false;
		cardElement.classList.remove('flipped');
		updateCard();
	} else if (e.key === 'Enter') {
		// Flip card
		cardElement.classList.toggle('flipped');
		isFlipped = !isFlipped;
	}
});

// Save progress to localStorage
function saveProgress() {
	const progress = {
		currentIndex,
		isFlipped,
		cards,
	};
	localStorage.setItem('flashcardProgress', JSON.stringify(progress));
}

// Load progress from localStorage
function loadProgress() {
	const saved = localStorage.getItem('flashcardProgress');
	if (saved) {
		const progress = JSON.parse(saved);
		currentIndex = progress.currentIndex;
		isFlipped = progress.isFlipped;
		cards = progress.cards;
		updateCard();
	}
}

// Add event listener for saving progress
window.addEventListener('beforeunload', saveProgress);

// Load progress when page loads
document.addEventListener('DOMContentLoaded', loadProgress);

cardElement.addEventListener(
	'touchstart',
	(e) => {
		touchStartX = e.touches[0].clientX;
		touchStartY = e.touches[0].clientY;
		isTouchMove = false;
	},
	{ passive: true }
);

cardElement.addEventListener(
	'touchmove',
	(e) => {
		isTouchMove = true;
		touchEndX = e.touches[0].clientX;
		touchEndY = e.touches[0].clientY;

		// Calculate the angle of the swipe
		const xDiff = touchEndX - touchStartX;
		const yDiff = touchEndY - touchStartY;
		const angle = Math.abs((Math.atan2(yDiff, xDiff) * 180) / Math.PI);

		// If the angle is between 0 and 45 degrees or between 135 and 180 degrees,
		// it's more horizontal than vertical, so prevent scrolling
		if (angle <= 45 || angle >= 135) {
			e.preventDefault();
		}
	},
	{ passive: false }
);

cardElement.addEventListener(
	'touchend',
	(e) => {
		touchEndX = e.changedTouches[0].clientX;
		touchEndY = e.changedTouches[0].clientY;

		// Only handle swipe if there was movement
		if (isTouchMove) {
			handleSwipe();
		} else {
			// It was a tap, handle card flip
			handleCardFlip();
		}
	},
	{ passive: true }
);

// Add touch event prevention to search results
searchResults.addEventListener(
	'touchstart',
	(e) => {
		e.stopPropagation();
	},
	{ passive: true }
);

function handleSwipe() {
	const swipeThreshold = window.innerWidth * 0.15; // 15% of screen width
	const xDiff = touchEndX - touchStartX;
	const yDiff = touchEndY - touchStartY;

	// Check if horizontal swipe is more prominent than vertical
	if (Math.abs(xDiff) > Math.abs(yDiff) && Math.abs(xDiff) > swipeThreshold) {
		if (xDiff > 0) {
			// Swipe right - previous card
			currentIndex = (currentIndex - 1 + cards.length) % cards.length;
		} else {
			// Swipe left - next card
			currentIndex = (currentIndex + 1) % cards.length;
		}
		isFlipped = false;
		cardElement.classList.remove('flipped');
		updateCard();
	}
}

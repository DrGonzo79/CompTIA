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
			'AES-256 is a version of AES with a 256-bit key length, offering robust encryption.\n\nPurpose: Provides stronger security to resist brute-force attacks and quantum computing threats.\nDeployment: Used in secure communications like HTTPS, file encryption, and secure file sharing.\nContext: Standard for encrypting classified information and high-security applications.',
	},
	{
		acronym: 'AH - Authentication Header',
		definition:
			'AH is a protocol in IPsec that ensures data integrity and authenticity of packets.\n\nPurpose: Adds a layer of security by verifying data integrity and source authentication without encryption.\nDeployment: Configured in IPsec settings in network devices and systems, often alongside ESP.\nContext: Used in secure network communication where integrity is crucial but confidentiality is not required.',
	},
	{
		acronym: 'AI - Artificial Intelligence',
		definition:
			'AI involves machine-driven intelligence processes in cybersecurity.\n\nPurpose: Enhances cybersecurity through automated threat detection, pattern recognition, and response.\nDeployment: Integrated into security tools like SIEM, EDR, and threat intelligence platforms.\nContext: Used for behavioral analysis, anomaly detection, and automating security responses at scale.',
	},
	{
		acronym: 'AIS - Automated Indicator Sharing',
		definition:
			'AIS is a system for sharing cybersecurity threat indicators between organizations.\n\nPurpose: Enables faster response to emerging threats through automated sharing of threat intelligence.\nDeployment: Implemented through TAXII/STIX protocols and platforms supported by CISA.\nContext: Critical in government and private sector collaboration for cyber defense.',
	},
	{
		acronym: 'ALE - Annualized Loss Expectancy',
		definition:
			'ALE quantifies the expected yearly monetary loss from security risks.\n\nPurpose: Helps organizations make informed decisions about security investments.\nDeployment: Calculated using SLE (Single Loss Expectancy) × ARO (Annual Rate of Occurrence).\nContext: Essential in risk management frameworks and security budget planning.',
	},
	{
		acronym: 'AP - Access Point',
		definition:
			'An AP is a networking device that enables wireless connectivity.\n\nPurpose: Provides wireless network access while maintaining security controls.\nDeployment: Installed strategically for coverage, managed through controllers or cloud platforms.\nContext: Critical in modern network infrastructure, requiring security features like WPA3.',
	},
	{
		acronym: 'API - Application Programming Interface',
		definition:
			'API defines protocols for software interaction and data exchange.\n\nPurpose: Enables secure and controlled access to application functionality and data.\nDeployment: Implemented with authentication, rate limiting, and encryption.\nContext: Essential in modern applications, requiring robust security controls.',
	},
	{
		acronym: 'APT - Advanced Persistent Threat',
		definition:
			'APT represents sophisticated, long-term targeted attacks.\n\nPurpose: Gains and maintains unauthorized access for espionage or data theft.\nDeployment: Detected through advanced security tools, threat hunting, and behavioral analysis.\nContext: Major concern for government and high-value corporate targets.',
	},
	{
		acronym: 'ARO - Annualized Rate of Occurrence',
		definition:
			'ARO estimates the frequency of security incidents per year.\n\nPurpose: Helps quantify risk frequency for security planning and ALE calculations.\nDeployment: Determined through historical data analysis and threat intelligence.\nContext: Used in risk assessment frameworks and security planning.',
	},
	{
		acronym: 'ARP - Address Resolution Protocol',
		definition:
			'ARP maps IP addresses to MAC addresses in local networks.\n\nPurpose: Enables proper packet delivery while presenting security considerations.\nDeployment: Built into network devices with security features like ARP inspection.\nContext: Critical for network operations but vulnerable to ARP poisoning attacks.',
	},
	{
		acronym: 'ASLR - Address Space Layout Randomization',
		definition:
			'ASLR is a security technique randomizing memory addresses.\n\nPurpose: Prevents memory-based attacks by making target locations unpredictable.\nDeployment: Built into modern operating systems and supported by applications.\nContext: Essential protection against buffer overflow and memory exploitation attacks.',
	},
	{
		acronym: 'ATT&CK - Adversarial Tactics, Techniques, and Common Knowledge',
		definition:
			'ATT&CK is a comprehensive framework for understanding cyber threats.\n\nPurpose: Provides structured approach to understanding and defending against attacks.\nDeployment: Used in threat modeling, security testing, and defense planning.\nContext: Standard reference for security teams and threat intelligence analysts.',
	},
	{
		acronym: 'AUP - Acceptable Use Policy',
		definition:
			'AUP defines rules for acceptable use of IT resources.\n\nPurpose: Establishes guidelines for secure and appropriate resource usage.\nDeployment: Distributed and acknowledged during onboarding, with regular updates.\nContext: Foundation of organizational security policy and compliance.',
	},
	{
		acronym: 'AV - Antivirus',
		definition:
			'Antivirus software protects against malicious code.\n\nPurpose: Detects, prevents, and removes malware from systems.\nDeployment: Installed on endpoints with central management and regular updates.\nContext: Basic security requirement for all systems, often part of larger EPP solutions.',
	},
	{
		acronym: 'BASH - Bourne Again Shell',
		definition:
			'BASH is a command-line interface and scripting environment.\n\nPurpose: Enables system administration and security automation.\nDeployment: Standard in Linux/Unix systems, used for security scripts and automation.\nContext: Essential tool for security professionals and system administrators.',
	},
	{
		acronym: 'BCP - Business Continuity Planning',
		definition:
			'BCP involves strategies for maintaining operations during disruptions.\n\nPurpose: Ensures critical business functions continue during incidents.\nDeployment: Documented plans with regular testing and updates.\nContext: Critical for organizational resilience and incident response.',
	},
	{
		acronym: 'BGP - Border Gateway Protocol',
		definition:
			'BGP manages routing between autonomous systems on the internet.\n\nPurpose: Enables global internet routing while requiring security controls.\nDeployment: Configured with authentication and filtering on border routers.\nContext: Critical internet infrastructure requiring protection against BGP hijacking.',
	},
	{
		acronym: 'BIA - Business Impact Analysis',
		definition:
			'BIA identifies critical operations and assesses disruption impacts.\n\nPurpose: Guides recovery priorities and resource allocation.\nDeployment: Conducted through interviews, analysis, and documentation.\nContext: Essential for disaster recovery and business continuity planning.',
	},
	{
		acronym: 'BIOS - Basic Input/Output System',
		definition:
			'BIOS is firmware initializing hardware during boot process.\n\nPurpose: Provides secure system initialization and hardware configuration.\nDeployment: Protected through passwords and security settings.\nContext: Critical for system security, often replaced by UEFI in modern systems.',
	},
	{
		acronym: 'BPA - Business Partners Agreement',
		definition:
			'BPA defines security responsibilities between business partners.\n\nPurpose: Establishes security requirements and responsibilities in partnerships.\nDeployment: Negotiated and signed before sharing sensitive resources.\nContext: Essential for managing third-party security risks.',
	},
	{
		acronym: 'BPDU - Bridge Protocol Data Unit',
		definition:
			'BPDU manages Layer 2 network topology.\n\nPurpose: Prevents network loops while requiring security controls.\nDeployment: Configured with BPDU guard and root guard for protection.\nContext: Important in switched networks requiring topology security.',
	},
	{
		acronym: 'BYOD - Bring Your Own Device',
		definition:
			'BYOD allows personal devices in work environments.\n\nPurpose: Enables workforce mobility while managing security risks.\nDeployment: Implemented with MDM, MAM, and security policies.\nContext: Common in modern workplaces requiring balance of convenience and security.',
	},
	{
		acronym: 'CA - Certificate Authority',
		definition:
			'CA is a trusted entity that issues and manages digital certificates.\n\nPurpose: Validates identity and binds public keys to entities, establishing trust in digital certificates.\nDeployment: Implemented as public CAs (like DigiCert) or private PKI infrastructure.\nContext: Critical for secure web communications (HTTPS), digital signatures, and email security.',
	},
	{
		acronym:
			'CAPTCHA - Completely Automated Public Turing Test to Tell Computers and Humans Apart',
		definition:
			'CAPTCHA is a security mechanism that validates human interaction.\n\nPurpose: Prevents automated attacks, bot activities, and brute force attempts.\nDeployment: Implemented on web forms, login pages, and registration processes.\nContext: Used in websites and applications to prevent automated abuse.',
	},
	{
		acronym: 'CAR - Corrective Action Report',
		definition:
			'CAR documents steps taken to address security issues.\n\nPurpose: Ensures proper documentation and tracking of security incident remediation.\nDeployment: Generated after incidents, audits, or compliance reviews.\nContext: Essential in incident response and compliance documentation.',
	},
	{
		acronym: 'CASB - Cloud Access Security Broker',
		definition:
			'CASB provides security controls between users and cloud services.\n\nPurpose: Enforces security policies across multiple cloud services and providers.\nDeployment: Implemented as cloud-based or on-premises solution with API integration.\nContext: Critical for organizations using multiple cloud services and requiring unified security.',
	},
	{
		acronym: 'CBC - Cipher Block Chaining',
		definition:
			'CBC is an encryption mode providing better security through chaining.\n\nPurpose: Enhances encryption security by linking blocks of ciphertext.\nDeployment: Used in protocols like TLS and file encryption systems.\nContext: Common in secure communications and data protection.',
	},
	{
		acronym: 'CCMP - Counter Mode/CBC-MAC Protocol',
		definition:
			'CCMP is a robust security protocol for wireless networks.\n\nPurpose: Provides both encryption and authentication for wireless data.\nDeployment: Implemented in WPA2/WPA3 for securing wireless networks.\nContext: Standard protocol in modern wireless network security.',
	},
	{
		acronym: 'CCTV - Closed-Circuit Television',
		definition:
			'CCTV provides video surveillance for physical security.\n\nPurpose: Monitors and records activity for security and investigation.\nDeployment: Installed with digital recording systems and network connectivity.\nContext: Essential component of physical security and monitoring.',
	},
	{
		acronym: 'CERT - Computer Emergency Response Team',
		definition:
			'CERT manages cybersecurity incidents and responses.\n\nPurpose: Coordinates responses to security incidents and provides guidance.\nDeployment: Established at organizational, national, or sector levels.\nContext: Critical for incident response and security coordination.',
	},
	{
		acronym: 'CFB - Cipher Feedback',
		definition:
			'CFB is a block cipher mode enabling stream-like encryption.\n\nPurpose: Allows encryption of data in smaller units than block size.\nDeployment: Used in applications requiring real-time encryption.\nContext: Found in secure communication systems and data streams.',
	},
	{
		acronym: 'CHAP - Challenge Handshake Authentication Protocol',
		definition:
			'CHAP provides secure authentication through challenges.\n\nPurpose: Verifies identity without transmitting passwords directly.\nDeployment: Implemented in network authentication systems, especially PPP.\nContext: Used in network access and remote authentication scenarios.',
	},
	{
		acronym: 'CIA - Confidentiality, Integrity, Availability',
		definition:
			'CIA represents core principles of information security.\n\nPurpose: Provides framework for comprehensive security controls.\nDeployment: Applied across all security policies and controls.\nContext: Fundamental to all security programs and compliance efforts.',
	},
	{
		acronym: 'CIO - Chief Information Officer',
		definition:
			'CIO oversees organizational IT strategy and operations.\n\nPurpose: Ensures alignment of IT and security with business objectives.\nDeployment: Executive position working with CISO and other leaders.\nContext: Critical role in security governance and strategy.',
	},
	{
		acronym: 'CIRT - Computer Incident Response Team',
		definition:
			'CIRT handles cybersecurity incidents and responses.\n\nPurpose: Provides organized approach to security incident management.\nDeployment: Established with defined procedures and tools.\nContext: Essential for effective incident response and recovery.',
	},
	{
		acronym: 'CMS - Content Management System',
		definition:
			'CMS manages digital content with security controls.\n\nPurpose: Enables secure content creation and management.\nDeployment: Implemented with access controls and security features.\nContext: Common in web applications requiring content security.',
	},
	{
		acronym: 'COOP - Continuity of Operations Planning',
		definition:
			'COOP ensures critical operations continue during disruptions.\n\nPurpose: Maintains essential functions during and after incidents.\nDeployment: Documented plans with regular testing and updates.\nContext: Critical for organizational resilience and recovery.',
	},
	{
		acronym: 'COPE - Corporate Owned, Personally Enabled',
		definition:
			'COPE is a mobile device management strategy.\n\nPurpose: Balances security control with personal use flexibility.\nDeployment: Implemented through MDM systems and policies.\nContext: Alternative to BYOD in security-conscious organizations.',
	},
	{
		acronym: 'CRC - Cyclical Redundancy Check',
		definition:
			'CRC detects accidental changes to raw data.\n\nPurpose: Ensures data integrity during transmission or storage.\nDeployment: Implemented in network protocols and storage systems.\nContext: Basic error detection in data communications.',
	},
	{
		acronym: 'CRL - Certificate Revocation List',
		definition:
			'CRL lists revoked digital certificates.\n\nPurpose: Identifies and blocks use of compromised certificates.\nDeployment: Published by CAs and checked during certificate validation.\nContext: Critical component of PKI and certificate management.',
	},
	{
		acronym: 'CSO - Chief Security Officer',
		definition:
			'CSO leads organizational security strategy.\n\nPurpose: Ensures comprehensive security across physical and digital domains.\nDeployment: Executive position overseeing all security operations.\nContext: Key role in security leadership and governance.',
	},
	{
		acronym: 'CSP - Cloud Service Provider',
		definition:
			'CSP delivers cloud computing services.\n\nPurpose: Provides scalable computing resources with security controls.\nDeployment: Offers IaaS, PaaS, or SaaS with security features.\nContext: Major component of modern IT infrastructure.',
	},
	{
		acronym: 'CSR - Certificate Signing Request',
		definition:
			'CSR requests issuance of digital certificate.\n\nPurpose: Initiates secure certificate issuance process.\nDeployment: Generated during SSL/TLS certificate requests.\nContext: Essential in PKI and secure communications setup.',
	},
	{
		acronym: 'CSRF - Cross-site Request Forgery',
		definition:
			'CSRF is a web security vulnerability exploiting trust.\n\nPurpose: Attacks leverage authenticated user sessions.\nDeployment: Prevented through tokens and request validation.\nContext: Common web application security concern.',
	},
	{
		acronym: 'CSU - Channel Service Unit',
		definition:
			'CSU interfaces between digital equipment and transmission lines.\n\nPurpose: Ensures secure and proper signal transmission.\nDeployment: Installed at network boundaries and carrier connections.\nContext: Found in telecommunications infrastructure.',
	},
	{
		acronym: 'CTM - Counter Mode',
		definition:
			'CTM is an encryption mode providing parallelization.\n\nPurpose: Enables efficient encryption of data blocks.\nDeployment: Used in high-performance encryption systems.\nContext: Found in secure communications requiring speed.',
	},
	{
		acronym: 'CTO - Chief Technology Officer',
		definition:
			'CTO leads technology strategy and innovation.\n\nPurpose: Ensures security in technology development and adoption.\nDeployment: Executive position working with security leadership.\nContext: Key role in secure technology implementation.',
	},
	{
		acronym: 'CVE - Common Vulnerabilities and Exposures',
		definition:
			'CVE is a standardized system for identifying and tracking security vulnerabilities.\n\nPurpose: Provides unique identifiers for known vulnerabilities to facilitate sharing and remediation.\nDeployment: Used in vulnerability management systems, security advisories, and patch management.\nContext: Essential for vulnerability tracking, reporting, and coordinated response.',
	},
	{
		acronym: 'CVSS - Common Vulnerability Scoring System',
		definition:
			'CVSS provides standardized vulnerability severity scores.\n\nPurpose: Enables consistent assessment and prioritization of vulnerabilities.\nDeployment: Used in vulnerability management tools and security reports.\nContext: Critical for risk assessment and remediation planning.',
	},
	{
		acronym: 'CYOD - Choose Your Own Device',
		definition:
			'CYOD is a managed device program with user choice.\n\nPurpose: Balances user preference with organizational security control.\nDeployment: Implemented through MDM with pre-approved device list.\nContext: Alternative to BYOD offering better security control.',
	},
	{
		acronym: 'DAC - Discretionary Access Control',
		definition:
			'DAC allows resource owners to control access permissions.\n\nPurpose: Provides flexible access control based on owner discretion.\nDeployment: Implemented in operating systems and file systems.\nContext: Common in commercial operating systems and applications.',
	},
	{
		acronym: 'DBA - Database Administrator',
		definition:
			'DBA manages database security and operations.\n\nPurpose: Ensures database security, integrity, and availability.\nDeployment: Works with security teams on database controls and monitoring.\nContext: Critical role in data security and compliance.',
	},
	{
		acronym: 'DDoS - Distributed Denial of Service',
		definition:
			'DDoS attacks use multiple sources to overwhelm targets.\n\nPurpose: Disrupts service availability through coordinated attacks.\nDeployment: Mitigated through DDoS protection services and network controls.\nContext: Common threat requiring specific defense strategies.',
	},
	{
		acronym: 'DEP - Data Execution Prevention',
		definition:
			'DEP prevents code execution from non-executable memory.\n\nPurpose: Prevents certain types of memory exploitation attacks.\nDeployment: Implemented at OS level and supported by hardware.\nContext: Important protection against buffer overflow attacks.',
	},
	{
		acronym: 'DES - Digital Encryption Standard',
		definition:
			'DES is a legacy symmetric encryption algorithm.\n\nPurpose: Provided data encryption (now considered insecure).\nDeployment: Largely replaced by AES, but still found in legacy systems.\nContext: Historical importance in encryption development.',
	},
	{
		acronym: 'DHCP - Dynamic Host Configuration Protocol',
		definition:
			'DHCP automates IP address assignment and network configuration.\n\nPurpose: Enables automated network configuration while requiring security controls.\nDeployment: Implemented with DHCP snooping and authentication.\nContext: Essential network service requiring protection.',
	},
	{
		acronym: 'DHE - Diffie-Hellman Ephemeral',
		definition:
			'DHE enables secure key exchange with perfect forward secrecy.\n\nPurpose: Provides secure key exchange that protects past communications.\nDeployment: Used in TLS and other secure protocols.\nContext: Important for secure communications requiring forward secrecy.',
	},
	{
		acronym: 'DKIM - DomainKeys Identified Mail',
		definition:
			'DKIM authenticates email sender and message integrity.\n\nPurpose: Prevents email spoofing and verifies message authenticity.\nDeployment: Implemented through DNS records and email server configuration.\nContext: Part of modern email security infrastructure.',
	},
	{
		acronym: 'DLL - Dynamic Link Library',
		definition:
			'DLL contains shared code and data for multiple programs.\n\nPurpose: Enables code reuse while presenting security considerations.\nDeployment: Protected through DLL signing and secure loading practices.\nContext: Common attack vector requiring security controls.',
	},
	{
		acronym: 'DLP - Data Loss Prevention',
		definition:
			'DLP prevents unauthorized data exfiltration.\n\nPurpose: Protects sensitive data from unauthorized access and transfer.\nDeployment: Implemented at network, endpoint, and cloud levels.\nContext: Critical for data security and compliance.',
	},
	{
		acronym: 'DMARC - Domain Message Authentication Reporting and Conformance',
		definition:
			'DMARC extends email authentication protocols.\n\nPurpose: Provides comprehensive email authentication and reporting.\nDeployment: Configured through DNS with SPF and DKIM.\nContext: Advanced email security standard.',
	},
	{
		acronym: 'DNAT - Destination Network Address Translation',
		definition:
			'DNAT modifies destination addresses in packet headers.\n\nPurpose: Enables secure internal service access from external networks.\nDeployment: Configured on firewalls and security gateways.\nContext: Used in network security architecture.',
	},
	{
		acronym: 'DNS - Domain Name System',
		definition:
			'DNS translates domain names to IP addresses.\n\nPurpose: Enables user-friendly network addressing while requiring security.\nDeployment: Secured through DNSSEC, filtering, and monitoring.\nContext: Critical internet infrastructure requiring protection.',
	},
	{
		acronym: 'DoS - Denial of Service',
		definition:
			'DoS attacks disrupt service availability.\n\nPurpose: Attempts to make resources unavailable to legitimate users.\nDeployment: Mitigated through traffic analysis and filtering.\nContext: Common attack requiring specific defenses.',
	},
	{
		acronym: 'DPO - Data Privacy Officer',
		definition:
			'DPO oversees data privacy compliance and protection.\n\nPurpose: Ensures organizational compliance with privacy regulations.\nDeployment: Required by regulations like GDPR in many organizations.\nContext: Critical role in privacy and compliance.',
	},
	{
		acronym: 'DRP - Disaster Recovery Plan',
		definition:
			'DRP defines procedures for system recovery after disasters.\n\nPurpose: Ensures business continuity and data recovery capabilities.\nDeployment: Documented procedures with regular testing and updates.\nContext: Essential for business continuity and resilience.',
	},
	{
		acronym: 'DSA - Digital Signature Algorithm',
		definition:
			'DSA creates and verifies digital signatures.\n\nPurpose: Provides authentication and non-repudiation for documents.\nDeployment: Implemented in PKI systems and security applications.\nContext: Used in secure document signing and verification.',
	},
	{
		acronym: 'DSL - Digital Subscriber Line',
		definition:
			'DSL provides digital data transmission over telephone lines.\n\nPurpose: Enables broadband internet access requiring security controls.\nDeployment: Implemented with authentication and encryption.\nContext: Common internet access method needing protection.',
	},
	{
		acronym: 'EAP - Extensible Authentication Protocol',
		definition:
			'EAP provides a framework for various authentication methods.\n\nPurpose: Enables flexible, secure network authentication.\nDeployment: Used in wireless and network access security.\nContext: Foundation for secure network access control.',
	},
	{
		acronym: 'ECB - Electronic Code Book',
		definition:
			'ECB is a basic block cipher mode of operation.\n\nPurpose: Provides basic encryption but with security limitations.\nDeployment: Generally avoided due to security weaknesses.\nContext: Teaching example of why advanced modes are needed.',
	},
	{
		acronym: 'ECC - Elliptic Curve Cryptography',
		definition:
			'ECC uses elliptic curves for cryptographic operations.\n\nPurpose: Provides strong encryption with smaller key sizes.\nDeployment: Used in modern cryptographic systems and protocols.\nContext: Advanced cryptography for resource-constrained systems.',
	},
	{
		acronym: 'ECDSA - Elliptic Curve Digital Signature Algorithm',
		definition:
			'ECDSA applies ECC to digital signatures.\n\nPurpose: Provides efficient digital signatures with strong security.\nDeployment: Used in TLS, cryptocurrency, and secure communications.\nContext: Modern alternative to traditional DSA.',
	},
	{
		acronym: 'EDR - Endpoint Detection and Response',
		definition:
			'EDR provides advanced endpoint threat detection and response.\n\nPurpose: Monitors endpoints for threats and enables rapid incident response.\nDeployment: Installed on endpoints with centralized management console.\nContext: Critical in modern security architecture for threat detection and response.',
	},
	{
		acronym: 'EFS - Encrypted File System',
		definition:
			'EFS provides file-level encryption in Windows systems.\n\nPurpose: Protects sensitive files through transparent encryption.\nDeployment: Enabled per file/folder with recovery agent support.\nContext: Used for protecting sensitive data on Windows systems.',
	},
	{
		acronym: 'ERP - Enterprise Resource Planning',
		definition:
			'ERP systems integrate core business processes.\n\nPurpose: Centralizes business operations while requiring comprehensive security.\nDeployment: Implemented with role-based access and security controls.\nContext: Critical business systems requiring strong security measures.',
	},
	{
		acronym: 'ESN - Electronic Serial Number',
		definition:
			'ESN uniquely identifies mobile devices.\n\nPurpose: Enables device authentication and tracking in mobile networks.\nDeployment: Embedded in mobile devices during manufacturing.\nContext: Used in mobile device security and management.',
	},
	{
		acronym: 'ESP - Encapsulating Security Payload',
		definition:
			'ESP provides encryption and authentication in IPsec.\n\nPurpose: Ensures confidentiality and integrity of IP packets.\nDeployment: Configured in IPsec implementations with encryption.\nContext: Core component of VPN and secure network communications.',
	},
	{
		acronym: 'FACL - File System Access Control List',
		definition:
			'FACL provides granular file permissions.\n\nPurpose: Enables detailed access control for files and directories.\nDeployment: Configured at file system level with specific permissions.\nContext: Used in Unix/Linux systems for precise access control.',
	},
	{
		acronym: 'FDE - Full Disk Encryption',
		definition:
			'FDE encrypts entire storage devices.\n\nPurpose: Protects all data on storage devices from unauthorized access.\nDeployment: Implemented through software or hardware encryption.\nContext: Essential for protecting data on mobile devices and laptops.',
	},
	{
		acronym: 'FIM - File Integrity Monitoring',
		definition:
			'FIM tracks changes to critical files and systems.\n\nPurpose: Detects unauthorized modifications to important files.\nDeployment: Implemented through monitoring tools with baselines.\nContext: Critical for compliance and security monitoring.',
	},
	{
		acronym: 'FPGA - Field Programmable Gate Array',
		definition:
			'FPGA is a configurable integrated circuit.\n\nPurpose: Enables hardware-level security implementations.\nDeployment: Used in custom security hardware solutions.\nContext: Found in specialized security applications and devices.',
	},
	{
		acronym: 'FRR - False Rejection Rate',
		definition:
			'FRR measures biometric authentication accuracy.\n\nPurpose: Quantifies legitimate users incorrectly rejected.\nDeployment: Used in biometric system configuration and testing.\nContext: Important metric in biometric security systems.',
	},
	{
		acronym: 'FTP - File Transfer Protocol',
		definition:
			'FTP transfers files between systems.\n\nPurpose: Enables file transfer while requiring security considerations.\nDeployment: Should be replaced by SFTP/FTPS for security.\nContext: Legacy protocol requiring secure alternatives.',
	},
	{
		acronym: 'FTPS - File Transfer Protocol Secure',
		definition:
			'FTPS adds SSL/TLS security to FTP.\n\nPurpose: Provides secure file transfer with encryption.\nDeployment: Implemented with SSL/TLS certificates and authentication.\nContext: Secure alternative to standard FTP.',
	},
	{
		acronym: 'GCM - Galois Counter Mode',
		definition:
			'GCM provides authenticated encryption.\n\nPurpose: Combines encryption and authentication efficiently.\nDeployment: Used in TLS and other secure protocols.\nContext: Modern encryption mode for secure communications.',
	},
	{
		acronym: 'GDPR - General Data Protection Regulation',
		definition:
			'GDPR enforces data protection and privacy in EU.\n\nPurpose: Protects individual privacy rights and data.\nDeployment: Requires specific security and privacy controls.\nContext: Major privacy regulation affecting global operations.',
	},
	{
		acronym: 'GPG - GNU Privacy Guard',
		definition:
			'GPG implements OpenPGP standard for encryption.\n\nPurpose: Provides encryption and digital signatures.\nDeployment: Used for secure email and file encryption.\nContext: Open-source tool for cryptographic operations.',
	},
	{
		acronym: 'GPO - Group Policy Object',
		definition:
			'GPO manages Windows domain security policies.\n\nPurpose: Enables centralized security policy management.\nDeployment: Configured in Active Directory environments.\nContext: Critical for Windows domain security management.',
	},
	{
		acronym: 'GPS - Global Positioning System',
		definition:
			'GPS provides location and timing information.\n\nPurpose: Enables location-based security services.\nDeployment: Used in device tracking and geofencing.\nContext: Component in mobile device security.',
	},
	{
		acronym: 'GPU - Graphics Processing Unit',
		definition:
			'GPU processes graphics and parallel computations.\n\nPurpose: Can be used for cryptographic operations or attacks.\nDeployment: Considered in cryptographic system design.\nContext: Relevant for cryptographic processing and attacks.',
	},
	{
		acronym: 'GRE - Generic Routing Encapsulation',
		definition:
			'GRE tunnels network protocols.\n\nPurpose: Enables secure tunneling of various protocols.\nDeployment: Configured on routers and security gateways.\nContext: Used in VPN and secure networking.',
	},
	{
		acronym: 'HA - High Availability',
		definition:
			'HA ensures continuous system operation.\n\nPurpose: Maintains service availability through redundancy.\nDeployment: Implemented through clustered systems and failover.\nContext: Critical for maintaining security service uptime.',
	},
	{
		acronym: 'HDD - Hard Disk Drive',
		definition:
			'HDD stores data magnetically.\n\nPurpose: Provides data storage requiring security controls.\nDeployment: Protected through encryption and secure erasure.\nContext: Common storage requiring security measures.',
	},
	{
		acronym: 'HIDS - Host-based Intrusion Detection System',
		definition:
			'HIDS monitors host systems for threats.\n\nPurpose: Detects malicious activities on individual hosts.\nDeployment: Installed on critical servers and systems.\nContext: Important component of endpoint security.',
	},
	{
		acronym: 'HIPS - Host-based Intrusion Prevention System',
		definition:
			'HIPS actively prevents host-based attacks.\n\nPurpose: Blocks malicious activities on individual hosts.\nDeployment: Installed with active prevention rules.\nContext: Advanced endpoint protection technology.',
	},
	{
		acronym: 'HMAC - Hash-based Message Authentication Code',
		definition:
			"HMAC verifies message integrity and authenticity.\n\nPurpose: Ensures messages haven't been tampered with.\nDeployment: Used in secure communications protocols.\nContext: Critical for secure data transmission.",
	},
	{
		acronym: 'HOTP - HMAC-based One-Time Password',
		definition:
			'HOTP generates secure one-time passwords.\n\nPurpose: Provides strong authentication through changing passwords.\nDeployment: Implemented in multi-factor authentication systems.\nContext: Used in secure access control systems.',
	},
	{
		acronym: 'HSM - Hardware Security Module',
		definition:
			'HSM is a physical device for secure cryptographic operations.\n\nPurpose: Provides secure key storage and cryptographic operations.\nDeployment: Implemented in data centers and security infrastructure.\nContext: Critical for protecting cryptographic keys and operations.',
	},
	{
		acronym: 'HTML - Hypertext Markup Language',
		definition:
			'HTML structures web content with security implications.\n\nPurpose: Delivers web content while requiring security controls.\nDeployment: Secured against XSS and injection attacks.\nContext: Foundation of web applications requiring security measures.',
	},
	{
		acronym: 'HTTP - Hypertext Transfer Protocol',
		definition:
			'HTTP enables web communication.\n\nPurpose: Facilitates web traffic while requiring security controls.\nDeployment: Should be secured with TLS (HTTPS).\nContext: Basic web protocol requiring security enhancement.',
	},
	{
		acronym: 'HTTPS - Hypertext Transfer Protocol Secure',
		definition:
			'HTTPS encrypts web communications.\n\nPurpose: Protects web traffic through encryption and authentication.\nDeployment: Implemented with TLS certificates and proper configuration.\nContext: Standard for secure web communications.',
	},
	{
		acronym: 'HVAC - Heating, Ventilation, and Air Conditioning',
		definition:
			'HVAC systems affect physical security and operations.\n\nPurpose: Maintains environmental conditions while presenting security concerns.\nDeployment: Secured against cyber-physical attacks.\nContext: Critical infrastructure requiring protection.',
	},
	{
		acronym: 'IaaS - Infrastructure as a Service',
		definition:
			'IaaS provides virtualized computing infrastructure.\n\nPurpose: Delivers scalable infrastructure while requiring security controls.\nDeployment: Implemented with cloud security controls and monitoring.\nContext: Cloud service model with shared security responsibility.',
	},
	{
		acronym: 'IaC - Infrastructure as Code',
		definition:
			'IaC automates infrastructure deployment.\n\nPurpose: Ensures consistent, secure infrastructure deployment.\nDeployment: Implemented with security controls in code.\nContext: Modern approach to secure infrastructure management.',
	},
	{
		acronym: 'IAM - Identity and Access Management',
		definition:
			'IAM controls access to resources.\n\nPurpose: Manages identities and access rights securely.\nDeployment: Implemented through directory services and access control systems.\nContext: Fundamental to organizational security.',
	},
	{
		acronym: 'ICMP - Internet Control Message Protocol',
		definition:
			'ICMP manages network diagnostics and errors.\n\nPurpose: Enables network troubleshooting while requiring security controls.\nDeployment: Often restricted at firewalls due to potential abuse.\nContext: Network protocol requiring security consideration.',
	},
	{
		acronym: 'ICS - Industrial Control Systems',
		definition:
			'ICS manages industrial processes.\n\nPurpose: Controls industrial operations while requiring specialized security.\nDeployment: Protected through air-gapping and specific security controls.\nContext: Critical infrastructure requiring robust protection.',
	},
	{
		acronym: 'IDEA - International Data Encryption Algorithm',
		definition:
			'IDEA is a symmetric block cipher.\n\nPurpose: Provides data encryption with historical significance.\nDeployment: Used in legacy systems, largely replaced by AES.\nContext: Historical encryption algorithm with limited modern use.',
	},
	{
		acronym: 'IDF - Intermediate Distribution Frame',
		definition:
			'IDF connects telecommunications equipment.\n\nPurpose: Provides network connectivity while requiring physical security.\nDeployment: Secured in locked rooms with access controls.\nContext: Network infrastructure requiring protection.',
	},
	{
		acronym: 'IdP - Identity Provider',
		definition:
			'IdP manages authentication and identity information.\n\nPurpose: Centralizes identity management and authentication.\nDeployment: Implemented for SSO and federated identity.\nContext: Critical for modern authentication systems.',
	},
	{
		acronym: 'IDS - Intrusion Detection System',
		definition:
			'IDS monitors for security threats.\n\nPurpose: Detects potential security incidents and attacks.\nDeployment: Implemented at network and host levels.\nContext: Essential security monitoring tool.',
	},
	{
		acronym: 'IEEE - Institute of Electrical and Electronics Engineers',
		definition:
			'IEEE develops technical standards.\n\nPurpose: Creates standards for secure technology implementation.\nDeployment: Standards implemented in various technologies.\nContext: Important for security standardization.',
	},
	{
		acronym: 'IKE - Internet Key Exchange',
		definition:
			'IKE manages security associations and keys.\n\nPurpose: Establishes secure communication channels in IPsec.\nDeployment: Implemented in VPN and secure networking.\nContext: Critical for VPN and secure communications.',
	},
	{
		acronym: 'IM - Instant Messaging',
		definition:
			'IM enables real-time communication.\n\nPurpose: Provides communication while requiring security controls.\nDeployment: Secured through encryption and authentication.\nContext: Common communication tool requiring protection.',
	},
	{
		acronym: 'IMAP - Internet Message Access Protocol',
		definition:
			'IMAP enables email access and management.\n\nPurpose: Provides email access while requiring security measures.\nDeployment: Secured with TLS and authentication.\nContext: Email protocol requiring protection.',
	},
	{
		acronym: 'IoC - Indicators of Compromise',
		definition:
			'IoC identifies security incidents.\n\nPurpose: Helps detect and respond to security incidents.\nDeployment: Used in security monitoring and incident response.\nContext: Critical for threat detection and response.',
	},
	{
		acronym: 'IoT - Internet of Things',
		definition:
			'IoT connects everyday devices to networks.\n\nPurpose: Enables device connectivity while requiring security.\nDeployment: Protected through network segmentation and security controls.\nContext: Growing attack surface requiring protection.',
	},
	{
		acronym: 'IP - Internet Protocol',
		definition:
			'IP routes data across networks.\n\nPurpose: Enables network communication while requiring security.\nDeployment: Secured through various network security controls.\nContext: Foundation of internet requiring protection.',
	},
	{
		acronym: 'IPS - Intrusion Prevention System',
		definition:
			'IPS blocks detected security threats.\n\nPurpose: Actively prevents detected security incidents.\nDeployment: Implemented inline with traffic flow.\nContext: Active security defense system.',
	},
	{
		acronym: 'IPSec - Internet Protocol Security',
		definition:
			'IPSec secures IP communications.\n\nPurpose: Provides encryption and authentication for IP traffic.\nDeployment: Implemented in VPNs and secure networking.\nContext: Standard for network layer security.',
	},
	{
		acronym: 'IR - Incident Response',
		definition:
			'IR manages security incidents.\n\nPurpose: Provides organized approach to security incidents.\nDeployment: Implemented through plans and trained teams.\nContext: Critical for security incident management.',
	},
	{
		acronym: 'IRC - Internet Relay Chat',
		definition:
			'IRC enables group text communication.\n\nPurpose: Provides chat functionality while requiring security.\nDeployment: Secured through encryption and authentication.\nContext: Legacy chat protocol requiring protection.',
	},
	{
		acronym: 'IRP - Incident Response Plan',
		definition:
			'IRP defines incident handling procedures.\n\nPurpose: Provides structured approach to security incidents.\nDeployment: Documented and tested with regular updates.\nContext: Essential for effective incident management.',
	},
	{
		acronym: 'ISO - International Standards Organization',
		definition:
			'ISO develops international standards.\n\nPurpose: Creates standards for security implementation.\nDeployment: Standards implemented across organizations.\nContext: Key for security standardization and compliance.',
	},
	{
		acronym: 'ISP - Internet Service Provider',
		definition:
			'ISP provides internet connectivity.\n\nPurpose: Delivers internet access with security considerations.\nDeployment: Implements network security controls.\nContext: Critical infrastructure requiring security measures.',
	},
	{
		acronym: 'ISSO - Information Systems Security Officer',
		definition:
			'ISSO manages system security.\n\nPurpose: Ensures system-level security compliance.\nDeployment: Assigned to specific systems or areas.\nContext: Key role in system security management.',
	},
	{
		acronym: 'IV - Initialization Vector',
		definition:
			'IV provides randomness in encryption.\n\nPurpose: Ensures unique encryption results for identical data.\nDeployment: Used in encryption algorithms and protocols.\nContext: Critical for secure encryption implementation.',
	},
	{
		acronym: 'KDC - Key Distribution Center',
		definition:
			'KDC manages cryptographic keys.\n\nPurpose: Provides secure key distribution in authentication.\nDeployment: Central component in Kerberos authentication.\nContext: Critical for secure authentication systems.',
	},
	{
		acronym: 'KEK - Key Encryption Key',
		definition:
			'KEK protects other encryption keys.\n\nPurpose: Secures storage and transmission of other keys.\nDeployment: Used in key management systems.\nContext: Important for key hierarchy security.',
	},
	{
		acronym: 'L2TP - Layer 2 Tunneling Protocol',
		definition:
			'L2TP creates network tunnels.\n\nPurpose: Enables VPN connectivity with IPSec security.\nDeployment: Implemented in VPN solutions.\nContext: VPN protocol requiring additional security.',
	},
	{
		acronym: 'LAN - Local Area Network',
		definition:
			'LAN connects local devices.\n\nPurpose: Provides local connectivity requiring security.\nDeployment: Secured through various network controls.\nContext: Basic network requiring protection.',
	},
	{
		acronym: 'LDAP - Lightweight Directory Access Protocol',
		definition:
			'LDAP manages directory information.\n\nPurpose: Provides directory services with authentication.\nDeployment: Implemented with security controls and encryption.\nContext: Critical for enterprise authentication.',
	},
	{
		acronym: 'LEAP - Lightweight Extensible Authentication Protocol',
		definition:
			'LEAP is a wireless authentication protocol.\n\nPurpose: Provides wireless authentication (now considered insecure).\nDeployment: Legacy protocol replaced by more secure options.\nContext: Historical example of deprecated security.',
	},
	{
		acronym: 'MaaS - Monitoring as a Service',
		definition:
			'MaaS provides cloud-based monitoring.\n\nPurpose: Enables security monitoring and alerting.\nDeployment: Implemented through cloud service providers.\nContext: Modern approach to security monitoring.',
	},
	{
		acronym: 'MAC - Mandatory Access Control',
		definition:
			'MAC enforces system-defined access control.\n\nPurpose: Provides strict, system-enforced access control.\nDeployment: Implemented in high-security systems.\nContext: Strong access control mechanism.',
	},
	{
		acronym: 'MAC - Media Access Control',
		definition:
			'MAC uniquely identifies network interfaces.\n\nPurpose: Enables device identification on networks.\nDeployment: Used in network security controls.\nContext: Important for network security.',
	},
	{
		acronym: 'MAC - Message Authentication Code',
		definition:
			'MAC verifies message integrity.\n\nPurpose: Ensures message authenticity and integrity.\nDeployment: Used in secure communications protocols.\nContext: Critical for secure messaging.',
	},
	{
		acronym: 'MAN - Metropolitan Area Network',
		definition:
			'MAN connects city-wide networks.\n\nPurpose: Provides regional connectivity requiring security.\nDeployment: Secured through various network controls.\nContext: Large network requiring protection.',
	},
	{
		acronym: 'MBR - Master Boot Record',
		definition:
			'MBR contains boot and partition information.\n\nPurpose: Enables system boot while requiring protection.\nDeployment: Secured against boot sector malware.\nContext: Critical system component requiring security.',
	},
	{
		acronym: 'MD5 - Message Digest 5',
		definition:
			'MD5 is a cryptographic hash function.\n\nPurpose: Creates message digests (now considered insecure).\nDeployment: Legacy hash function replaced by secure alternatives.\nContext: Example of deprecated cryptographic algorithm.',
	},
	{
		acronym: 'MDF - Main Distribution Frame',
		definition:
			'MDF centralizes telecommunications connections.\n\nPurpose: Provides central connection point requiring security.\nDeployment: Secured through physical and access controls.\nContext: Critical infrastructure requiring protection.',
	},
	{
		acronym: 'MDM - Mobile Device Management',
		definition:
			'MDM controls mobile device security.\n\nPurpose: Manages security of organizational mobile devices.\nDeployment: Implemented through MDM platforms and policies.\nContext: Essential for mobile device security.',
	},
	{
		acronym: 'MFA - Multi-Factor Authentication',
		definition:
			'MFA requires multiple authentication factors.\n\nPurpose: Strengthens authentication through multiple verifications.\nDeployment: Implemented using various authentication methods.\nContext: Critical modern security control.',
	},
	{
		acronym: 'MFD - Multi-Function Device',
		definition:
			'MFD combines multiple office functions.\n\nPurpose: Provides multiple services requiring security controls.\nDeployment: Secured through access controls and encryption.\nContext: Common office equipment requiring protection.',
	},
	{
		acronym: 'MFP - Multi-Function Printer',
		definition:
			'MFP combines printing with other functions.\n\nPurpose: Provides multiple services requiring security.\nDeployment: Protected through access controls and encryption.\nContext: Office equipment requiring security measures.',
	},
	{
		acronym: 'ML - Machine Learning',
		definition:
			'ML enables automated pattern recognition.\n\nPurpose: Enhances security through automated analysis.\nDeployment: Implemented in security tools and monitoring.\nContext: Advanced technology for security analytics.',
	},
	{
		acronym: 'MMS - Multimedia Message Service',
		definition:
			'MMS enables rich mobile messaging.\n\nPurpose: Provides multimedia messaging requiring security.\nDeployment: Secured through mobile network controls.\nContext: Mobile service requiring protection.',
	},
	{
		acronym: 'MOA - Memorandum of Agreement',
		definition:
			'MOA formally defines security responsibilities between parties.\n\nPurpose: Establishes binding security obligations and requirements.\nDeployment: Documented and signed before sharing sensitive resources.\nContext: Critical for multi-party security arrangements.',
	},
	{
		acronym: 'MOU - Memorandum of Understanding',
		definition:
			'MOU outlines intended security collaboration.\n\nPurpose: Documents non-binding security arrangements and intentions.\nDeployment: Used in initial stages of security partnerships.\nContext: Precursor to formal security agreements.',
	},
	{
		acronym: 'MPLS - Multi-protocol Label Switching',
		definition:
			'MPLS directs data through network paths.\n\nPurpose: Enables efficient, secure data routing in networks.\nDeployment: Implemented in service provider networks with security controls.\nContext: Enterprise networking technology requiring protection.',
	},
	{
		acronym: 'MSA - Master Service Agreement',
		definition:
			'MSA defines long-term service relationships.\n\nPurpose: Establishes security requirements for ongoing services.\nDeployment: Negotiated with security provisions and controls.\nContext: Foundation for secure service relationships.',
	},
	{
		acronym: 'MSCHAP - Microsoft Challenge Handshake Authentication Protocol',
		definition:
			'MSCHAP authenticates users in Microsoft networks.\n\nPurpose: Provides secure authentication for network access.\nDeployment: Used in Windows domains and VPN services.\nContext: Microsoft-specific authentication protocol.',
	},
	{
		acronym: 'MSP - Managed Service Provider',
		definition:
			'MSP manages IT services and security.\n\nPurpose: Provides outsourced IT and security management.\nDeployment: Operates under security agreements and standards.\nContext: Third-party security service provider.',
	},
	{
		acronym: 'MSSP - Managed Security Service Provider',
		definition:
			'MSSP provides specialized security services.\n\nPurpose: Delivers dedicated security monitoring and management.\nDeployment: Operates security operations centers and tools.\nContext: Specialized security service provider.',
	},
	{
		acronym: 'MTBF - Mean Time Between Failures',
		definition:
			'MTBF measures system reliability.\n\nPurpose: Quantifies system stability and availability.\nDeployment: Used in system design and maintenance planning.\nContext: Important for security system reliability.',
	},
	{
		acronym: 'MTTF - Mean Time to Failure',
		definition:
			'MTTF predicts system failure timing.\n\nPurpose: Helps plan security system maintenance.\nDeployment: Used in security infrastructure planning.\nContext: Critical for security system maintenance.',
	},
	{
		acronym: 'MTTR - Mean Time to Recover',
		definition:
			'MTTR measures system recovery speed.\n\nPurpose: Quantifies incident recovery capabilities.\nDeployment: Used in disaster recovery planning.\nContext: Key metric for incident response.',
	},
	{
		acronym: 'MTU - Maximum Transmission Unit',
		definition:
			'MTU defines largest packet size.\n\nPurpose: Optimizes network performance and security.\nDeployment: Configured in network devices and security tools.\nContext: Network parameter affecting security.',
	},
	{
		acronym: 'NAC - Network Access Control',
		definition:
			'NAC enforces network connection security.\n\nPurpose: Controls device access to networks based on security policy.\nDeployment: Implemented through NAC platforms and policies.\nContext: Critical for secure network access.',
	},
	{
		acronym: 'NAT - Network Address Translation',
		definition:
			'NAT maps private to public IP addresses.\n\nPurpose: Provides address privacy and conservation.\nDeployment: Configured on firewalls and routers.\nContext: Basic network security mechanism.',
	},
	{
		acronym: 'NDA - Non-disclosure Agreement',
		definition:
			'NDA protects sensitive information.\n\nPurpose: Legally binds parties to maintain confidentiality.\nDeployment: Signed before sharing sensitive information.\nContext: Legal security control measure.',
	},
	{
		acronym: 'NFC - Near Field Communication',
		definition:
			'NFC enables short-range wireless communication.\n\nPurpose: Provides secure short-range data exchange.\nDeployment: Used in mobile payments and access control.\nContext: Proximity-based security technology.',
	},
	{
		acronym: 'NGFW - Next-generation Firewall',
		definition:
			'NGFW provides advanced network protection.\n\nPurpose: Combines traditional firewall with advanced security features.\nDeployment: Implemented at network boundaries with deep inspection.\nContext: Modern network security appliance.',
	},
	{
		acronym: 'NIDS - Network-based Intrusion Detection System',
		definition:
			'NIDS monitors network traffic for threats.\n\nPurpose: Detects network-based attacks and anomalies.\nDeployment: Monitors network segments through sensors.\nContext: Critical network security monitoring tool.',
	},
	{
		acronym: 'NIPS - Network-based Intrusion Prevention System',
		definition:
			'NIPS blocks network-based attacks.\n\nPurpose: Actively prevents detected network attacks.\nDeployment: Inline deployment on network segments.\nContext: Active network defense system.',
	},
	{
		acronym: 'NIST - National Institute of Standards & Technology',
		definition:
			'NIST develops security standards.\n\nPurpose: Provides authoritative security guidance and standards.\nDeployment: Standards implemented across organizations.\nContext: Key source of security best practices.',
	},
	{
		acronym: 'NTFS - New Technology File System',
		definition:
			'NTFS provides secure file system features.\n\nPurpose: Enables file-level security and encryption.\nDeployment: Standard in Windows systems with security features.\nContext: Secure Windows file system.',
	},
	{
		acronym: 'NTLM - New Technology LAN Manager',
		definition:
			'NTLM authenticates in Windows networks.\n\nPurpose: Provides Windows authentication protocol.\nDeployment: Legacy protocol still used in some environments.\nContext: Windows authentication mechanism.',
	},
	{
		acronym: 'NTP - Network Time Protocol',
		definition:
			'NTP synchronizes system time.\n\nPurpose: Ensures accurate timing for security functions.\nDeployment: Implemented with secure NTP servers.\nContext: Critical for security logging and certificates.',
	},
	{
		acronym: 'OAUTH - Open Authorization',
		definition:
			'OAUTH enables secure authorization.\n\nPurpose: Provides secure delegation of resource access.\nDeployment: Implemented in web and mobile applications.\nContext: Standard for API security.',
	},
	{
		acronym: 'OCSP - Online Certificate Status Protocol',
		definition:
			'OCSP verifies certificate validity.\n\nPurpose: Checks digital certificate revocation status.\nDeployment: Used in PKI environments for real-time checks.\nContext: Critical for certificate validation.',
	},
	{
		acronym: 'OID - Object Identifier',
		definition:
			'OID uniquely identifies objects globally.\n\nPurpose: Provides unique identification in security contexts.\nDeployment: Used in certificates and security protocols.\nContext: Important for PKI and security standards.',
	},
	{
		acronym: 'OS - Operating System',
		definition:
			'OS manages hardware and software resources.\n\nPurpose: Provides secure platform for applications and services.\nDeployment: Hardened according to security best practices.\nContext: Foundation of system security.',
	},
	{
		acronym: 'OSINT - Open-source Intelligence',
		definition:
			'OSINT gathers intelligence from public sources.\n\nPurpose: Collects security information from public data.\nDeployment: Used in threat intelligence and investigation.\nContext: Important for threat assessment and research.',
	},
	{
		acronym: 'OSPF - Open Shortest Path First',
		definition:
			'OSPF routes network traffic efficiently.\n\nPurpose: Enables secure and efficient network routing.\nDeployment: Implemented with authentication and encryption.\nContext: Enterprise routing protocol requiring security.',
	},
	{
		acronym: 'OT - Operational Technology',
		definition:
			'OT controls industrial processes.\n\nPurpose: Manages industrial systems with security requirements.\nDeployment: Protected through specialized security controls.\nContext: Critical infrastructure technology.',
	},
	{
		acronym: 'OTA - Over the Air',
		definition:
			'OTA enables wireless updates.\n\nPurpose: Provides secure remote system updates.\nDeployment: Implemented with signing and verification.\nContext: Important for mobile and IoT security.',
	},
	{
		acronym: 'OVAL - Open Vulnerability Assessment Language',
		definition:
			'OVAL standardizes vulnerability assessment.\n\nPurpose: Enables consistent vulnerability testing and reporting.\nDeployment: Used in security assessment tools.\nContext: Standard for vulnerability management.',
	},
	{
		acronym: 'P12 - PKCS #12',
		definition:
			'P12 stores cryptographic objects.\n\nPurpose: Securely stores keys and certificates.\nDeployment: Used in certificate deployment and backup.\nContext: Standard format for certificate storage.',
	},
	{
		acronym: 'P2P - Peer to Peer',
		definition:
			'P2P enables direct device communication.\n\nPurpose: Allows decentralized network communication.\nDeployment: Secured through encryption and authentication.\nContext: Network architecture requiring security controls.',
	},
	{
		acronym: 'PaaS - Platform as a Service',
		definition:
			'PaaS provides development and deployment platform.\n\nPurpose: Enables secure application deployment.\nDeployment: Implemented with security controls and monitoring.\nContext: Cloud service model with security considerations.',
	},
	{
		acronym: 'PAC - Proxy Auto Configuration',
		definition:
			'PAC automates proxy settings.\n\nPurpose: Manages proxy configuration securely.\nDeployment: Deployed through group policy or web servers.\nContext: Network security configuration mechanism.',
	},
	{
		acronym: 'PAM - Privileged Access Management',
		definition:
			'PAM controls privileged account access.\n\nPurpose: Secures and monitors privileged access.\nDeployment: Implemented through PAM platforms and policies.\nContext: Critical for administrative access control.',
	},
	{
		acronym: 'PAM - Pluggable Authentication Modules',
		definition:
			'PAM provides flexible authentication.\n\nPurpose: Enables modular authentication mechanisms.\nDeployment: Configured in Linux/Unix systems.\nContext: Framework for authentication services.',
	},
	{
		acronym: 'PAP - Password Authentication Protocol',
		definition:
			'PAP performs basic password authentication.\n\nPurpose: Provides simple authentication (insecure).\nDeployment: Legacy protocol avoided in modern systems.\nContext: Example of weak authentication.',
	},
	{
		acronym: 'PAT - Port Address Translation',
		definition:
			'PAT maps multiple private addresses to one public.\n\nPurpose: Conserves IP addresses while providing security.\nDeployment: Configured on firewalls and routers.\nContext: Network address translation variant.',
	},
	{
		acronym: 'PBKDF2 - Password-Based Key Derivation Function 2',
		definition:
			'PBKDF2 strengthens password security.\n\nPurpose: Creates strong keys from passwords.\nDeployment: Used in password storage and encryption.\nContext: Standard for password-based cryptography.',
	},
	{
		acronym: 'PBX - Private Branch Exchange',
		definition:
			'PBX manages internal phone systems.\n\nPurpose: Provides secure internal communications.\nDeployment: Protected against toll fraud and attacks.\nContext: Voice communication infrastructure.',
	},
	{
		acronym: 'PCAP - Packet Capture',
		definition:
			'PCAP captures network traffic.\n\nPurpose: Enables network traffic analysis and investigation.\nDeployment: Used in network monitoring and forensics.\nContext: Important for security analysis.',
	},
	{
		acronym: 'PCI DSS - Payment Card Industry Data Security Standard',
		definition:
			'PCI DSS protects payment card data.\n\nPurpose: Ensures secure handling of payment information.\nDeployment: Implemented through specific security controls.\nContext: Critical for payment processing security.',
	},
	{
		acronym: 'PDU - Power Distribution Unit',
		definition:
			'PDU distributes power to equipment.\n\nPurpose: Provides managed power with security features.\nDeployment: Secured against unauthorized access.\nContext: Critical infrastructure component.',
	},
	{
		acronym: 'PEAP - Protected Extensible Authentication Protocol',
		definition:
			'PEAP secures EAP authentication.\n\nPurpose: Provides secure tunnel for authentication.\nDeployment: Used in wireless and network authentication.\nContext: Enhanced wireless security protocol.',
	},
	{
		acronym: 'PED - Personal Electronic Device',
		definition:
			'PED encompasses personal computing devices.\n\nPurpose: Requires security controls for organizational use.\nDeployment: Managed through MDM and security policies.\nContext: End-user device security concern.',
	},
	{
		acronym: 'PEM - Privacy Enhanced Mail',
		definition:
			'PEM formats cryptographic objects.\n\nPurpose: Stores and transmits security objects.\nDeployment: Used in certificate and key management.\nContext: Standard format for security data.',
	},
	{
		acronym: 'PFS - Perfect Forward Secrecy',
		definition:
			'PFS protects past communications.\n\nPurpose: Ensures security of previous sessions.\nDeployment: Implemented in modern encryption protocols.\nContext: Advanced security feature in communications.',
	},
	{
		acronym: 'PGP - Pretty Good Privacy',
		definition:
			'PGP provides email and file encryption.\n\nPurpose: Enables secure communication and storage.\nDeployment: Used for email encryption and file security.\nContext: Standard for end-to-end encryption.',
	},
	{
		acronym: 'PHI - Protected Health Information',
		definition:
			'PHI includes protected medical data.\n\nPurpose: Requires specific security controls by law.\nDeployment: Protected through HIPAA compliance measures.\nContext: Regulated healthcare information.',
	},
	{
		acronym: 'PII - Personally Identifiable Information',
		definition:
			'PII is data that can identify individuals.\n\nPurpose: Requires protection to prevent identity theft and fraud.\nDeployment: Protected through encryption, access controls, and data handling policies.\nContext: Regulated data type requiring specific security controls.',
	},
	{
		acronym: 'PIV - Personal Identity Verification',
		definition:
			'PIV provides federal identity credentials.\n\nPurpose: Ensures secure identification for federal employees.\nDeployment: Implemented through smart cards with certificates.\nContext: Federal security standard for identity verification.',
	},
	{
		acronym: 'PKCS - Public Key Cryptography Standards',
		definition:
			'PKCS defines cryptography standards.\n\nPurpose: Ensures compatibility in cryptographic implementations.\nDeployment: Used in certificate management and encryption.\nContext: Critical standards for cryptographic operations.',
	},
	{
		acronym: 'PKI - Public Key Infrastructure',
		definition:
			'PKI manages digital certificates and keys.\n\nPurpose: Provides framework for certificate-based security.\nDeployment: Implemented through CAs, certificates, and policies.\nContext: Foundation for certificate-based security.',
	},
	{
		acronym: 'POP - Post Office Protocol',
		definition:
			'POP retrieves email from servers.\n\nPurpose: Enables email access with basic security.\nDeployment: Secured through SSL/TLS encryption.\nContext: Basic email protocol requiring security.',
	},
	{
		acronym: 'POTS - Plain Old Telephone Service',
		definition:
			'POTS provides basic telephone service.\n\nPurpose: Delivers voice communication with inherent security.\nDeployment: Protected through physical security measures.\nContext: Legacy voice communication infrastructure.',
	},
	{
		acronym: 'PPP - Point-to-Point Protocol',
		definition:
			'PPP connects two network nodes.\n\nPurpose: Provides direct network connectivity with security.\nDeployment: Implemented with authentication and encryption.\nContext: Basic network protocol with security features.',
	},
	{
		acronym: 'PPTP - Point-to-Point Tunneling Protocol',
		definition:
			'PPTP creates VPN tunnels.\n\nPurpose: Enables VPN connections (considered insecure).\nDeployment: Legacy protocol replaced by more secure options.\nContext: Outdated VPN protocol with vulnerabilities.',
	},
	{
		acronym: 'PSK - Pre-shared Key',
		definition:
			'PSK provides shared secret for authentication.\n\nPurpose: Enables simple but effective authentication.\nDeployment: Used in WPA/WPA2 and VPN configurations.\nContext: Basic security mechanism for authentication.',
	},
	{
		acronym: 'PTZ - Pan-Tilt-Zoom',
		definition:
			'PTZ enables camera movement control.\n\nPurpose: Provides flexible physical security monitoring.\nDeployment: Used in security camera systems.\nContext: Physical security surveillance technology.',
	},
	{
		acronym: 'PUP - Potentially Unwanted Program',
		definition:
			'PUP describes questionable software.\n\nPurpose: Identifies software requiring security consideration.\nDeployment: Detected by security software and policies.\nContext: Security concern in software management.',
	},
	{
		acronym: 'RA - Recovery Agent',
		definition:
			'RA enables data recovery access.\n\nPurpose: Provides authorized access to encrypted data.\nDeployment: Configured in encryption systems.\nContext: Important for data recovery scenarios.',
	},
	{
		acronym: 'RA - Registration Authority',
		definition:
			'RA validates certificate requests.\n\nPurpose: Verifies identity for certificate issuance.\nDeployment: Part of PKI infrastructure.\nContext: Critical role in certificate management.',
	},
	{
		acronym: 'RAD - Rapid Application Development',
		definition:
			'RAD accelerates software development.\n\nPurpose: Enables quick development with security integration.\nDeployment: Includes security in development cycle.\nContext: Development methodology requiring security focus.',
	},
	{
		acronym: 'RADIUS - Remote Authentication Dial-in User Service',
		definition:
			'RADIUS provides centralized authentication.\n\nPurpose: Manages network access authentication.\nDeployment: Implemented for network access control.\nContext: Standard protocol for network authentication.',
	},
	{
		acronym: 'RAID - Redundant Array of Independent Disks',
		definition:
			'RAID provides disk redundancy.\n\nPurpose: Ensures data availability and integrity.\nDeployment: Implemented in storage systems.\nContext: Data protection through redundancy.',
	},
	{
		acronym: 'RAS - Remote Access Server',
		definition:
			'RAS enables remote network access.\n\nPurpose: Provides secure remote connectivity.\nDeployment: Implemented with authentication and encryption.\nContext: Infrastructure for remote access.',
	},
	{
		acronym: 'RAT - Remote Access Trojan',
		definition:
			'RAT enables unauthorized remote control.\n\nPurpose: Malicious software for remote system access.\nDeployment: Detected and blocked by security controls.\nContext: Common malware threat.',
	},
	{
		acronym: 'RBAC - Role-based Access Control',
		definition:
			'RBAC manages access through roles.\n\nPurpose: Simplifies access management through roles.\nDeployment: Implemented in identity management systems.\nContext: Standard access control model.',
	},
	{
		acronym: 'RC4 - Rivest Cipher 4',
		definition:
			'RC4 is a stream cipher algorithm.\n\nPurpose: Provides encryption (now considered insecure).\nDeployment: Legacy algorithm avoided in modern systems.\nContext: Example of deprecated encryption.',
	},
	{
		acronym: 'RDP - Remote Desktop Protocol',
		definition:
			'RDP enables remote system control.\n\nPurpose: Provides remote access to systems.\nDeployment: Secured through encryption and authentication.\nContext: Common remote access protocol.',
	},
	{
		acronym: 'RFID - Radio Frequency Identification',
		definition:
			'RFID enables wireless identification.\n\nPurpose: Provides contactless identification and tracking.\nDeployment: Used in access control and asset tracking.\nContext: Physical security and asset management.',
	},
	{
		acronym: 'RIPEMD - RACE Integrity Primitives Evaluation Message Digest',
		definition:
			'RIPEMD creates cryptographic hashes.\n\nPurpose: Provides message integrity verification.\nDeployment: Used in cryptographic applications.\nContext: Alternative to SHA hash functions.',
	},
	{
		acronym: 'ROI - Return on Investment',
		definition:
			'ROI measures security investment value.\n\nPurpose: Justifies security spending and resources.\nDeployment: Calculated for security projects and tools.\nContext: Security investment evaluation metric.',
	},
	{
		acronym: 'RPO - Recovery Point Objective',
		definition:
			'RPO defines acceptable data loss.\n\nPurpose: Specifies maximum tolerable data loss.\nDeployment: Used in backup and recovery planning.\nContext: Critical disaster recovery metric.',
	},
	{
		acronym: 'RSA - Rivest, Shamir, & Adleman',
		definition:
			'RSA is an asymmetric encryption algorithm.\n\nPurpose: Provides public key encryption and digital signatures.\nDeployment: Used in secure communications and certificate systems.\nContext: Foundational public key cryptography algorithm.',
	},
	{
		acronym: 'RTBH - Remotely Triggered Black Hole',
		definition:
			'RTBH blocks malicious traffic.\n\nPurpose: Mitigates DDoS and other network attacks.\nDeployment: Implemented on border routers and networks.\nContext: Network defense mechanism against attacks.',
	},
	{
		acronym: 'RTO - Recovery Time Objective',
		definition:
			'RTO defines system recovery time goals.\n\nPurpose: Specifies maximum acceptable downtime.\nDeployment: Used in disaster recovery planning.\nContext: Critical business continuity metric.',
	},
	{
		acronym: 'RTOS - Real-time Operating System',
		definition:
			'RTOS manages time-critical operations.\n\nPurpose: Ensures predictable system responses.\nDeployment: Used in embedded and critical systems.\nContext: Specialized OS for time-sensitive applications.',
	},
	{
		acronym: 'RTP - Real-time Transport Protocol',
		definition:
			'RTP streams multimedia content.\n\nPurpose: Enables real-time audio/video transmission.\nDeployment: Secured through SRTP for encryption.\nContext: Multimedia streaming protocol requiring security.',
	},
	{
		acronym: 'S/MIME - Secure/Multipurpose Internet Mail Extensions',
		definition:
			'S/MIME secures email communications.\n\nPurpose: Provides email encryption and digital signatures.\nDeployment: Implemented through certificates and encryption.\nContext: Standard for secure email communication.',
	},
	{
		acronym: 'SaaS - Software as a Service',
		definition:
			'SaaS delivers cloud-based applications.\n\nPurpose: Provides software access with security controls.\nDeployment: Secured through authentication and encryption.\nContext: Cloud service model requiring security measures.',
	},
	{
		acronym: 'SAE - Simultaneous Authentication of Equals',
		definition:
			'SAE provides secure key exchange.\n\nPurpose: Enhances WPA3 wireless security.\nDeployment: Implemented in modern wireless networks.\nContext: Advanced wireless security protocol.',
	},
	{
		acronym: 'SAML - Security Assertion Markup Language',
		definition:
			'SAML enables secure authentication exchange.\n\nPurpose: Provides federated authentication and SSO.\nDeployment: Implemented for enterprise authentication.\nContext: Standard for identity federation.',
	},
	{
		acronym: 'SAN - Storage Area Network',
		definition:
			'SAN provides centralized storage access.\n\nPurpose: Enables secure, shared storage resources.\nDeployment: Protected through access controls and encryption.\nContext: Enterprise storage infrastructure.',
	},
	{
		acronym: 'SAN - Subject Alternative Name',
		definition:
			'SAN extends certificate domain coverage.\n\nPurpose: Allows multiple domains on single certificate.\nDeployment: Used in SSL/TLS certificates.\nContext: Certificate extension for flexibility.',
	},
	{
		acronym: 'SASE - Secure Access Service Edge',
		definition:
			'SASE combines network and security services.\n\nPurpose: Provides cloud-based security and networking.\nDeployment: Implemented as cloud service with edge security.\nContext: Modern security architecture approach.',
	},
	{
		acronym: 'SCADA - Supervisory Control and Data Acquisition',
		definition:
			'SCADA controls industrial processes.\n\nPurpose: Manages industrial systems with security needs.\nDeployment: Protected through specialized security controls.\nContext: Critical infrastructure technology.',
	},
	{
		acronym: 'SCAP - Security Content Automation Protocol',
		definition:
			'SCAP automates security assessment.\n\nPurpose: Standardizes security configuration and assessment.\nDeployment: Used in vulnerability management tools.\nContext: Framework for security automation.',
	},
	{
		acronym: 'SCEP - Simple Certificate Enrollment Protocol',
		definition:
			'SCEP manages certificate enrollment.\n\nPurpose: Automates certificate provisioning.\nDeployment: Used in certificate management systems.\nContext: Certificate lifecycle automation.',
	},
	{
		acronym: 'SD-WAN - Software-defined Wide Area Network',
		definition:
			'SD-WAN manages wide area networks.\n\nPurpose: Provides flexible, secure network connectivity.\nDeployment: Implemented with security controls and encryption.\nContext: Modern WAN technology.',
	},
	{
		acronym: 'SDK - Software Development Kit',
		definition:
			'SDK provides development tools.\n\nPurpose: Enables secure application development.\nDeployment: Used with security best practices.\nContext: Development tools requiring security.',
	},
	{
		acronym: 'SDLC - Software Development Life Cycle',
		definition:
			'SDLC manages software development.\n\nPurpose: Integrates security throughout development.\nDeployment: Implemented with security at each phase.\nContext: Secure development framework.',
	},
	{
		acronym: 'SDLM - Software Development Lifecycle Methodology',
		definition:
			'SDLM structures development process.\n\nPurpose: Ensures systematic secure development.\nDeployment: Applied throughout development lifecycle.\nContext: Methodology for secure development.',
	},
	{
		acronym: 'SDN - Software-defined Networking',
		definition:
			'SDN centralizes network control.\n\nPurpose: Enables flexible network management and security.\nDeployment: Implemented with security controls and policies.\nContext: Modern network architecture.',
	},
	{
		acronym: 'SE Linux - Security-Enhanced Linux',
		definition:
			'SE Linux adds mandatory access controls.\n\nPurpose: Provides enhanced Linux security.\nDeployment: Implemented through security policies.\nContext: Advanced Linux security feature.',
	},
	{
		acronym: 'SED - Self-encrypting Drive',
		definition:
			'SED provides hardware-based encryption.\n\nPurpose: Ensures automatic data encryption.\nDeployment: Used for data protection at rest.\nContext: Storage security technology.',
	},
	{
		acronym: 'SEH - Structured Exception Handler',
		definition:
			'SEH manages program exceptions.\n\nPurpose: Provides error handling with security implications.\nDeployment: Protected against exploitation attempts.\nContext: Programming security consideration.',
	},
	{
		acronym: 'SFTP - SSH File Transfer Protocol',
		definition:
			'SFTP enables secure file transfer.\n\nPurpose: Provides encrypted file transfer capability.\nDeployment: Implemented with SSH for security.\nContext: Secure alternative to FTP.',
	},
	{
		acronym: 'SHA - Secure Hash Algorithm',
		definition:
			'SHA creates cryptographic hashes.\n\nPurpose: Ensures data integrity and authentication.\nDeployment: Used in various security applications.\nContext: Standard cryptographic hash function.',
	},
	{
		acronym: 'SHTTP - Secure Hypertext Transfer Protocol',
		definition:
			'SHTTP is an alternative to HTTPS.\n\nPurpose: Provides security for web communications.\nDeployment: Rarely used, superseded by HTTPS/TLS.\nContext: Historical secure web protocol.',
	},
	{
		acronym: 'SIEM - Security Information and Event Management',
		definition:
			'SIEM analyzes security data and events.\n\nPurpose: Provides centralized security monitoring and analysis.\nDeployment: Implemented as central security monitoring platform.\nContext: Critical enterprise security monitoring tool.',
	},
	{
		acronym: 'SIM - Subscriber Identity Module',
		definition:
			'SIM authenticates mobile devices.\n\nPurpose: Securely identifies mobile subscribers.\nDeployment: Used in mobile devices with encryption.\nContext: Mobile device security component.',
	},
	{
		acronym: 'SLA - Service Level Agreement',
		definition:
			'SLA defines service performance requirements.\n\nPurpose: Establishes security and performance metrics.\nDeployment: Implemented through contracts and monitoring.\nContext: Service management and accountability.',
	},
	{
		acronym: 'SLE - Single Loss Expectancy',
		definition:
			'SLE calculates loss from single incident.\n\nPurpose: Quantifies potential security incident impact.\nDeployment: Used in risk assessment calculations.\nContext: Risk assessment metric.',
	},
	{
		acronym: 'SMS - Short Message Service',
		definition:
			'SMS enables text messaging.\n\nPurpose: Provides mobile messaging with security concerns.\nDeployment: Protected through carrier security measures.\nContext: Mobile communication requiring security.',
	},
	{
		acronym: 'SMTP - Simple Mail Transfer Protocol',
		definition:
			'SMTP transmits email messages.\n\nPurpose: Enables email delivery with security requirements.\nDeployment: Secured through TLS and authentication.\nContext: Core email protocol requiring protection.',
	},
	{
		acronym: 'SMTPS - Simple Mail Transfer Protocol Secure',
		definition:
			'SMTPS adds encryption to SMTP.\n\nPurpose: Secures email transmission.\nDeployment: Implemented with TLS encryption.\nContext: Secure email transport protocol.',
	},
	{
		acronym: 'SNMP - Simple Network Management Protocol',
		definition:
			'SNMP manages network devices.\n\nPurpose: Enables network monitoring and management.\nDeployment: Secured through SNMPv3 and access controls.\nContext: Network management protocol requiring security.',
	},
	{
		acronym: 'SOAP - Simple Object Access Protocol',
		definition:
			'SOAP exchanges structured information.\n\nPurpose: Enables web service communication.\nDeployment: Secured through WS-Security standards.\nContext: Web services protocol requiring protection.',
	},
	{
		acronym: 'SOAR - Security Orchestration, Automation and Response',
		definition:
			'SOAR automates security operations.\n\nPurpose: Streamlines security incident response.\nDeployment: Integrated with security tools and workflows.\nContext: Advanced security automation platform.',
	},
	{
		acronym: 'SoC - System on Chip',
		definition:
			'SoC integrates system components.\n\nPurpose: Provides integrated security features.\nDeployment: Used in mobile and embedded devices.\nContext: Hardware security integration.',
	},
	{
		acronym: 'SOC - Security Operations Center',
		definition:
			'SOC monitors security operations.\n\nPurpose: Provides centralized security monitoring and response.\nDeployment: Staffed 24/7 with security analysts.\nContext: Core security operations facility.',
	},
	{
		acronym: 'SOW - Statement of Work',
		definition:
			'SOW defines project requirements.\n\nPurpose: Specifies security requirements and deliverables.\nDeployment: Used in security project planning.\nContext: Project security documentation.',
	},
	{
		acronym: 'SPF - Sender Policy Framework',
		definition:
			'SPF prevents email spoofing.\n\nPurpose: Validates email sender authenticity.\nDeployment: Implemented through DNS records.\nContext: Email authentication protocol.',
	},
	{
		acronym: 'SPIM - Spam over Internet Messaging',
		definition:
			'SPIM describes instant message spam.\n\nPurpose: Identifies messaging-based attacks.\nDeployment: Blocked through messaging security controls.\nContext: Messaging security threat.',
	},
	{
		acronym: 'SQL - Structured Query Language',
		definition:
			'SQL manages database operations.\n\nPurpose: Enables database interaction requiring security.\nDeployment: Protected against injection and abuse.\nContext: Database technology requiring protection.',
	},
	{
		acronym: 'SQLi - SQL Injection',
		definition:
			'SQLi attacks database security.\n\nPurpose: Exploits database input vulnerabilities.\nDeployment: Prevented through input validation and parameterization.\nContext: Common web application vulnerability.',
	},
	{
		acronym: 'SRTP - Secure Real-time Transport Protocol',
		definition:
			'SRTP secures multimedia streams.\n\nPurpose: Provides encryption for real-time communications.\nDeployment: Used in VoIP and video conferencing.\nContext: Secure multimedia protocol.',
	},
	{
		acronym: 'SSD - Solid State Drive',
		definition:
			'SSD stores data electronically.\n\nPurpose: Provides fast storage requiring security controls.\nDeployment: Protected through encryption and secure erasure.\nContext: Modern storage technology.',
	},
	{
		acronym: 'SSH - Secure Shell',
		definition:
			'SSH enables secure remote access.\n\nPurpose: Provides encrypted remote system access.\nDeployment: Used for secure administration and file transfer.\nContext: Standard for secure remote access.',
	},
	{
		acronym: 'SSL - Secure Sockets Layer',
		definition:
			'SSL secures network communications.\n\nPurpose: Provided encrypted communications (now obsolete).\nDeployment: Replaced by TLS for security.\nContext: Legacy security protocol.',
	},
	{
		acronym: 'SSO - Single Sign-On',
		definition:
			'SSO enables unified authentication.\n\nPurpose: Simplifies secure access to multiple systems.\nDeployment: Implemented through identity providers.\nContext: Enterprise authentication mechanism.',
	},
	{
		acronym: 'STIX - Structured Threat Information eXchange',
		definition:
			'STIX standardizes threat intelligence.\n\nPurpose: Enables sharing of threat information.\nDeployment: Used in threat intelligence platforms.\nContext: Threat intelligence sharing standard.',
	},
	{
		acronym: 'SWG - Secure Web Gateway',
		definition:
			'SWG controls web access.\n\nPurpose: Protects organizations from web-based threats.\nDeployment: Implemented at network edge or cloud.\nContext: Web security control point.',
	},
	{
		acronym: 'TACACS+ - Terminal Access Controller Access Control System Plus',
		definition:
			'TACACS+ provides centralized authentication.\n\nPurpose: Enables centralized AAA services for network devices.\nDeployment: Implemented for network device administration.\nContext: Enterprise network security protocol.',
	},
	{
		acronym: 'TAXII - Trusted Automated eXchange of Indicator Information',
		definition:
			'TAXII enables threat intelligence sharing.\n\nPurpose: Provides standard for sharing threat data.\nDeployment: Used with STIX for threat intelligence exchange.\nContext: Threat intelligence sharing protocol.',
	},
	{
		acronym: 'TCP/IP - Transmission Control Protocol/Internet Protocol',
		definition:
			'TCP/IP enables network communication.\n\nPurpose: Provides foundation for network connectivity.\nDeployment: Secured through various network controls.\nContext: Core internet protocol suite.',
	},
	{
		acronym: 'TGT - Ticket Granting Ticket',
		definition:
			'TGT enables Kerberos authentication.\n\nPurpose: Provides initial authentication credential.\nDeployment: Used in Kerberos authentication systems.\nContext: Enterprise authentication component.',
	},
	{
		acronym: 'TKIP - Temporal Key Integrity Protocol',
		definition:
			'TKIP secures wireless networks.\n\nPurpose: Provided enhanced WEP security (now deprecated).\nDeployment: Replaced by more secure protocols.\nContext: Legacy wireless security protocol.',
	},
	{
		acronym: 'TLS - Transport Layer Security',
		definition:
			'TLS encrypts network communications.\n\nPurpose: Provides secure communication channel.\nDeployment: Implemented in web and application security.\nContext: Standard for secure communications.',
	},
	{
		acronym: 'TOC - Time of Check',
		definition:
			'TOC relates to race condition vulnerabilities.\n\nPurpose: Identifies security timing vulnerabilities.\nDeployment: Addressed in secure coding practices.\nContext: Security programming consideration.',
	},
	{
		acronym: 'TOTP - Time-based One-Time Password',
		definition:
			'TOTP generates time-based codes.\n\nPurpose: Provides dynamic authentication codes.\nDeployment: Used in multi-factor authentication.\nContext: Strong authentication mechanism.',
	},
	{
		acronym: 'TPM - Trusted Platform Module',
		definition:
			'TPM provides hardware security.\n\nPurpose: Enables secure key storage and platform integrity.\nDeployment: Integrated in system hardware.\nContext: Hardware security foundation.',
	},
	{
		acronym: 'TTP - Tactics, Techniques, and Procedures',
		definition:
			'TTP describes attacker behavior.\n\nPurpose: Characterizes threat actor methods.\nDeployment: Used in threat intelligence analysis.\nContext: Threat analysis framework.',
	},
	{
		acronym: 'TSIG - Transaction Signature',
		definition:
			'TSIG secures DNS updates.\n\nPurpose: Authenticates DNS transactions.\nDeployment: Implemented in DNS security.\nContext: DNS security mechanism.',
	},
	{
		acronym: 'UAT - User Acceptance Testing',
		definition:
			'UAT validates system functionality.\n\nPurpose: Ensures security requirements are met.\nDeployment: Performed before system deployment.\nContext: Security testing phase.',
	},
	{
		acronym: 'UDP - User Datagram Protocol',
		definition:
			'UDP provides fast network communication.\n\nPurpose: Enables connectionless data transfer.\nDeployment: Secured through application controls.\nContext: Network protocol requiring protection.',
	},
	{
		acronym: 'UEFI - Unified Extensible Firmware Interface',
		definition:
			'UEFI manages system boot process.\n\nPurpose: Provides secure boot capabilities.\nDeployment: Implemented in modern hardware.\nContext: Secure boot technology.',
	},
	{
		acronym: 'UEM - Unified Endpoint Management',
		definition:
			'UEM manages all endpoint devices.\n\nPurpose: Provides centralized device security management.\nDeployment: Implemented across organization devices.\nContext: Enterprise device management.',
	},
	{
		acronym: 'UPS - Uninterruptible Power Supply',
		definition:
			'UPS provides backup power.\n\nPurpose: Ensures continuous system operation.\nDeployment: Installed for critical systems.\nContext: Infrastructure protection component.',
	},
	{
		acronym: 'URI - Uniform Resource Identifier',
		definition:
			'URI identifies network resources.\n\nPurpose: Provides resource location and naming.\nDeployment: Used in web and application security.\nContext: Resource identification standard.',
	},
	{
		acronym: 'URL - Uniform Resource Locator',
		definition:
			'URL specifies resource locations.\n\nPurpose: Enables web resource access.\nDeployment: Protected against manipulation attacks.\nContext: Web addressing mechanism.',
	},
	{
		acronym: 'USB - Universal Serial Bus',
		definition:
			'USB enables device connectivity.\n\nPurpose: Provides peripheral connection capability.\nDeployment: Controlled through security policies.\nContext: Physical connection security concern.',
	},
	{
		acronym: 'UTM - Unified Threat Management',
		definition:
			'UTM combines security functions.\n\nPurpose: Provides integrated security services.\nDeployment: Implemented at network boundaries.\nContext: Comprehensive security appliance.',
	},
	{
		acronym: 'UTP - Unshielded Twisted Pair',
		definition:
			'UTP carries network signals.\n\nPurpose: Provides network connectivity medium.\nDeployment: Protected against physical threats.\nContext: Network infrastructure component.',
	},
	{
		acronym: 'VBA - Visual Basic for Applications',
		definition:
			'VBA enables application automation.\n\nPurpose: Provides macro programming capability.\nDeployment: Controlled due to security risks.\nContext: Application security concern.',
	},
	{
		acronym: 'VDE - Virtual Desktop Environment',
		definition:
			'VDE provides isolated desktop environments.\n\nPurpose: Enables secure desktop virtualization.\nDeployment: Implemented for secure remote access.\nContext: Secure desktop delivery platform.',
	},
	{
		acronym: 'VDI - Virtual Desktop Infrastructure',
		definition:
			'VDI hosts virtual desktops.\n\nPurpose: Provides centralized desktop management.\nDeployment: Implemented with security controls.\nContext: Enterprise desktop virtualization.',
	},
	{
		acronym: 'VLAN - Virtual Local Area Network',
		definition:
			'VLAN segments network traffic.\n\nPurpose: Enables logical network separation.\nDeployment: Configured for network segmentation.\nContext: Network security control.',
	},
	{
		acronym: 'VLSM - Variable Length Subnet Masking',
		definition:
			'VLSM optimizes IP address allocation.\n\nPurpose: Enables efficient network segmentation.\nDeployment: Implemented in subnet design.\nContext: Network design security consideration.',
	},
	{
		acronym: 'VM - Virtual Machine',
		definition:
			'VM provides isolated computing environment.\n\nPurpose: Enables system isolation and sandboxing.\nDeployment: Implemented with hypervisor security controls.\nContext: Virtualization security component.',
	},
	{
		acronym: 'VoIP - Voice over IP',
		definition:
			'VoIP enables voice communication over IP.\n\nPurpose: Provides voice services requiring security.\nDeployment: Protected through encryption and QoS.\nContext: Network voice communication service.',
	},
	{
		acronym: 'VPC - Virtual Private Cloud',
		definition:
			'VPC creates isolated cloud environments.\n\nPurpose: Provides secure cloud network isolation.\nDeployment: Configured with security groups and ACLs.\nContext: Cloud security architecture component.',
	},
	{
		acronym: 'VPN - Virtual Private Network',
		definition:
			'VPN creates secure network tunnels.\n\nPurpose: Enables secure remote network access.\nDeployment: Implemented with encryption and authentication.\nContext: Remote access security solution.',
	},
	{
		acronym: 'VTC - Video Teleconferencing',
		definition:
			'VTC enables video communication.\n\nPurpose: Provides secure video conferencing.\nDeployment: Protected through encryption and access controls.\nContext: Remote communication platform.',
	},
	{
		acronym: 'WAF - Web Application Firewall',
		definition:
			'WAF protects web applications.\n\nPurpose: Filters malicious web traffic.\nDeployment: Implemented at application edge.\nContext: Web security control point.',
	},
	{
		acronym: 'WAP - Wireless Access Point',
		definition:
			'WAP provides wireless connectivity.\n\nPurpose: Enables secure wireless network access.\nDeployment: Secured through encryption and authentication.\nContext: Wireless network infrastructure.',
	},
	{
		acronym: 'WEP - Wired Equivalent Privacy',
		definition:
			'WEP was early wireless security.\n\nPurpose: Provided basic wireless encryption (now broken).\nDeployment: Completely deprecated and unsafe.\nContext: Example of obsolete security.',
	},
	{
		acronym: 'WIDS - Wireless Intrusion Detection System',
		definition:
			'WIDS monitors wireless networks.\n\nPurpose: Detects wireless security threats.\nDeployment: Implemented through sensors and analysis.\nContext: Wireless security monitoring.',
	},
	{
		acronym: 'WIPS - Wireless Intrusion Prevention System',
		definition:
			'WIPS actively protects wireless networks.\n\nPurpose: Prevents wireless attacks actively.\nDeployment: Implemented with prevention capabilities.\nContext: Active wireless security control.',
	},
	{
		acronym: 'WO - Work Order',
		definition:
			'WO documents required work.\n\nPurpose: Tracks security-related tasks.\nDeployment: Used in change management process.\nContext: Security operation documentation.',
	},
	{
		acronym: 'WPA - Wi-Fi Protected Access',
		definition:
			'WPA secures wireless networks.\n\nPurpose: Provides wireless network security.\nDeployment: Implemented with various encryption options.\nContext: Standard wireless security protocol.',
	},
	{
		acronym: 'WPS - Wi-Fi Protected Setup',
		definition:
			'WPS simplifies wireless setup.\n\nPurpose: Enables easy wireless configuration (security concerns).\nDeployment: Often disabled due to vulnerabilities.\nContext: Convenience feature with security risks.',
	},
	{
		acronym: 'WTLS - Wireless Transport Layer Security',
		definition:
			'WTLS secures wireless communications.\n\nPurpose: Provides security for wireless protocols.\nDeployment: Used in mobile and wireless systems.\nContext: Wireless security protocol.',
	},
	{
		acronym: 'XDR - Extended Detection and Response',
		definition:
			'XDR provides comprehensive threat detection.\n\nPurpose: Enables unified security visibility and response.\nDeployment: Integrated across security tools.\nContext: Advanced security monitoring platform.',
	},
	{
		acronym: 'XML - Extensible Markup Language',
		definition:
			'XML structures data exchange.\n\nPurpose: Enables structured data sharing.\nDeployment: Protected against injection attacks.\nContext: Data format requiring security.',
	},
	{
		acronym: 'XOR - Exclusive OR',
		definition:
			'XOR performs binary operations.\n\nPurpose: Used in encryption and security operations.\nDeployment: Implemented in cryptographic functions.\nContext: Basic cryptographic operation.',
	},
	{
		acronym: 'XSRF - Cross-site Request Forgery',
		definition:
			'XSRF exploits web trust relationships.\n\nPurpose: Executes unauthorized actions through user trust.\nDeployment: Prevented through tokens and validation.\nContext: Web application vulnerability.',
	},
	{
		acronym: 'XSS - Cross-site Scripting',
		definition:
			'XSS injects malicious scripts.\n\nPurpose: Executes unauthorized code in browsers.\nDeployment: Prevented through input validation and encoding.\nContext: Common web security vulnerability.',
	},
	{
		acronym: 'ZKP - Zero Knowledge Proof',
		definition:
			'ZKP proves knowledge without revelation.\n\nPurpose: Enables verification without data exposure.\nDeployment: Used in advanced authentication systems.\nContext: Privacy-preserving security mechanism.',
	},
	{
		acronym: 'ZT - Zero Trust',
		definition:
			'ZT assumes no implicit trust.\n\nPurpose: Provides continuous security validation.\nDeployment: Implemented through various security controls.\nContext: Modern security architecture model.',
	},
	{
		acronym: 'ZTNA - Zero Trust Network Access',
		definition:
			'ZTNA enforces zero trust principles.\n\nPurpose: Enables secure access based on identity and context.\nDeployment: Implemented through identity-based controls.\nContext: Modern access control framework.',
	},
	{
		acronym: 'RBAC - Rule-based Access Control',
		definition:
			'RBAC enforces rule-based permissions.\n\nPurpose: Controls access based on predefined rules.\nDeployment: Implemented in access control systems.\nContext: Access control mechanism.',
	},
	{
		acronym: 'SABSA - Sherwood Applied Business Security Architecture',
		definition:
			'SABSA is a security architecture framework.\n\nPurpose: Provides enterprise security architecture methodology.\nDeployment: Used in security design and planning.\nContext: Security architecture framework.',
	},
];

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

	// First, convert \n to <br> tags
	const definitionWithBreaks = cards[currentIndex].definition.replace(
		/\n/g,
		'<br>'
	);

	const tempDiv = document.createElement('div');
	tempDiv.innerHTML = definitionWithBreaks;
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

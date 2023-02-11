# Blue Team Toolset - ACTIVELY UPDATED
Repository with bunch of tools and resources for cyber threat intelligence, etc.

The resources are sorted by categories and subcategories.

As an example if you have a IP address that you think is malicious, you can go to the IP section of "Cyber Threat Intelligence Tools" and use the resources to input the IP.

NOTE: If there is anything you see wrong, or need to be added, you are free to contribute and I will try look into it. I will also try to improve the structure for easier nagivation.                               

### ToDo (Completed ToDo's will be removed)
* Add more tools - In Progress
* Add more SIEMs - In Progress
* Add resources to news category - In Progress
* Add rules and tools to "rule-based formats category)" (Maybe change name of category?) - In Progress
* Network Forensics Analysis Tools Category
* Add descriptions




# Table of Contents
1. [Cyber Threat Intelligence Tools (Input based on what intelligence you have)](#cyber-threat-intelligence-sources)
   - 1.1 [IOC](#ioc)
   - 1.2 [IP](#ip)
   - 1.3 [Domain](#domain)
   - 1.4 [URL](#url)
   - 1.5 [File Hash](#file-hash)
   - 1.6 [File Upload](#file-upload)
   - 1.7 [Keyword](#keyword)
   - 1.8 [SSL Certificates/Fingerprints](#ssl)
   - 1.9 [ASN/COUNTRY/TLD Feeds](#asn-feeds)
   - 1.10 [AS NAME/AS NUMBER](#as-name-number)
   - 1.11 [Email File (Phising Analysis Tools)](#email-file)
2. [Cyber Defence Frameworks](#cyber-defence-frameworks)
3. [Cyber Threat Intelligence](#cyber-threat-intelligence-sharing)
    - 3.1 [Formats](#formats)
    - 3.2 [Platforms](#platforms)
4. [Cyber Threat Intelligence News](#cyber-threat-intelligence-news)
5. [Rule-based Formats](#cyber-threat-intelligence-rule-based-formats)
    - 5.1 [YARA (Files)](#yara)
        + 5.1.1 [YARA Rules](#yara-rules)
        + 5.1.2 [YARA Tools](#yara-tools)
    - 5.2 [SNORT (Network Traffic)](#snort)
        + 5.2.1 [SNORT Rules](#snort-rules)
        + 5.2.2 [SNORT Tools](#snort-tools)
    - 5.3 [SIGMA (Log Files)](#sigma)
        + 5.3.1 [SIGMA Rules](#sigma-rules)
        + 5.3.2 [SIGMA Tools](#sigma-tools)
        



## Cyber Threat Intelligence Sources (Input based on what intelligence you have) <a name="cyber-threat-intelligence-sources"></a>

### IOC <a name="ioc"></a>
* [ThreatFox](https://threatfox.abuse.ch/browse/) (IP:PORT, Domain, URL)
* [VirusTotal](https://www.virustotal.com/gui/home/search)

### IP <a name="ip"></a>
* [VirusTotal](https://www.virustotal.com/gui/home/search)
* [Cisco Talos Intelligence](https://talosintelligence.com/reputation_center)
* [Feodotracker Botnet C&Cs](https://feodotracker.abuse.ch/browse/) - *(Emotet, TrickBot, Dridex, QakBot, BazarLoader, BumbleBee)*
* [SHODAN](https://www.shodan.io/)
* [AbuseIPDB](https://www.abuseipdb.com/)

### Domain <a name="domain"></a>
* [DNSdumpster](https://dnsdumpster.com/)
* [UrlScan.io](https://urlscan.io/)
* [VirusTotal](https://www.virustotal.com/gui/home/url)
* [URLhaus](https://urlhaus.abuse.ch/browse/)
* [Cisco Talos Intelligence](https://talosintelligence.com/reputation_center)
* [SHODAN](https://www.shodan.io/)
* [AbuseIPDB](https://www.abuseipdb.com/)

### URL <a name="url"></a>
* [UrlScan.io](https://urlscan.io/)
* [VirusTotal](https://www.virustotal.com/gui/home/url)
* [URLhaus](https://urlhaus.abuse.ch/browse/)

### File Hash <a name="file-hash"></a>
* [VirusTotal](https://www.virustotal.com/gui/home/search) - *(MD5, SHA1, SHA256)*
* [URLhaus](https://urlhaus.abuse.ch/browse/) - *(MD5, SHA256)*
* [YARAify Search](https://yaraify.abuse.ch/search/) - *(MD5, SHA1, SHA256, SHA3-384)*
* [MalwareBazaar Database](https://bazaar.abuse.ch/browse/) - *(MD5, SHA1, SHA256, SHA3-384)*

### File Upload <a name="file-upload"></a>
* [YARAify File Scan](https://yaraify.abuse.ch/scan/)
* [VirusTotal](https://www.virustotal.com/gui/home/upload)

### Keyword <a name="keyword"></a>
* [SHODAN](https://www.shodan.io/)

### SSL Certificates/Fingerprints <a name="ssl"></a>
* [SSL Certificates](https://sslbl.abuse.ch/ssl-certificates/) *(SHA1)*
* [JA3 Fingerprints](https://sslbl.abuse.ch/ja3-fingerprints/)
    
### ASN/COUNTRY/TLD Feeds <a name="asn-feeds"></a>
* [URLhaus Feeds](https://urlhaus.abuse.ch/feeds/)

#### AS NAME/AS NUMBER <a name="as-name-number"></a>
* [Feodotracker Botnet C&Cs](https://feodotracker.abuse.ch/browse/) - *(Emotet, TrickBot, Dridex, QakBot, BazarLoader, BumbleBee)*

### Email File (Phising Analysis Tools) <a name="email-file"></a>
* [PhishTool](https://www.phishtool.com/)

- - - 
- - - 
- - - 
- - - 

## Cyber Defence Frameworks <a name="cyber-defence-frameworks"></a>
* [The Cyber Kill Chain®](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
* [The Unified Kill Chain](https://www.unifiedkillchain.com/)
* [Diamond Model](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)
* [MITRE ATT&CK](https://attack.mitre.org/)

- - - 

## Cyber Threat Intelligence Sharing <a name="cyber-threat-intelligence-sharing"></a>

### Formats <a name="formats"></a>
* [TAXII - The Trusted Automated eXchange of Indicator Information](https://oasis-open.github.io/cti-documentation/taxii/intro)
* [STIX - Structured Threat Information Expression](https://oasis-open.github.io/cti-documentation/stix/intro)
* [MAEC - Malware Attribute Enumeration and Characterization](https://maecproject.github.io/)
* [VERIS - Vocabulary for Event Recording and Incident Sharing](http://veriscommunity.net/index.html)
* [CAPEC - Common Attack Pattern Enumeration and Classification](https://capec.mitre.org/)
* [CybOX - Cyber Observable eXpression](https://cyboxproject.github.io/)
* [IODEF (RFC5070) - Incident Object Description Exchange Format](https://www.rfc-editor.org/rfc/rfc5070)
* [IDMEF (RFC4765) - Intrusion Detection Message Exchange Format](https://www.rfc-editor.org/rfc/rfc4765)


### Platforms <a name="platforms"></a>
* [MISP - Malware Information Sharing Platform](https://www.misp-project.org/)
* [OPENCTI - Open Cyber Threat Intelligence Platform](https://www.filigran.io/en/products/opencti/)

- - - 

### Cyber Threat Intelligence News <a name="cyber-threat-intelligence-news"></a>

- - -

## Rule-based Formats <a name="cyber-threat-intelligence-rule-based-formats"></a>

### YARA (Files) <a name="yara"></a>
* [YARA](https://virustotal.github.io/yara/)

#### YARA Rules<a name="yara-rules"></a>
* [Awesome-yara](https://github.com/InQuest/awesome-yara#rules)

#### YARA Tools<a name="yara-tools"></a>
* [Awesome-yara](https://github.com/InQuest/awesome-yara#tools)


### SNORT (Network Traffic) <a name="snort"></a>
* [SNORT](https://www.snort.org/)

#### SNORT Rules<a name="snort-rules"></a>

#### SNORT Tools <a name="snort-tools"></a>



### SIGMA (Log Files) <a name="sigma"></a>
* [SIGMA](https://github.com/SigmaHQ/sigma)

#### SIGMA Rules <a name="sigma-rules"></a>

#### SIGMA Tools <a name="sigma-tools"></a>
* [Sigmac](https://github.com/SigmaHQ/sigma)



## Blacklists/Rulesets <a name="Cyber-Threat-Intelligence-Tools-SSL-Certificates/Fingerprints"></a>
* [Botnet](https://feodotracker.abuse.ch/blocklist/) *(Emotet, TrickBot, Dridex, QakBot, BazarLoader, BumbleBee)* 
* [Botnet/SSL/JA3](https://sslbl.abuse.ch/blacklist/)

## SIEM Solutions <a name="Cyber-Threat-Intelligence-Tools-SSL-Certificates/Fingerprints"></a>
* [Splunk](https://www.splunk.com/)
* [Elastic Stack](https://www.elastic.co/elastic-stack?elektra=home&storm=stack)
    - [Elasticsearch](https://www.elastic.co/elasticsearch/)
    - [Kibana](https://www.elastic.co/kibana/)
    - [Integrations](https://www.elastic.co/integrations/)
* [Logpoint](https://www.logpoint.com/en/product/logpoint-as-a-siem-tool/)

## EXTRA (To be categorized)
* [YARAhub](https://yaraify.abuse.ch/yarahub/)
* [YARAify Search](https://yaraify.abuse.ch/search/)

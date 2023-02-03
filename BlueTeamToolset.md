# Blue Team Toolset - ACTIVELY UPDATED
Repository with bunch of tools and resources for hacking, cyber threat intelligence, etc.

The resources are sorted by categories and subcategories.

As an example if you have a IP address that you think is malicious, you can go to the IP section of "Cyber Threat Intelligence" and use the resources to input the IP.

NOTE: If there is anything you see wrong, or need to be added, you are free to contribute and I will try look into it. I will also try to improve the structure for easier nagivation.

### ToDo
* Add more tools
* Add more SIEMs
* Add news category
* Create a category with a list of different IDS/IPS rulesets
* Add table of content
* Add fast search navigation

## Cyber Threat Intelligence Tools (Input based on what intelligence you have)

### IOC
* [ThreatFox](https://threatfox.abuse.ch/browse/) (IP:PORT, Domain, URL)
* [VirusTotal](https://www.virustotal.com/gui/home/search)

### IP
* [VirusTotal](https://www.virustotal.com/gui/home/search)
* [Cisco Talos Intelligence](https://talosintelligence.com/reputation_center)
* [Feodotracker Botnet C&Cs](https://feodotracker.abuse.ch/browse/) - *(Emotet, TrickBot, Dridex, QakBot, BazarLoader, BumbleBee)*

### Domain
* [DNSdumpster](https://dnsdumpster.com/)
* [UrlScan.io](https://urlscan.io/)
* [VirusTotal](https://www.virustotal.com/gui/home/url)
* [URLhaus](https://urlhaus.abuse.ch/browse/)
* [Cisco Talos Intelligence](https://talosintelligence.com/reputation_center)

### URL
* [UrlScan.io](https://urlscan.io/)
* [VirusTotal](https://www.virustotal.com/gui/home/url)
* [URLhaus](https://urlhaus.abuse.ch/browse/)

### File Hash
* [VirusTotal](https://www.virustotal.com/gui/home/search) - *(MD5, SHA1, SHA256)*
* [URLhaus](https://urlhaus.abuse.ch/browse/) - *(MD5, SHA256)*
* [YARAify Search](https://yaraify.abuse.ch/search/) - *(MD5, SHA1, SHA256, SHA3-384)*
* [MalwareBazaar Database](https://bazaar.abuse.ch/browse/) - *(MD5, SHA1, SHA256, SHA3-384)*

### File Upload
* [YARAify File Scan](https://yaraify.abuse.ch/scan/)
* [VirusTotal](https://www.virustotal.com/gui/home/upload)

### SSL Certificates/Fingerprints
* [SSL Certificates](https://sslbl.abuse.ch/ssl-certificates/) *(SHA1)*
* [JA3 Fingerprints](https://sslbl.abuse.ch/ja3-fingerprints/)
    
### ASN/COUNTRY/TLD Feeds
* [URLhaus Feeds](https://urlhaus.abuse.ch/feeds/)

#### AS NAME/AS NUMBER
* [Feodotracker Botnet C&Cs](https://feodotracker.abuse.ch/browse/) - *(Emotet, TrickBot, Dridex, QakBot, BazarLoader, BumbleBee)*

### Email File (Phising Analysis Tools)
* [PhishTool](https://www.phishtool.com/)

- - - 
- - - 
- - - 
- - - 

## Cyber Defence Frameworks
* [The Cyber Kill Chain®](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
* [The Unified Kill Chain](https://www.unifiedkillchain.com/)
* [Diamond Model](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)
* [MITRE ATT&CK](https://attack.mitre.org/)

- - - 

## Cyber Threat Intelligence Sharing

### Formats
* [TAXII - The Trusted Automated eXchange of Indicator Information](https://oasis-open.github.io/cti-documentation/taxii/intro)
* [STIX - Structured Threat Information Expression](https://oasis-open.github.io/cti-documentation/stix/intro)

### Platforms
* [MISP - Malware Information Sharing Platform](https://www.misp-project.org/)
* [OPENCTI - Open Cyber Threat Intelligence Platform](https://www.filigran.io/en/products/opencti/)

- - - 

## Rule based detection tools
### Files
* [YARA](https://virustotal.github.io/yara/)
### Network Traffic
* [SNORT](https://www.snort.org/)
### Log Files
* [SIGMA](https://github.com/SigmaHQ/sigma)

## IDS
* [YAIDS](https://yaids.io/)
* [SNORT](https://www.snort.org/)

## IPS
* [SNORT](https://www.snort.org/)

## Blacklists/Rulesets
* [Botnet](https://feodotracker.abuse.ch/blocklist/) *(Emotet, TrickBot, Dridex, QakBot, BazarLoader, BumbleBee)* 
* [Botnet/SSL/JA3](https://sslbl.abuse.ch/blacklist/)

## SIEM
* [Splunk](https://www.splunk.com/)
* [Elastic Stack](https://www.elastic.co/elastic-stack?elektra=home&storm=stack)
    - [Elasticsearch](https://www.elastic.co/elasticsearch/)
    - [Kibana](https://www.elastic.co/kibana/)
    - [Integrations](https://www.elastic.co/integrations/)

## EXTRA (To be categorized)
* [YARAhub](https://yaraify.abuse.ch/yarahub/)
* [YARAify Search](https://yaraify.abuse.ch/search/)

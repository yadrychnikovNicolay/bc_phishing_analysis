# phishing_analysis - emails

## Case
Your colleagues have provided you with emails in .eml format, ".eml" files are individual email files stored in Multipurpose Internet Mail Extensions (MIME) format. To scan .eml emails, you can use tools such as email clients (Outlook, Thunderbird, etc.), email viewing applications, or specialized tools such as email scanners.

Here are some general steps you can take to scan an .eml file:

- Open the .eml file in an email client or email viewing application. You can also open the .eml file with a text editor to see the source code of the email.
- Check the email headers to identify the sender, recipient, date and subject information. You may also find additional information, such as the mail servers involved in the transmission of the message.
- Check the content of the email for signs of phishing, such as suspicious links or requests for sensitive data.
- Check attachments for malicious files, such as macros or scripts.
- Use email analysis tools to extract additional information from the email, such as IP addresses of email servers or additional headers.

## Report
- What is the email's timestamp? 
- Who is the email from?
- What is his email address?
- What email address will receive a reply to this email? 
- What brand was this email tailored to impersonate?
- What is the originating IP? Defang the IP address. 
- What do you think will be a domain of interest? Defang the domain.
- What is the shortened URL? Defang the URL.
- Do you think this is a phishing email?

## Tools
#### [VirusTotal](https://www.virustotal.com/gui/home/upload)
VirusTotal was founded in 2004 as a free service that analyzes files and URLs for viruses, worms, trojans and other kinds of malicious content. Our goal is to make the internet a safer place through collaboration between members of the antivirus industry, researchers and end users of all kinds. Fortune 500 companies, governments and leading security companies are all part of the VirusTotal community, which has grown to over 500,000 registered users.

#### [PhishTools](https://www.phishtool.com/)  
Be you a security researcher investigating a new phish-kit, a SOC analyst responding to user reported phishing, a threat intelligence analyst collecting phishing IoCs or an investigator dealing with email-born fraud.

PhishTool combines threat intelligence, OSINT, email metadata and battle tested auto-analysis pathways into one powerful phishing response platform. Making you and your organisation a formidable adversary - immune to phishing campaigns that those with lesser email security capabilities fall victim to.

#### [MX Lookup](https://mxtoolbox.com/)
This test will list MX records for a domain in priority order. The MX lookup is done directly against the domain's authoritative name server, so changes to MX Records should show up instantly. You can click Diagnostics , which will connect to the mail server, verify reverse DNS records, perform a simple Open Relay check and measure response time performance. You may also check each MX record (IP Address) against 105 DNS based blacklists 

#### [PhishTank](https://phishtank.com/?)
PhishTank is a collaborative clearing house for data and information about phishing on the Internet. Also, PhishTank provides an open API for developers and researchers to integrate anti-phishing data into their applications at no charge.

#### [Spamhaus](https://www.spamhaus.org/)
Spamhaus is the world leader in supplying realtime highly accurate threat intelligence to the Internet's major networks.

#### [Phishing incident response](https://www.incidentresponse.org/playbooks/phishing)  
The phishing incident response playbook contains all 7 steps defined by the NIST incident response process: Prepare, Detect, Analyze, Contain, Eradicate, Recover, Post-Incident Handling.

#### [EML Analyzer](https://eml-analyzer.herokuapp.com/)
Simple EML Analyzer

#### [CyberChef Defanger](https://gchq.github.io/CyberChef/#recipe=Defang_URL(true,true,true,'Valid%20domains%20and%20full%20URLs')Defang_IP_Addresses())
Defang URLS and IP Addresses


## Writeup

### email_1
Timestamp: Mon, 20 Mar 2023 08:57:04 -0700  
From: Paypal  
Email From: service@paypal.be  
Email Reply-To: service@paypal.be  
Brand Impersonated: ---  
Originating IP: 66[.]211[.]170[.]87  
Domain of Interest: hxxps[://]www[.]paypal[.]com  
Shortened URL: ---  
Phishing?: No  

### email_2
Timestamp: Mon, 12 Dec 2022 09:56:36 +0100  
From: "Trust"  
Email From: stainless@midnightmagicevents.com  
Email Reply-To: stainless@midnightmagicevents.com  
Brand Impersonated: Trust  
Originating IP: 85[.]209[.]134[.]107  
Domain of Interest: hxxps[://]climovil[.]com  
Shortened URL: ---  
Phishing?: Yes  

### email_3
Timestamp: Sun, 26 Mar 2023 13:31:56 +0000  
From: "Tinder"  
Email From: gq@80-78-255-128.cloudvps.regruhosting.ru  
Email Reply-To: gq@80-78-255-128.cloudvps.regruhosting.ru  
Brand Impersonated: Tinder  
Originating IP: 80[.]78[.]255[.]128  
Domain of Interest: hxxp[://]blog[.]tulingxueyuan[.]cn  
Shortened URL: ---  
Phishing?: Yes  

### email_4
Timestamp: Fri, 3 Mar 2023 12:44:01 +0100  
From: "Dr. Dan Miller"  
Email From: babakingsouthmichael@gmail.com  
Email Reply-To: babakingsouthmichael@gmail.com  
Brand Impersonated: UNDRR  
Originating IP: 209[.]85[.]220[.]41  
Domain of Interest: ---  
Shortened URL: ---  
Phishing?: Yes  

### email_5
Timestamp: Sat, 27 Aug 2022 09:42:09 +0000  
From: "Ariana"  
Email From: newsmail@app9l.serenitepure.fr  
Email Reply-To: news@aichakandisha.com  
Brand Impersonated: SerenitePure?  
Originating IP: 51[.]83[.]34[.]109  
Domain of Interest: hxxp[://]serenitepure[.]fr  
Shortened URL: ---  
Phishing?: Yes  

## General Thought Process
In general, when the "From" field mentions a well known brand but the actual email address is something weird like dfqssf.randomassdomain.cn, it usually means it's a scam.
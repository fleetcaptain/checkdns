## CheckDNS
CheckDNS automates processing subdomain records, with an eye on subdomain takeover. Given input subdomains, checkdns filters subdomains that are live according to public DNS resolvers and outputs any A or CNAME records. Sifting through the A records may yield additional in-scope hosts for a penetration test while CNAME records and their corresponding destination address can be quickly reviewed for potential subdomain takeovers.


## Screenshot
![CheckDNS screenshot](https://cp270.files.wordpress.com/2018/01/checkdns.png)


## Usage

Process subdomains from a file

``python checkdns.py -i subdomains.txt``


Process subdomains and save the results to a file

``python checkdns.py -i subdomains.txt -o output.txt``


The input file should contain subdomains, one per line. The subdomains should be in FQDN format. For example:

*subdomain.example.com*

*mail.example.com*

*someservice.example.com*


If the top level domain is not present (file contains only hostnames or subdomain names), then the -d option can be used to append the TLD after the subdomain. For example, with input like...

*subdomain*

*mail*

*someservice*


...you can run ``python checkdns.py -i subdomains.txt -d example.com``. 

As a side note, using this method CheckDNS can brute force or enumerate potential subdomain names. However, it is not designed to do this - it's a processing tool for when you have a list of discovered subdomains and want to know more details for each subdomain.


## License
CheckDNS is licensed under the GNU GPL license, which can be found [here](https://github.com/fleetcaptain/checkdns/blob/master/LICENSE).

Please respect legal restrictions and conduct testing only against infrastructure which you have permission to target.


## Version
Version 1.0 1/15/18

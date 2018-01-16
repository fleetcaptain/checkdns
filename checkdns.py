#!/usr/bin/env/python
# CheckDNS
# version 1.0
# by Carl Pearson - github.com/fleetcaptain

import sys
import dns.resolver
from optparse import OptionParser

Resolver = dns.resolver.Resolver()

# print header/banner
def print_banner():
	print ""
	print "      ______              ___   _____  __  ______"
	print "     / __| |___ ____  ____| |__ |  _ \|  \| |    |"
	print "    | /  |  _  \` __`|  __| / / | | | |   | | ---|"
	print "    | \__| | | | |___| |__|   \ | |_| | |   |--- |"
	print "     \___|_|_|_|_____|____|_|\_\|____/|_|\__|____/"
	print ""
	print "                             Coded by Carl Pearson"
	print "                           github.com/fleetcaptain"
	print ""

# given a subdomain and resolver, query resolver to a) verify record is "live" (i.e. we get a reply) and b) see if it's an A or CNAME record
def lookup(guess, name_server):
	Resolver.nameservers = [name_server]
	answer = None
	try:
		# obtain the DNS reply in DIG format, convert to string, and split newlines into an array
		answer = str(Resolver.query(guess).response).split('\n')
	except:
		return "ERROR", "e"
	# If we didn't get NXDOMAIN or like error, then proceed
	'''
	The answer in DIG format looks like this

	id 35423
	opcode QUERY
	rcode NOERROR
	flags QR RD RA
	;QUESTION
	myservice.example.com. IN A
	;ANSWER
	myservice.example.com. 299 IN CNAME myservice.cloudservice.net.
	myservice.cloudservice.net. 9 IN A 500.600.700.800
	;AUTHORITY
	;ADDITIONAL

	we grab the first line after ";ANSWER" - it's the first answer and the one we care about. 
	May be the only answer depending on the specific host (like if it's an A record only 1 IP may be returned)
	'''
	answerline = ""
	for x in range(0, len(answer)): # for each line
		if answer[x] == ";ANSWER":
			answerline = answer[x + 1] # first answer
			break
	lineitems = answerline.split(' ')
	host = lineitems[len(lineitems) - 1] # host is the last line
	host = host[:-1] # remove the trailing period
	# determine if this is a CNAME or A record. A records can be interesting to find vulnerable hosts and CNAME
	# records can be interesting for subdomain takeover
	for item in lineitems:
		if item == 'CNAME':
			return "CNAME", host
		elif item == 'A':
			return "A", host




# ---------------------
# -- Begin Main Code --
# ---------------------

# Initialize variables
resolvers = ['8.8.8.8', '8.8.4.4', '9.9.9.9', '75.75.75.75']
server = 0
count = 0
rtype = ""
record = ""
cnames = []
ahosts = []

print_banner()

# Parse options
parser = OptionParser()
parser.add_option("-i", "--input", dest="input_file", help="File with subdomains to check. Subdomains should be listed one per line")
parser.add_option("-o", "--output", dest="out_file", help="Write results to specified output file")
parser.add_option("-d", "--domain", dest="domain", help="Top level domain to target. Required if the subdomain file contains subdomain/host names only and not the FQDN (i.e. 'myservice' instead of 'myservice.example.com')")

(options, args) = parser.parse_args()
domain = options.domain
input_file = options.input_file
out_file = options.out_file

# Input file is required
if (input_file == None):
	print '[!] Error: you must specify a source file with subdomains!'
	print parser.usage
	exit()

print "Usage: checkdns.py <file with subdomain list> (top level domain) (output file)"
f = open(input_file, 'r')
data = f.readlines()
f.close()
total = str(len(data))
print 'Read ' + total + ' subdomains from input file'
print 'Checking subdomains, please wait...'

# for each subdomain in the data
for subdomain in data:
	try:
		name = subdomain.strip('\n').strip('\r')
		if (domain != None and domain not in name):
			(rtype, record) = lookup(name + '.' + domain, resolvers[server])
		else:
			(rtype, record) = lookup(name, resolvers[server])

		# if the query did not return an error, then add result to appropriate array
		if rtype != "ERROR":
			if rtype == "CNAME":
				cnames.append(name + " -->-- " + record)
			elif rtype == "A":
				ahosts.append(name + " -->-- " + record)

		# round robin the resolvers
		server = server + 1
		server = server % len(resolvers)
		count = count + 1

		# update user on progress so far
		if (count % 30) == 0:
			print str(count) + '/' + total
	except KeyboardInterrupt:
		print '\nUser exit'
		exit()

# sort the arrays for nicer alphabetical order
ahosts.sort()
cnames.sort()

# print results to user
print ""
print '== A records =='
for x in range(0, len(ahosts)):
	print ahosts[x]
print ""
print '== CNAME records =='
for x in range(0, len(cnames)):
	print cnames[x]

# if the user asked us to save the results to a file, do so here
if (out_file != None):
	f = open(out_file, 'w')
	f.write('== A records ==\n')
	for x in range(0, len(ahosts)):
		f.write(ahosts[x] + '\n')
	f.write('\n== CNAME records ==\n')
	for x in range(0, len(cnames)):
		f.write(cnames[x] + '\n')
	print ''
	print 'Results saved to ' + out_file



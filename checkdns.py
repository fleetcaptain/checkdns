#!/usr/bin/env/python
# CheckDNS
# by Carl Pearson - github.com/fleetcaptain

import sys
import dnslib
from optparse import OptionParser

debug = False


# print header/banner
def print_banner():
	print ""
	print "      ___ _                _     ____  __  _ ____"
	print "     / __| |___ ____  ____| |__ |  _ \|  \| |    |"
	print "    | /  |  _  \` __`|  __| / / | | | |   | | ---|"
	print "    | \__| | | | |___| |__|   \ | |_| | |   |--- |"
	print "     \___|_|_|_|_____|____|_|\_\|____/|_|\__|____/ v1.2"
	print ""
	print "                             Coded by Carl Pearson"
	print "                           github.com/fleetcaptain"
	print ""



# given a subdomain and resolver, query resolver to a) verify record is "live" (i.e. we get a reply) and b) see if it's an A or CNAME record
def lookup(guess, name_server):
	if (debug):
		print 'Trying ' + guess + ' at ' + name_server
	use_tcp = False
	response = None
	failed = False
	record_type = ""
	record_value = ""
	query = dnslib.DNSRecord.question(guess)
	try:
		response_q = query.send(name_server, 53, use_tcp, timeout = 3)
		if response_q:
			if (debug):
				print "response_q: " + response_q + "\n"
			response = dnslib.DNSRecord.parse(response_q)
	except KeyboardInterrupt:
		print 'User exit'
		exit()
	except:
		# probably socket timed out
		print "ERROR - possible socket timeout when trying " + guess
		pass
	if response:
		if debug:
			print "Decoded response:\n" + str(response) + "\n"
		rcode = dnslib.RCODE[response.header.rcode]
		
		if rcode == 'NOERROR' or rcode == 'NXDOMAIN':
			# success, this is a valid subdomain
			if debug:
				print "response.rr:\n" + str(response.rr) + "\n"
			for r in response.rr: 
			# note that we are looping through each piece of the answer but we only return from this method once... we must pick what we return verrry carefully, see explantion below
				if debug:
					print "r:\n" + str(r) + "\n"
				rtype = None
				try:
					rtype = str(dnslib.QTYPE[r.rtype])
				except:
					rtype = str(r.rtype)
				#print rtype
				
				if (rtype == 'CNAME'):
					#print r.rdata
					record_type = 'CNAME'
					record_value = str(r.rdata)
					''' 
					*Why the following break keyword is here
					So if we submit a query and get back a CNAME, the response contains the CNAME record and also the 
					CNAME records' record, and so on down to the A or AAAA record with the final IP address for the
					query we submitted. 
					Example:
					;; ANSWER SECTION:
					support.indeed.com.	7200	IN	CNAME	indeed.zendesk.com.
					indeed.zendesk.com.	900	IN	A	52.34.200.91
					indeed.zendesk.com.	900	IN	A	35.167.245.158
					indeed.zendesk.com.	900	IN	A	34.216.174.56

					That's fine, and we loop through each of these "answers" in the 'for r in response.rr' loop.
					PROBLEM: we were overwriting the value of record_type and record_value each time around the loop. 
					So if the first 'r' was a CNAME record we wouldn't know about it since the subsequent A/AAAA record would update 'record_type
					and record_value to reflect the A record not the first CNAME record!
					The user would see the subdomain as a plain A record but that wasn't true...
					Since this is structered as a method call that returns a single record type and value pair, and because
					we care more about the CNAME record our query points to than the IP (at least for subdomain takeover recon), we will
					halt analysis and return the CNAME data if we encounter a CNAME record. We care that a domain name points to an
					AWS bucket, for example, not the particular Amazon IP it ultimately has to talk to.
					'''
					break 
				elif (rtype == 'A' or rtype == 'AAAA'):
					record_type = 'A'
					record_value = str(r.rdata)
		else:
			print "ERROR - returned stats " + rcode + " when trying " + guess
	else:
		print "error with response: " + response
	return record_type, record_value
	




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
parser.add_option("--debug", dest="debug", action="store_true", help="Enable verbose debug output")

(options, args) = parser.parse_args()
domain = options.domain
input_file = options.input_file
out_file = options.out_file
debug = options.debug

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

quit_flag = 0

# for each subdomain in the data
for subdomain in data:
	if (' ' not in subdomain):
		try:
			name = subdomain.replace('\n', '').replace('\r', '')
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

			# did user quit
			if (quit_flag == 1):
				exit()
				break
		except KeyboardInterrupt:
			print '\nUser exit'
			quit_flag = 1
			exit()
		except:
			# Generally unknown error. Keep going
			# Known errors: subdomain sample starting with a dot, ex .domain.com
			continue

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


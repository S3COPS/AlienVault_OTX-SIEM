#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Get-OTX-IOCs
# Retrieves IOCs from Open Threat Exchange
#
# Create an account and select your feeds
# https://otx.alienvault.com
#
# AUTHOR KSQ: https://github.com/S3COPS @opsecure
# Adapted from Original Script by Neo23x0: https://github.com/Neo23x0/signature-base
# Using AlienVault SDK for OTXv2: https://github.com/AlienVault-OTX/OTX-Python-SDK
# 
# 

from OTXv2 import OTXv2
# from pandas.io.json import json_normalize
# from datetime import datetime, timedelta
import re
import os
import sys
import syslog
import logging
import traceback
import argparse

#############################################################################################
# ENTER OTX API HERE:
#############################################################################################
OTX_KEY = ''

#############################################################################################
# WHITELISTS AND EXCEPTIONS
#############################################################################################
# ENTER ANY WHITELIST HASHES HERE:
HASH_WHITELIST = ['e617348b8947f28e2a280dd93c75a6ad','125da188e26bd119ce8cad7eeb1fc2dfa147ad47','06f7826c2862d184a49e3672c0aa6097b11e7771a4bf613ec37941236c1a8e20']

# ENTER ANY WHITELIST DOMAINS HERE:
DOMAIN_WHITELIST = ['proofpoint.com']

# ENTER ANY WHITELIST URLS HERE:
URL_WHITELIST = ['https://www.my-whitelisted-url.com']

#############################################################################################

class WhiteListedIOC(Exception): pass

class OTXReceiver():

	# IOC STRINGS
	hash_iocs = ""
	filename_iocs = ""
	c2_iocs = ""
	c2_domain_iocs = ""
	c2_ip_iocs = ""
	url_iocs = ""
	mutex_iocs = ""
	email_iocs = ""
	cve_iocs = ""

	# OUTPUT FORMATS
	separator = ";"
	use_csv_header = False
	extension = "txt"
	hash_upper = False
	filename_regex_out = True

	def __init__(self, api_key, siem_mode, debug, proxy):
		self.debug = debug
		self.otx = OTXv2(api_key, proxy)
		if siem_mode:
			# CSV Separator is not the default comma due to poor validation practices in the OTC Name Field
			self.separator = ";"
			self.use_csv_header = True
			self.extension = "csv"
			self.hash_upper = True
			self.filename_regex_out = False

	def get_iocs_last(self):

# UNCOMMENT THE mtime LINE TO DOWNLOAD LAST n DAYS
		# mtime = (datetime.now() - timedelta(days=days_to_load)).isoformat()
		print "Starting OTX feed download ..."
		self.events = self.otx.getall()
		print "Download complete - %s events received" % len(self.events)
		# json_normalize(self.events)

	def write_iocs(self, ioc_folder):

		hash_ioc_file = os.path.join(ioc_folder, "otx-hash-iocs.{0}".format(self.extension))
		filename_ioc_file = os.path.join(ioc_folder, "otx-filename-iocs.{0}".format(self.extension))
		c2_ioc_file = os.path.join(ioc_folder, "otx-c2-iocs.{0}".format(self.extension))
		c2_domain_ioc_file = os.path.join(ioc_folder, "otx-c2-domain-iocs.{0}".format(self.extension))
		c2_ip_ioc_file = os.path.join(ioc_folder, "otx-c2-ip-iocs.{0}".format(self.extension))
		url_ioc_file = os.path.join(ioc_folder, "otx-url-iocs.{0}".format(self.extension))
		mutex_ioc_file = os.path.join(ioc_folder, "otx-mutex-iocs.{0}".format(self.extension))
		email_ioc_file = os.path.join(ioc_folder, "otx-email-iocs.{0}".format(self.extension))
		cve_ioc_file = os.path.join(ioc_folder, "otx-cve-iocs.{0}".format(self.extension))


		print "Processing indicators ......."
		for event in self.events:
			try:
				for indicator in event["indicators"]:

					try:
# Capture Hashes - flagged as 'FileHash-MD5', 'FileHash-SHA1' or 'FileHash-SHA256' in OTX feed
						if indicator["type"] in ('FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256'):

							# Whitelisting
							if indicator["indicator"] in HASH_WHITELIST:
								raise WhiteListedIOC

							hash = indicator["indicator"]
							if self.hash_upper:
								hash = indicator["indicator"].upper()

							self.hash_iocs += "{0}{8}{1}{8}{2}{8}{3}{8}{4}{8}{5}{8}{6}{8}{7}\n".format(
								hash,
								event["name"].encode('unicode-escape'),
								event["TLP"].encode('unicode-escape'),
								event["author_name"].encode('unicode-escape'),
								event["created"].encode('unicode-escape'),
								event["modified"].encode('unicode-escape'),
								event["id"].encode('unicode-escape'),
								" | ".join(event["references"])[:1000],
								self.separator)


# Capture FilePaths - flagged as 'FilePath' in OTX feed
						if indicator["type"] == 'FilePath':

							filename = indicator["indicator"]
							if self.filename_regex_out:
								filename = (indicator["indicator"])

							self.filename_iocs += "{0}{8}{1}{8}{2}{8}{3}{8}{4}{8}{5}{8}{6}{8}{7}\n".format(
								filename,
								event["name"].encode('unicode-escape'),
								event["TLP"].encode('unicode-escape'),
								event["author_name"].encode('unicode-escape'),
								event["created"].encode('unicode-escape'),
								event["modified"].encode('unicode-escape'),
								event["id"].encode('unicode-escape'),
								" | ".join(event["references"])[:1000],
								self.separator)

# Capture Domains - flagged as 'domain' or 'hostname' in OTX feed
						if indicator["type"] in ('domain', 'hostname'):

							c2_domain = indicator["indicator"]

							self.c2_domain_iocs += "{0}{8}{1}{8}{2}{8}{3}{8}{4}{8}{5}{8}{6}{8}{7}\n".format(
								c2_domain,
								event["name"].encode('unicode-escape'),
								event["TLP"].encode('unicode-escape'),
								event["author_name"].encode('unicode-escape'),
								event["created"].encode('unicode-escape'),
								event["modified"].encode('unicode-escape'),
								event["id"].encode('unicode-escape'),
								" | ".join(event["references"])[:1000],
								self.separator)


# Capture IP Addresses - flagged as 'IPv4' or 'IPv6' in OTX feed
						if indicator["type"] in ('IPv4', 'IPv6'):

							c2_ip = indicator["indicator"]

							self.c2_ip_iocs += "{0}{8}{1}{8}{2}{8}{3}{8}{4}{8}{5}{8}{6}{8}{7}\n".format(
								c2_ip,
								event["name"].encode('unicode-escape'),
								event["TLP"].encode('unicode-escape'),
								event["author_name"].encode('unicode-escape'),
								event["created"].encode('unicode-escape'),
								event["modified"].encode('unicode-escape'),
								event["id"].encode('unicode-escape'),
								" | ".join(event["references"])[:1000],
								self.separator)


# Capture URL's - flagged as 'URL' or 'URI' in OTX feed
						if indicator["type"] in ('URL', 'URI'):

							url = indicator["indicator"]

							self.url_iocs += "{0}{8}{1}{8}{2}{8}{3}{8}{4}{8}{5}{8}{6}{8}{7}\n".format(
								url,
								event["name"].encode('unicode-escape'),
								event["TLP"].encode('unicode-escape'),
								event["author_name"].encode('unicode-escape'),
								event["created"].encode('unicode-escape'),
								event["modified"].encode('unicode-escape'),
								event["id"].encode('unicode-escape'),
								" | ".join(event["references"])[:1000],
								self.separator)


# Capture MUTEX - flagged as 'Mutex' in OTX feed
						if indicator["type"] == 'Mutex':

							mutex = indicator["indicator"]

							self.mutex_iocs += "{0}{8}{1}{8}{2}{8}{3}{8}{4}{8}{5}{8}{6}{8}{7}\n".format(
								mutex,
								event["name"].encode('unicode-escape'),
								event["TLP"].encode('unicode-escape'),
								event["author_name"].encode('unicode-escape'),
								event["created"].encode('unicode-escape'),
								event["modified"].encode('unicode-escape'),
								event["id"].encode('unicode-escape'),
								" | ".join(event["references"])[:1000],
								self.separator)


# Capture EMAILS - flagged as 'email' in OTX feed
						if indicator["type"] == 'email':

							email = indicator["indicator"]

							self.email_iocs += "{0}{8}{1}{8}{2}{8}{3}{8}{4}{8}{5}{8}{6}{8}{7}\n".format(
								email,
								event["name"].encode('unicode-escape'),
								event["TLP"].encode('unicode-escape'),
								event["author_name"].encode('unicode-escape'),
								event["created"].encode('unicode-escape'),
								event["modified"].encode('unicode-escape'),
								event["id"].encode('unicode-escape'),
								" | ".join(event["references"])[:1000],
								self.separator)


# Capture CVE- flagged as 'CVE' in OTX feed
						if indicator["type"] == 'CVE':

							cve = indicator["indicator"]

							self.cve_iocs += "{0}{8}{1}{8}{2}{8}{3}{8}{4}{8}{5}{8}{6}{8}{7}\n".format(
								cve,
								event["name"].encode('unicode-escape'),
								event["TLP"].encode('unicode-escape'),
								event["author_name"].encode('unicode-escape'),
								event["created"].encode('unicode-escape'),
								event["modified"].encode('unicode-escape'),
								event["id"].encode('unicode-escape'),
								" | ".join(event["references"])[:1000],
								self.separator)

					except WhiteListedIOC, e:
						pass

			except Exception, e:
				traceback.print_exc()


###########################################################################################################
		# WRITE TO FILES
###########################################################################################################

		# WRITE HASHES
		with open(hash_ioc_file, "w") as hash_fh:
			if self.use_csv_header:
				hash_fh.write('hash{0}name{0}tlp{0}author_name{0}created{0}modified{0}pulse_id{0}references\n'.format(self.separator))
				#('hash{0}description\n'.format(self.separator))
			hash_fh.write(self.hash_iocs)
			print "{0} hash iocs written to {1}".format(self.hash_iocs.count('\n'), hash_ioc_file)

		# WRITE FILENAMES
		with open(filename_ioc_file, "w") as fn_fh:
			if self.use_csv_header:
				fn_fh.write('filename{0}name{0}tlp{0}author_name{0}created{0}modified{0}pulse_id{0}references\n'.format(self.separator))
			fn_fh.write(self.filename_iocs)
			print "{0} filename iocs written to {1}".format(self.filename_iocs.count('\n'), filename_ioc_file)

		# WRITE C2 DOMAINS
		with open(c2_domain_ioc_file, "w") as c2d_fh:
			if self.use_csv_header:
				c2d_fh.write('domain{0}name{0}tlp{0}author_name{0}created{0}modified{0}pulse_id{0}references\n'.format(self.separator))
			c2d_fh.write(self.c2_domain_iocs)
			print "{0} c2 domain iocs written to {1}".format(self.c2_domain_iocs.count('\n'), c2_domain_ioc_file)

		# WRITE C2 IP ADDRESSES
		with open(c2_ip_ioc_file, "w") as c2i_fh:
			if self.use_csv_header:
				c2i_fh.write('ip{0}name{0}tlp{0}author_name{0}created{0}modified{0}pulse_id{0}references\n'.format(self.separator))
			c2i_fh.write(self.c2_ip_iocs)
			print "{0} c2 IP iocs written to {1}".format(self.c2_ip_iocs.count('\n'), c2_ip_ioc_file)

		# WRITE URLS
		with open(url_ioc_file, "w") as url_fh:
			if self.use_csv_header:
				url_fh.write('url{0}name{0}tlp{0}author_name{0}created{0}modified{0}pulse_id{0}references\n'.format(self.separator))
			url_fh.write(self.url_iocs)
			print "{0} URL iocs written to {1}".format(self.url_iocs.count('\n'), url_ioc_file)

		# WRITE MUTEX
		with open(mutex_ioc_file, "w") as mutex_fh:
			if self.use_csv_header:
				mutex_fh.write('mutex{0}name{0}tlp{0}author_name{0}created{0}modified{0}pulse_id{0}references\n'.format(self.separator))
			mutex_fh.write(self.mutex_iocs)
			print "{0} MUTEX iocs written to {1}".format(self.mutex_iocs.count('\n'), mutex_ioc_file)

		# WRITE EMAILS
		with open(email_ioc_file, "w") as email_fh:
			if self.use_csv_header:
				email_fh.write('email{0}name{0}tlp{0}author_name{0}created{0}modified{0}pulse_id{0}references\n'.format(self.separator))
			email_fh.write(self.email_iocs)
			print "{0} Email iocs written to {1}".format(self.email_iocs.count('\n'), email_ioc_file)

		# WRITE CVE
		with open(cve_ioc_file, "w") as cve_fh:
			if self.use_csv_header:
				cve_fh.write('cve{0}name{0}tlp{0}author_name{0}created{0}modified{0}pulse_id{0}references\n'.format(self.separator))
			cve_fh.write(self.cve_iocs)
			print "{0} CVE iocs written to {1}".format(self.cve_iocs.count('\n'), cve_ioc_file)

###########################################################################################################


def my_escape(string):
	return re.sub(r'([\-\(\)\.\[\]\{\}\\\+])',r'\\\1',string)


if __name__ == '__main__':

	parser = argparse.ArgumentParser(description='OTX IOC Receiver')
	parser.add_argument('-k', help='OTX API key', metavar='APIKEY', default=OTX_KEY)
	# parser.add_argument('-l', help='Time frame in days (default=30)', default=30)
	parser.add_argument('-o', metavar='dir', help='Output directory', default='/opt/threat_feeds/otx/iocs/')
	parser.add_argument('-p', metavar='proxy', help='Proxy server (e.g. http://proxy:8080 or '
													'http://user:pass@proxy:8080', default=None)
	parser.add_argument('--verifycert', action='store_true', help='Verify the server certificate', default=False)
	parser.add_argument('--siem', action='store_true', default=False, help='CSV Output for use in SIEM systems')
	parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

	args = parser.parse_args()

	if len(args.k) != 64:
		print "Set an API key in script or via -k APIKEY. Go to https://otx.alienvault.com create an account and get your own API key"
		sys.exit(0)

	# Create a receiver
	otx_receiver = OTXReceiver(api_key=args.k, siem_mode=args.siem, debug=args.debug, proxy=args.p)

	# Retrieve the events and store the IOCs
	# otx_receiver.get_iocs_last(int(args.l))
	otx_receiver.get_iocs_last()

	# Write IOC files
	otx_receiver.write_iocs(ioc_folder=args.o)

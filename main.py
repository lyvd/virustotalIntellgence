'''
Upload a file for scanning with VirusTotal
POST /vtapi/v2/file/scan allows you to send a file for scanning with VirusTotal
'''
import os.path
import argparse
import hashlib
import FileInfo
import constants
import sys
import requests
import time

def parse_pe(newFile, avName = "Microsoft"):

	# create FileInfo class
	fileInfo = FileInfo.Info()

	# set name
	fileInfo.setName((os.path.split(newFile)[1]))

	# get sha256 hash
	sha1 = hashlib.sha256(open(newFile, 'rb').read()).hexdigest()



	# set hash
	fileInfo.setHash(sha1)

	# get size
	fileInfo.setSizeOfFile(os.path.getsize(newFile))

	# display name
	print("File name : %s " % (fileInfo.getName()))

	# display hash
	print("File Hash: " + fileInfo.getHash())

	# display size
	print("File Size : %d " % (fileInfo.getSizeOfFile()))

	fileSize = fileInfo.getSizeOfFile()

	# Check whether file size is lower than limit size
	if fileSize >= constants.limit_size:
		print("Hello")
		
		# Informs user to decide scanning hash instead
		userinp = raw_input('File ' + fileInfo.getName() + ' is larger than 32M. Submit its hash instead ? [Y/n]')

		# if user don't want to submit hash
		if userinp == 'n' or userinp == 'N':
			sys.exit('Please choose a different filename and try again.')

		# if user want to 
		elif userinp == 'y' or userinp == 'Y' or userinp == '':

			# hash submission function
			print("Hello")

		# other cases
		else:
			sys.exit('Invalid userinput')
			
	else:

		# upload file to virustotal
		scanResult = file_scan(newFile, fileInfo)

		# if successfull get file scan report
		if int(scanResult["response_code"]) == 1:

			# set scan ID for later retrieving the report
			fileInfo.setScanId(scanResult["scan_id"])

			# set permalink
			fileInfo.setPermalink(scanResult["permalink"])

			# Display scan id
			print("Scan ID: %s" % (fileInfo.getScanId()))
			print("Permanent link: %s" % (fileInfo.getPermalink()))

		# get report of given scan ID
		report = get_report(fileInfo.getHash()) 
		print("Report")
		#print(report)  

		# if get the report successfully
		if int(report["response_code"] == 1):

			# total Av
			fileInfo.setTotalAv(report['total'])

			# av positives
			fileInfo.setAvPositives(report['positives'])

			# Scan date of the hash
			fileInfo.setScanDate(report['scan_date'])

			# Antivirus label
			for i in report['scans']:

				av = FileInfo.AV()
				# set AV name
				av.setName(i)

				# set detected result
				av.setDetected(report['scans'][i][constants.av_detected]) 

				# set version
				av.setVersion(report['scans'][i][constants.av_version])

				# set result
				av.setResult(report['scans'][i][constants.av_result])

				# AV update
				av.setUpdate(report['scans'][i][constants.av_update])

				# set trusted AV
				av.setTrusted()

				#print("AV trusted ", av.getTrusted())
				
				# Save AV info to the list
				fileInfo.saveAvInfo(av)


		#print(behavior)
		print("Number of AVs: %d" % (fileInfo.getTotalAv()))
		print("Number of Positive AVs: %d" % (fileInfo.getAvPositives()))
		print("AV %s: %s" % (avName, fileInfo.AvDetected(avName)))
		print("Virus name: %s" % (fileInfo.getVirusName(avName)))
		print("Scan date: %s " % (fileInfo.getScanDate()))
		print("Malware score: %d " %(fileInfo.mal_score()))
		#print("Trusted AV: %s " %(fileInfo.isAvTrusted()))

		# listing out all of AVs
		#for i in fileInfo.av:
		#	print("AV name: %s \n Trusted: %s " %(i.getName(), i.getTrusted()))
		#fileInfo.getAvLabel(avName)

		# get file behavior
		#behavior = get_behavior(fileInfo.getHash())
		#print("Response code %d: " % behavior['response_code'])

		# search
		#filesearch = search()
		#print(filesearch)


'''
Calculate malware score base on the detection rates of the antivirus
Intially, if a malware is decteted by more than three Avs, we consider it malicious.
'''
#def malw_score()
def file_scan(newFile, fileInfo):

	# parameters	
	params = {'apikey': constants.api_key}

	# files to submit
	files = {'file': (fileInfo.getName(), open(newFile, 'rb'))}

	# send a post request
	response = requests.post(constants.file_scan, files = files, params = params)

	# get a response
	json_response = response.json()

	return json_response


'''
Retrieves a concluded file scan report for a given file. Unlike the public API, this call allows
you to also access all the information we have on a particular file (VirusTotal metadata, signature
information, structural information, etc.) by using the allinfo parameter described later on.
You may use either HTTP GET or POST with this API call

'''
def get_report(resource):

	'''
	Set params. Params include:
	apikey: your api key
	resource: An md5/sha1/sha256 hash of a file for which you want to retrieve the most recent 
	antivirus report. You may also specify a scan_id (sha256-timestamp as returned by the scan API)
	to access a specific report. You can also specify a CSV list made up a combination of hashes
	and scan_ids (up to 25 items), this allows you to perform a batch request with just one single call

	allinfo (optional). If specified and set to one, the call will return additional info, other 
	than the antivirus results, on the file being queried. This additional info includes the output
	of several tools acting on the file (PDFiD, ExifTool, sigcheck, TrID, etc.), metadata regarding
	VirusTotal submissions (number of unique sources that have sent the file in the past, first seen
	date, last seen data, etc.), the output of in-house technologies such as a behavioural sandbox etc.	  
	'''

	params = {'apikey' : constants.api_key, 'resource' : resource, 'allinfo' : 1}

	# Set up headers for requests

	headers = {
	"Accept-Encoding": "gzip, deflate",
	"User-Agent" : "gzip,  My Python requests library example client or username"
	}

	try:

		# make a get request
		response = requests.get(constants.file_report, params = params, headers = headers)

	except requests.RequestException as e:
		print(e.message)
	# get the result

	json_response = response.json()

	return json_response

'''
Get file's behavior.
VirusTotal runs a distributed setup of Cuckoo sandbox machines that execute files we receive.
Execution is attempted only once, upon first submission to Virustotal, and only Portable Executables
under 10MB in size are ran. The execution of files is a best effort process, hence, there are no
guarantees about a report being generated for a given file in our data set.
Parameters
apikey: your api key
hash: the md5/sha1/sha256 hash of the file whose dynamic behavioral report you want to retrieve.
'''

def get_behavior(resource):

	# parameters
	params = {'apikey': constants.api_key, 'hash': resource}

	# headers
	headers = {
		"Accept-Encoding": "gzip, deflate",
		"User-Agent" : "gzip,  My Python requests library example client or username"
	}

	# do a request to get a report
	response = requests.get(constants.file_behavior, params = params, headers = headers)

	json_response = response.json()

	return json_response


'''
def search():

	headers = {
		"Accept-Encoding": "gzip, deflate",
		"User-Agent" : "gzip,  My Python requests library example client or username"
	}

	params = {'apikey': constants.api_key, 'query': 'type:peexe size:90kb+ positives:5+ behaviour:"taskkill"'}

	response = requests.post(constants.file_search, data = params, headers = headers)

	response_json = response.json()

	return response_json

'''
def main():

	# parse arguments

	# Create an ArgumentParser object
	parser = argparse.ArgumentParser(prog = "Virustotal Scanning", description = 'Scanning file with Virustotal')


	# Add the first argument: an file
	parser.add_argument('-f', dest='file', help='Specify a disired pe file')

	parser.add_argument('-a', dest='query_av', help='Specify a disired Antivirus vendor')
	# Let's parse arguments, the arguments are accessed through args variable
	args = parser.parse_args()


	parse_pe(args.file, args.query_av)

if __name__ == "__main__":
	main()

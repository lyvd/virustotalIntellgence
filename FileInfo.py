

class Info:

	# Construtor

	def __init__(self):

		# SHA1 as identifier
		self.hash = ""

		# AV identifier
		self.av = []

		# scan time
		self.time = ""

		# file size
		self.size = 0

		# file name
		self.name = ""

		# scan id
		# scan id lets us query the report later
		# making use of the file report retrieving API.
		self.scanId = ""

		# virustotal link
		self.permalink = ""

		# scan date
		self.scanDate = ""

		# total av
		self.totalAv = 0

		# av positives
		self.positives = 0

	# set name
	def setName(self, name):
		self.name = name

	# get name
	def getName(self):
		return self.name

	# set hash
	def setHash(self, hash):
		self.hash = hash

	# get hash
	def getHash(self):
		return self.hash

	# set file's label by an antivirus
	def saveAvInfo(self, newAv):
		self.av.append(newAv)

	# get file's label by an antivirus
	def AvDetected(self, label):

		for i in self.av:
			if(i.getName() == label):
				return i.getDetected()

	def getVirusName(self, label):
		for i in self.av:
			if(i.getName() == label):
				return i.getResult()

	# set size of a file
	def setSizeOfFile(self, size):
		self.size = size

	# get size of a file
	def getSizeOfFile(self):
		return self.size

	# set scan id
	def setScanId(self, scanId):
		self.scanId = scanId

	# get scan id
	def getScanId(self):
		return self.scanId

	# set permalink
	def setPermalink(self, link):
		self.permalink = link

	# get permalink
	def getPermalink(self):
		return self.permalink

	# set scan date
	def setScanDate(self, scanDate):
		self.scanDate = scanDate

	# get scan date
	def getScanDate(self):
		return self.scanDate

	# set total av
	def setTotalAv(self, totalAv):
		self.totalAv = totalAv

	# get total Av
	def getTotalAv(self):
		return self.totalAv

	# set av positives
	def setAvPositives(self, avPositives):
		self.positives = avPositives

	# get av positives
	def getAvPositives(self):
		return self.positives


class AV:

	# constructor
	def __init__(self):

		# av name
		self.name = ""

		# detected
		self.detected = None

		# version
		self.version = ""

		# result
		self.result = ""

		# update
		self.update = ""

	# set av name
	def setName(self, name):
		self.name = name

	# get name
	def getName(self):
		return self.name

	# set malware as detected
	def setDetected(self, detected):
		self.detected = detected

	# get detect result
	def getDetected(self):
		if self.detected == True:
			return "Detected"
		else:
			return "Not Detected"
	# set av version
	def setVersion(self, version):
		self.version = version

	# get av version
	def getVersion(self):
		return self.version

	# set result
	def setResult(self, result):
		self.result = result

	# get result
	def getResult(self):
		return self.result

	# set update
	def setUpdate(self, update):
		self.update = update

	# get update
	def getUpdate(self):
		return self.update


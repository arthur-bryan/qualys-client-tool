class Asset:
	"""
	Class that represents an Asset.

	Attributes:
		ip: IP address of the asset.
		hostname: hostname of the asset.
		vulnerabilities: list containing Vulnerabilities objects, results from detections.
	"""

	def __init__(self, ip: str, hostname: str):
		"""
		Contructor method of class Asset.

		Args:
			ip: IP address of the asset.
			hostname: hostname of the asset.
		"""
		self.ip = ip
		self.hostname = hostname
		self.vulnerabilities = []

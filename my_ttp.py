from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import sys
import random
import datetime
import pickle
import socketserver

available_specifications = {0: "RSA+SHA256", 1: "RSA+SHA384",
							2: "ECDSA+SHA256", 3: "ECDSA+SHA384"}

backend = default_backend()
rsa_private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048, backend = backend)
rsa_public_key = rsa_private_key.public_key()
ec_private_key = ec.generate_private_key(ec.SECP384R1(), backend = backend)
ec_public_key = ec_private_key.public_key()
one_day = datetime.timedelta(1, 0, 0)
specification = random.randint(0,3)

generated_certs = []

class TrustedThirdParty(socketserver.BaseRequestHandler):

	def setup(self):
		self.backend = default_backend()
		self.rsa_private_key = rsa_private_key
		self.rsa_public_key = rsa_public_key
		self.ec_private_key = ec_private_key
		self.ec_public_key = ec_public_key
		
		self.public_key = None

		self.issuer_name = x509.Name([
			x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
			x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Orissa"),
			x509.NameAttribute(NameOID.LOCALITY_NAME, u"Berhampur"),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"IITD"),
			x509.NameAttribute(NameOID.COMMON_NAME, u"iitd.ac.in")])

	def create_subject_name(self, subject_info):
		self.subject_name = x509.Name([
			x509.NameAttribute(NameOID.COUNTRY_NAME, subject_info["COUNTRY_NAME"]),
			x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_info["STATE_OR_PROVINCE_NAME"]),
			x509.NameAttribute(NameOID.LOCALITY_NAME, subject_info["LOCALITY_NAME"]),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_info["ORGANIZATION_NAME"]),
			x509.NameAttribute(NameOID.COMMON_NAME, subject_info["COMMON_NAME"])])

	def handle_csr(self, public_key):
		builder = x509.CertificateBuilder()
		builder = builder.issuer_name(self.issuer_name)
		builder = builder.subject_name(self.subject_name)
		builder = builder.not_valid_before(datetime.datetime.today() - one_day)
		builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
		builder = builder.serial_number(x509.random_serial_number())
		builder = builder.public_key(public_key)
		builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True,)
		if specification == 0:
			self.public_key = self.rsa_public_key.public_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PublicFormat.SubjectPublicKeyInfo)
			cert = builder.sign(private_key= self.rsa_private_key, algorithm=hashes.SHA256(), backend=backend)

		elif specification == 1:
			self.public_key = self.rsa_public_key.public_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PublicFormat.SubjectPublicKeyInfo)
			cert = builder.sign(private_key= self.rsa_private_key, algorithm=hashes.SHA384(), backend=backend)

		elif specification == 2:
			self.public_key = self.ec_public_key.public_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PublicFormat.SubjectPublicKeyInfo)
			cert = builder.sign(private_key= self.ec_private_key, algorithm=hashes.SHA256(), backend=backend)

		else:
			self.public_key = self.ec_public_key.public_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PublicFormat.SubjectPublicKeyInfo)
			cert = builder.sign(private_key= self.ec_private_key, algorithm=hashes.SHA384(), backend=backend)

		generated_certs.append(cert.public_bytes(serialization.Encoding.PEM))
		return cert.public_bytes(serialization.Encoding.PEM)

	def handle(self):
		request_data = self.request.recv(16384).strip()
		request_data = pickle.loads(request_data)

		if (request_data["type"] == "generate_cert"):

			print("Host {} requesting to generate certificate".format(self.client_address[0]))

			self.create_subject_name(request_data["subject_info"])
			subject_public_key = request_data["public_key"]
			cert = self.handle_csr(serialization.load_pem_public_key(subject_public_key, backend))

			response_data = dict()
			response_data.update({"cert_pem" : cert})
			response_data.update({"public_key" : self.public_key})
			response_data.update({"specification_id" : specification})
			response_data.update({"length" : sys.getsizeof(self.public_key)})

			print("Generated Certificate for the Host ", self.client_address[0], " is: ", cert)
			print("Generated Response: ", response_data)

			response = pickle.dumps(response_data)

		else:
			response = ""

		self.request.sendall(response)
		print("\n------------------------------------------------------------\n")

if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 4444

    with socketserver.TCPServer((HOST, PORT), TrustedThirdParty) as server:
    	print("The Trusted Third Party Server is running. Press Ctrl + C to close the server")
    	print("The issuer have the following Identity have COMMON_NAME: iitd.ac.in")
    	print("The Trusted Third Party server uses the ", available_specifications[specification],
    		" specification for Digital Signature")
    	print("\n\n------------------------------------------------------------\n\n")
    	server.allow_reuse_address = True
    	server.serve_forever()

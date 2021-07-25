from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID

import socket
import sys
import pickle
import time
import os
import random

"""
Server and Trusted Third Party Socket Server Parameters:
"""

available_specifications = {0: "RSA+SHA256", 1: "RSA+SHA384",
							2: "ECDSA+SHA256", 3: "ECDSA+SHA384"}

host = "127.0.0.1"
server_port = 4445
ttp_port = 4444
sock = None


class Client():
	def __init__(self):
		self.backend = default_backend()

		# The subject information of the client
		self.subject_info = dict()
		self.subject_info.update({"COUNTRY_NAME" : u"IN"})
		self.subject_info.update({"STATE_OR_PROVINCE_NAME" : u"DELHI"})
		self.subject_info.update({"LOCALITY_NAME" : u"HAUZ KHAZ"})
		self.subject_info.update({"ORGANIZATION_NAME" : u"IITD"})
		self.subject_info.update({"COMMON_NAME" : u"csz2445.iitd.ac.in"})

		# The Public Keys of the Client.
		self.ec_private_key = ec.generate_private_key(ec.SECP384R1(), self.backend)
		self.ec_public_key = self.ec_private_key.public_key()
		self.ec_serialized_public_key = self.ec_public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo)

		self.rsa_private_key = rsa.generate_private_key(public_exponent = 65537,
			key_size = 2048, backend = self.backend)
		self.rsa_public_key = self.rsa_private_key.public_key()
		self.rsa_serialized_public_key = self.rsa_public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo)

		# The certificate generated for each public key from Trusted Third Party
		self.ec_certificate = None
		self.ec_certificate_pem = None

		self.rsa_certificate = None
		self.rsa_certificate_pem = None

		# The certificated received from the server
		self.server_certificate = None
		self.server_certificate_pem = None
		self.server_public_key = None
		self.server_public_key_pem = None

		# The selected Public and Private Key and Certificated depending on specification_id
		self.public_key = None
		self.private_key = None
		self.certificate_pem = None
		self.certificate = None
		self.serialized_public_key = None

		# The specification used for digital signature
		self.server_digital_signature = None
		self.ttp_digital_signature = None
		self.client_digital_signature = None

		# The public key of TTP for verifying the server certificates
		self.ttp_public_key = None

		# TLS parameters
		self.handshake_messages = []
		self.session_parameters = None

		self.dh_private_key = None
		self.dh_public_key = None
		self.serialized_dh_public_key = None

		self.server_dh_public_key = None
		self.serialized_server_dh_public_key = None

		# TLS Key
		self.master_key = None
		self.mac_secret = None
		self.nonce = None

		# Handshake_messages
		self.handshake_messages = []

	def verify_certificate(self, certificate):
		if ((certificate.signature_algorithm_oid.dotted_string == "1.2.840.113549.1.1.11") or
			(certificate.signature_algorithm_oid.dotted_string == "1.2.840.113549.1.1.12")):
			try:
				self.ttp_public_key.verify(signature = certificate.signature,
					data = certificate.tbs_certificate_bytes,
					padding = padding.PKCS1v15(),
					algorithm = certificate.signature_hash_algorithm)
				return True
			except Exception as e:
				print(e)
				return False
		else:
			try:
				self.ttp_public_key.verify(signature = certificate.signature,
					data = certificate.tbs_certificate_bytes,
					signature_algorithm = ec.ECDSA(certificate.signature_hash_algorithm))
				return True
			except Exception as e:
				print(e)
				return False

	def get_public_key(self, certificate):
		#print("Received public_key key is", certificate.public_key().public_bytes(
		#	encoding=serialization.Encoding.PEM,
		#	format=serialization.PublicFormat.SubjectPublicKeyInfo))
		return certificate.public_key()

	def get_certificate(self):
		request_param = dict()
		request_param.update({"subject_info" : self.subject_info})
		request_param.update({"public_key" : self.ec_serialized_public_key})
		request_param.update({"type" : "generate_cert"})

		print("Request for certificate for ECDSA based public key is made: ")
		print(request_param)
		print("-------------------------------------------------------------")

		request = pickle.dumps(request_param)
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
			sock.connect((host, ttp_port))
			sock.sendall(request)
			response = sock.recv(16384)

		response_data = pickle.loads(response)

		self.ttp_public_key = serialization.load_pem_public_key(response_data["public_key"], self.backend)
		self.ttp_digital_signature = response_data["specification_id"]

		self.ec_certificate_pem = response_data["cert_pem"]
		self.ec_certificate = x509.load_pem_x509_certificate(self.ec_certificate_pem, self.backend)

		print("Certificate for ECDSA based public key received from Trusted Third Party: ")
		print(self.ec_certificate_pem)
		print("-------------------------------------------------------------")

		request_param = dict()
		request_param.update({"subject_info" : self.subject_info})
		request_param.update({"public_key" : self.rsa_serialized_public_key})
		request_param.update({"type" : "generate_cert"})

		print("Request for certificate for RSA based public key is made: ")
		print(request_param)
		print("-------------------------------------------------------------")

		request = pickle.dumps(request_param)
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
			sock.connect((host, ttp_port))
			sock.sendall(request)
			response = sock.recv(16384)

		response_data = pickle.loads(response)

		self.rsa_certificate_pem = response_data["cert_pem"]
		self.rsa_certificate = x509.load_pem_x509_certificate(self.rsa_certificate_pem, self.backend)

		print("Certificate for RSA based public key received from Trusted Third Party: ")
		print(self.rsa_certificate_pem)

	def client_hello(self):
		nonce = str(time.time())[-4:] + str(random.getrandbits(124))
		self.client_random = nonce

		cipher_spec = [
			{"key_exchg_algo": "DH", "cipher_algo": "AES", "mac_algo": "HMAC", "cipher_type": "Block"},
			{"key_exchg_algo": "DH", "cipher_algo": "AES", "mac_algo": "CMAC", "cipher_type": "Block"},
			{"key_exchg_algo": "DH", "cipher_algo": "CHACHA20", "mac_algo": "HMAC", "cipher_type": "Stream"},
			{"key_exchg_algo": "DH", "cipher_algo": "CHACHA20", "mac_algo": "CMAC", "cipher_type": "Stream"},
			{"key_exchg_algo": "ECDH", "cipher_algo": "AES", "mac_algo": "HMAC", "cipher_type": "Block"},
			{"key_exchg_algo": "ECDH", "cipher_algo": "AES", "mac_algo": "CMAC", "cipher_type": "Block"},
			{"key_exchg_algo": "ECDH", "cipher_algo": "CHACHA20", "mac_algo": "HMAC", "cipher_type": "Stream"},
			{"key_exchg_algo": "ECDH", "cipher_algo": "CHACHA20", "mac_algo": "CMAC", "cipher_type": "Stream"}
		]

		content = dict()
		content.update({"version": 1.3})
		content.update({"random": nonce})
		content.update({"session_id": str(random.getrandbits(32))})
		content.update({"cipher_suite": cipher_spec})
		content.update({"compression_method": []})

		request = dict()
		request.update({"type": "client_hello"})
		request.update({"content": content})
		request.update({"length": sys.getsizeof(content)})

		# Selection of the digital signature algorithm based on Trusted Third Party:
		if(self.ttp_digital_signature == 0) or (self.ttp_digital_signature == 1):
			self.public_key = self.ec_public_key
			self.private_key = self.ec_private_key
			self.certificate_pem = self.ec_certificate_pem
			self.certificate = self.ec_certificate
			self.serialized_public_key = self.ec_serialized_public_key

		else:
			self.public_key = self.rsa_public_key
			self.private_key = self.rsa_private_key
			self.certificate_pem = self.rsa_certificate_pem
			self.certificate = self.rsa_certificate
			self.serialized_public_key = self.rsa_serialized_public_key

		return request

	def send_request(self, request_params):
		request = pickle.dumps(request_params)
		
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
			sock.connect((host, server_port))
			sock.sendall(request)
			response =sock.recv(16384)

		response_data = pickle.loads(response)

		return response_data

	def client_certificate(self):
		request = dict()
		request.update({"type": "certificate"})
		request.update({"content": self.certificate_pem})
		request.update({"length": sys.getsizeof(self.certificate_pem)})
		return request

	def client_key_exchange(self):
		content = dict()

		# Selection of the key exchange algorithm related parameters
		if self.session_parameters["cipher_suite"]["key_exchg_algo"] == "DH" :
			content.update({"parameters": 
								{"generator" : 2, 
								 "key_size" : 1024,
								 "dh_public_key" : self.serialized_dh_public_key
								}
							})
		else:
			content.update({"parameters":
								{"ec_public_key" : self.serialized_public_key}
							})

		param = str.encode(self.client_random) + str.encode(self.server_random) + pickle.dumps(content) 

		# Generation of signature for authentication purpose
		if self.server_digital_signature == 1:
			content.update({"signature": self.private_key.sign(data = param,
				padding = padding.PKCS1v15(), algorithm = hashes.SHA256())})
		else:
			content.update({"signature": self.private_key.sign(data = param,
				signature_algorithm = ec.ECDSA(hashes.SHA256()))})

		request = dict()
		request.update({"type": "client_key_exchange"})
		request.update({"content": content})
		request.update({"length": sys.getsizeof(content)})

		return request

	def client_certificate_verify(self):

		content = dict()

		byte_message = pickle.dumps(self.handshake_messages)

		# Generation of signature for authentication purpose
		if self.server_digital_signature == 1:
			content.update({"signature": self.private_key.sign(data = byte_message,
				padding = padding.PKCS1v15(), algorithm = hashes.SHA256())})
		else:
			content.update({"signature": self.private_key.sign(data = byte_message,
				signature_algorithm = ec.ECDSA(hashes.SHA256()))})

		request = dict()
		request.update({"type": "client_certificate_verify"})
		request.update({"content": content})
		request.update({"length": sys.getsizeof(content)})

		return request

	def record_protocol(self, type, message, length):
		if type == "send" :

			print("Applying the record protocol for sending the message: ", message)
			print("\n------------------------------------------------\n")

			print("Generating the MAC of the message using ", 
				self.session_parameters["cipher_suite"]["mac_algo"],
				"algorithm")

			if self.session_parameters["cipher_suite"]["mac_algo"] == "CMAC":
				cmac_util = cmac.CMAC(algorithms.AES(self.mac_secret), self.backend)
				cmac_util.update(message)
				mac = cmac_util.finalize()

			if self.session_parameters["cipher_suite"]["mac_algo"] == "HMAC":
				hmac_util = hmac.HMAC(self.mac_secret, hashes.SHA256(), self.backend)
				hmac_util.update(message)
				mac = hmac_util.finalize()

			print("The MAC generated from the",  self.session_parameters["cipher_suite"]["mac_algo"],
				" MAC algorithm is: ", mac)
			print("------------------------------------------------------------")

			message_mac = message + mac

			print("Concatenating the message and mac for encryption: ", message_mac)
			print("------------------------------------------------------------")
			
			print("Generating the Encryption of the message using ",
				self.session_parameters["cipher_suite"]["cipher_algo"],
				"algorithm")

			if self.session_parameters["cipher_suite"]["cipher_algo"] == "AES":
				aes_cipher = Cipher(algorithms.AES(self.master_key), modes.CTR(self.nonce), self.backend)
				aes_encryptor = aes_cipher.encryptor()
				cipher_txt = aes_encryptor.update(message_mac) + aes_encryptor.finalize()

			if self.session_parameters["cipher_suite"]["cipher_algo"] == "CHACHA20":
				cha_cipher = Cipher(algorithms.ChaCha20(self.master_key, self.nonce), mode = None, backend = self.backend)
				cha_encryptor = cha_cipher.encryptor()
				cipher_txt = cha_encryptor.update(message_mac) + cha_encryptor.finalize()

			print("The Encrypted Message generated from the",  self.session_parameters["cipher_suite"]["cipher_algo"],
				" encryption algorithm is: ", cipher_txt)
			print("------------------------------------------------------------")

			return {"message": cipher_txt, "length": len(message), "size": sys.getsizeof(cipher_txt)}

		if type == "receive" :

			print("Applying the record protocol for receiving the message: ", message)
			print("\n------------------------------------------------\n")

			print("Generating the Decryption of the message using ",
				self.session_parameters["cipher_suite"]["cipher_algo"],
				"algorithm")

			if self.session_parameters["cipher_suite"]["cipher_algo"] == "AES":
				aes_cipher = Cipher(algorithms.AES(self.master_key), modes.CTR(self.nonce), self.backend)
				aes_decryptor = aes_cipher.decryptor()
				plain_txt = aes_decryptor.update(message) + aes_decryptor.finalize()

			if self.session_parameters["cipher_suite"]["cipher_algo"] == "CHACHA20":
				cha_cipher = Cipher(algorithms.ChaCha20(self.master_key, self.nonce), mode = None, backend = self.backend)
				cha_decryptor = cha_cipher.decryptor()
				plain_txt = cha_decryptor.update(message) + cha_decryptor.finalize()

			print("The Decrypted Message generated from the", self.session_parameters["cipher_suite"]["cipher_algo"],
				" encryption algorithm is: ", plain_txt)
			print("------------------------------------------------------------")

			plain_message = plain_txt[:length]
			mac = plain_txt[length:]

			print("The Message Extracted is: ", plain_message)
			print("The MAC received is: ", mac)
			print("------------------------------------------------------------")

			print("Verifying the MAC of the message using ", 
				self.session_parameters["cipher_suite"]["mac_algo"],
				"algorithm")

			if self.session_parameters["cipher_suite"]["mac_algo"] == "CMAC":
				cmac_util = cmac.CMAC(algorithms.AES(self.mac_secret), self.backend)
				cmac_util.update(plain_message)
				cmac_util.verify(mac)

			if self.session_parameters["cipher_suite"]["mac_algo"] == "HMAC":
				hmac_util = hmac.HMAC(self.mac_secret, hashes.SHA256(), self.backend)
				hmac_util.update(plain_message)
				hmac_util.verify(mac)

			print("Successfully verified the MAC of the message using ", 
				self.session_parameters["cipher_suite"]["mac_algo"],
				"algorithm")

			return plain_message

	def tls_handshake_simulate(self):

		# Cipher Suite agreement.
		print("Sending the client hello message to server: ")

		request_param = self.client_hello()

		self.handshake_messages.append(request_param)

		print("The request parameters are: ", request_param)

		response = self.send_request(request_param)

		self.handshake_messages.append(response["messages"])

		self.session_parameters = response["messages"][0]["content"]
		self.client_digital_signature = self.session_parameters["specification_id"]
		self.server_digital_signature = self.session_parameters["specification_id"] + 1
		self.server_random = self.session_parameters["random"]

		print("Received the server hello message from server: ", response["messages"][0])
		print("The client uses the ", available_specifications[self.client_digital_signature],
    		" specification for Digital Signature")
		print("\n\n------------------------------------------------------------------------------\n\n")

		# Certificate Processing
		self.server_certificate_pem = response["messages"][1]["content"]
		self.server_certificate = x509.load_pem_x509_certificate(self.server_certificate_pem, self.backend)

		print("Received the certificate from the server: ", response["messages"][1])

		print("Verifying the Certificate by using TTP public key")

		if not self.verify_certificate(self.server_certificate):
			print("The Certificate is Tempered, Closing the connection.")

		print("Verified the Certificate by using TTP public key")
		print("\n\n------------------------------------------------------------------------------\n\n")

		# Server Key Exchange Message
		if self.session_parameters["cipher_suite"]["key_exchg_algo"] == "DH" :
			self.serialized_parameters = response["messages"][2]["content"]["parameters"]["dh_parameters"]
			self.parameters = serialization.load_pem_parameters(self.serialized_parameters, self.backend)
			self.dh_private_key = self.parameters.generate_private_key()
			self.dh_public_key = self.dh_private_key.public_key()
			self.serialized_dh_public_key = self.dh_public_key.public_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PublicFormat.SubjectPublicKeyInfo)
			self.serialized_server_dh_public_key = response["messages"][2]["content"]["parameters"]["dh_public_key"]
			self.server_dh_public_key = serialization.load_pem_public_key(self.serialized_server_dh_public_key, self.backend)
			self.server_public_key = self.get_public_key(self.server_certificate)
			self.shared_key = self.dh_private_key.exchange(self.server_dh_public_key)
			self.pre_master_key = HKDF(algorithm=hashes.SHA256(),
				length=32, salt=None, info=None, backend = self.backend).derive(self.shared_key)
		else:
			self.server_public_key_pem = response["messages"][2]["content"]["parameters"]["ec_public_key"]
			self.server_public_key = serialization.load_pem_public_key(self.server_public_key_pem, self.backend)
			self.shared_key = self.private_key.exchange(ec.ECDH(), self.server_public_key)
			self.pre_master_key = HKDF(algorithm=hashes.SHA256(),
					length=32, salt=None, info=None, backend = self.backend).derive(self.shared_key)

		print("Received the server key exchange message from server: ", response["messages"][2])


		# Verify the Signature
		print("Verifying the Signature on message by using server public key")

		signature = response["messages"][2]["content"]["signature"]

		# Generating the signed message
		message_content = dict(response["messages"][2]["content"])
		del message_content["signature"]

		message_content = str.encode(self.client_random) + str.encode(self.server_random) +	pickle.dumps(message_content)

		if self.server_digital_signature == 1:
			try:
				self.server_public_key.verify(signature = signature,
					data = message_content,
					padding = padding.PKCS1v15(),
					algorithm = hashes.SHA384())
			except Exception as e:
				print(e)
		else:
			try:
				self.server_public_key.verify(signature = signature,
					data = message_content,
					signature_algorithm = ec.ECDSA(hashes.SHA384()))
			except Exception as e:
				print(e)

		print("Verified the Signature on message with server public key")
		print("\n\n------------------------------------------------------------------------------\n\n")


		# Server Certificate Request Message
		print("Received the certificate request from the server: ", response["messages"][3])
		print("\n\n------------------------------------------------------------------------------\n\n")

		# Server Done Message:
		print("Received the server_done message from the server: ", response["messages"][4])
		print("\n\n------------------------------------------------------------------------------\n\n")

		request_data = dict()
		request_data.update({"messages": []})

		request_data["messages"].append(self.client_certificate())

		# Client Certificate Message
		print("Sent the certificate to the server: ", request_data["messages"][0])
		print("\n\n------------------------------------------------------------------------------\n\n")
		
		request_data["messages"].append(self.client_key_exchange())

		# Client Key Exchange Message
		print("Sent the Client Key Exchange to the server: ", request_data["messages"][1])
		print("\n\n------------------------------------------------------------------------------\n\n")

		self.handshake_messages.append(request_data["messages"][0])
		self.handshake_messages.append(request_data["messages"][1])

		request_data["messages"].append(self.client_certificate_verify())

		# Client Key Exchange Message
		print("Sent the Client Certificate Verify to the server: ", request_data["messages"][2])
		print("\n\n------------------------------------------------------------------------------\n\n")

		request_data.update({"type": "phase-3"})
		response = self.send_request(request_data)

		print("Generating the cryptographic parameters from the pre_master_key")
		print("--------------------------------------------------------------------------")

		# Generating the cryptographic parameters from the pre_master_key
		hmac_util = hmac.HMAC(self.pre_master_key, hashes.SHA256(), self.backend)
		hmac_util.update(b"master_key" + str.encode(self.client_random) + str.encode(self.server_random))
		self.master_key = hmac_util.finalize()

		hmac_util = hmac.HMAC(self.pre_master_key, hashes.SHA256(), self.backend)
		hmac_util.update(b"mac_secret" + str.encode(self.client_random) + str.encode(self.server_random))
		self.mac_secret = hmac_util.finalize()

		hmac_util = hmac.HMAC(self.pre_master_key, hashes.SHA256(), self.backend)
		hmac_util.update(b"nonce" + str.encode(self.client_random) + str.encode(self.server_random))
		self.nonce = hmac_util.finalize()[:16]

		print("pre_master_key", self.pre_master_key)
		print("master_key", self.master_key)
		print("mac_secret", self.mac_secret)
		print("cipher_nonce", self.nonce)

		print("\n\n------------------------------------------------------------------------------\n\n")


client_obj = Client()

print("The Client is requesting for OTP for transaction from server.")
print("The subject have the following Identity, COMMON_NAME: csz2445.iitd.ac.in")

print("\n ----------------------------------------------------------------------- \n")

print("Requesting Trusted Third Party to generate a Certificate running on port 4444")
print("-----------------------------------------------------------------------")
client_obj.get_certificate()

print("\n ----------------------------------------------------------------------- \n")


print("Starting Handshake Protocol with the Server running on 4445")
client_obj.tls_handshake_simulate()
print("Handshake Protocol completed with the Server")

print("\n ----------------------------------------------------------------------- \n")


print("Framing the request for OTP from the server")
amount = random.randint(100000,999999)
message = "The OTP for transferring Rs " + str(amount) + " to your friend’s account"
message_bytes = bytes(message, "utf-8")

request_data = client_obj.record_protocol(type = "send", message = str.encode(message), length = None)
request_data.update({"type": "generate_otp"})

print("The request for OTP sent to server is ", request_data)
print("-----------------------------------------------------------------------")

response_data = client_obj.send_request(request_data)

print("The encrypted reply received from the server: ", response_data)
print("-----------------------------------------------------------------------")

received_message = client_obj.record_protocol(
	type = "receive", message = response_data["message"], length = response_data["length"])

print("The plain text version of reply received from the server: ", str(received_message, "utf-8"))
print("\n ----------------------------------------------------------------------- \n")
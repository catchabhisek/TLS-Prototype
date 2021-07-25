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
import socketserver


"""
Server and Trusted Third Party Socket Server Parameters:
"""

host = "127.0.0.1"
server_port = 4445
ttp_port = 4444

available_specifications = {0: "RSA+SHA256", 1: "RSA+SHA384",
							2: "ECDSA+SHA256", 3: "ECDSA+SHA384"}

class Server():
	def __init__(self):
		self.backend = default_backend()

		# The subject information of the server
		self.subject_info = dict()
		self.subject_info.update({"COUNTRY_NAME" : u"IN"})
		self.subject_info.update({"STATE_OR_PROVINCE_NAME" : u"DELHI"})
		self.subject_info.update({"LOCALITY_NAME" : u"HAUZ KHAZ"})
		self.subject_info.update({"ORGANIZATION_NAME" : u"IITD"})
		self.subject_info.update({"COMMON_NAME" : u"SIL765.iitd.ac.in"})

		# The Public and Private Keys of the Server.
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

		# The certificated received from the client
		self.client_certificate = None
		self.client_certificate_pem = None
		self.client_public_key = None
		self.client_public_key_pem = None

		# The selected Public and Private Key and Certificated depending on specification_id
		self.public_key = None
		self.private_key = None
		self.certificate_pem = None
		self.certificate = None
		self.serialized_public_key = None
		self.client_public_key = None

		# The specification used for digital signature
		self.server_digital_signature = None
		self.ttp_digital_signature = None
		self.client_digital_signature = None

		# The public key of TTP for verifying the server certificates
		self.ttp_public_key = None

		# TLS parameters
		self.session_parameters = None
		self.parameters = dh.generate_parameters(generator=2, key_size=1024, backend = self.backend)
		self.serialized_parameters = self.parameters.parameter_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.ParameterFormat.PKCS3)

		self.dh_private_key = self.parameters.generate_private_key()
		self.dh_public_key = self.dh_private_key.public_key()
		self.serialized_dh_public_key = self.dh_public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo)

		self.client_dh_public_key = None
		self.serialized_client_dh_public_key = None

		# TLS Key
		self.shared_key = None
		self.pre_master_key = None
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
		request_param.update({"length" : sys.getsizeof(self.ec_serialized_public_key)})


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
		request_param.update({"length" : sys.getsizeof(self.rsa_serialized_public_key)})

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


class ServerSocket(socketserver.BaseRequestHandler):

	def server_hello(self, request):
		nonce = str(time.time())[-4:] + str(random.getrandbits(124))

		server_obj.server_random = nonce
		server_obj.client_random = request["content"]["random"]

		content = dict()
		content.update({"version": 1.3})
		content.update({"random": nonce})
		content.update({"session_id": request["content"]["session_id"]})
		content.update({"compression_method": []})

		# Selection of the digital signature algorithm based on Trusted Third Party:
		if(server_obj.ttp_digital_signature == 0) or (server_obj.ttp_digital_signature == 1):
			content.update({"cipher_suite": request["content"]["cipher_suite"][random.randint(4,7)]})
			server_obj.server_digital_signature = 3
			server_obj.client_digital_signature = 2
			content.update({"specification_id": 2})
			server_obj.public_key = server_obj.ec_public_key
			server_obj.private_key = server_obj.ec_private_key
			server_obj.certificate_pem = server_obj.ec_certificate_pem
			server_obj.certificate = server_obj.ec_certificate
			server_obj.serialized_public_key = server_obj.ec_serialized_public_key
		else:
			content.update({"cipher_suite": request["content"]["cipher_suite"][random.randint(0,3)]})
			server_obj.server_digital_signature = 1
			server_obj.client_digital_signature = 0
			content.update({"specification_id": 0})
			server_obj.public_key = server_obj.rsa_public_key
			server_obj.private_key = server_obj.rsa_private_key
			server_obj.certificate_pem = server_obj.rsa_certificate_pem
			server_obj.certificate = server_obj.rsa_certificate
			server_obj.serialized_public_key = server_obj.rsa_serialized_public_key

		server_obj.session_parameters = content

		request = dict()
		request.update({"type": "server_hello"})
		request.update({"content": content})
		request.update({"length": sys.getsizeof(content)})

		return request

	def certificate(self):
		request = dict()
		request.update({"type": "certificate"})
		request.update({"content": server_obj.certificate_pem})
		request.update({"length": sys.getsizeof(server_obj.certificate_pem)})
		return request

	def server_key_exchange(self):
		content = dict()

		# Selection of the key exchange algorithm related parameters
		if server_obj.session_parameters["cipher_suite"]["key_exchg_algo"] == "DH" :
			content.update({"parameters":
								{"dh_parameters" : server_obj.serialized_parameters,
								 "dh_public_key" : server_obj.serialized_dh_public_key
								}
							})
		else:
			content.update({"parameters":
								{"ec_public_key" : server_obj.serialized_public_key}
							})

		param = str.encode(server_obj.client_random) + str.encode(server_obj.server_random) + pickle.dumps(content)

		# Generation of signature for authentication purpose
		if server_obj.server_digital_signature == 1:
			content.update({"signature": server_obj.private_key.sign(data = param,
				padding = padding.PKCS1v15(), algorithm = hashes.SHA384())})
		else:
			content.update({"signature": server_obj.private_key.sign(data = param,
				signature_algorithm = ec.ECDSA(hashes.SHA384()))})

		request = dict()
		request.update({"type": "server_key_exchange"})
		request.update({"content": content})
		request.update({"length": sys.getsizeof(content)})
		return request

	def certificate_request_message(self):
		request = dict()
		request.update({"type": "certificate_request"})
		request.update({"content": {"type": available_specifications[server_obj.server_digital_signature],
						"authorities": "" } })
		request.update({"length": sys.getsizeof(request["content"])})
		return request

	def server_done_message(self):
		request = dict()
		request.update({"type": "server_done"})
		request.update({"content": ""})
		request.update({"length": sys.getsizeof(request["content"])})
		return request

	def handle(self):
		request_data = self.request.recv(16384).strip()
		request_data = pickle.loads(request_data)

		if (request_data["type"] == "client_hello"):
			server_obj.handshake_messages.append(request_data)
			response_data = dict()
			response_data.update({"messages": []})

			#Send server_hello message
			print("Received the client hello message from client: ", request_data)

			response_data["messages"].append(self.server_hello(request_data))

			print("Sent the server hello message to client: ", response_data["messages"][0])
			print("The server uses the ", available_specifications[server_obj.server_digital_signature],
    			" specification for Digital Signature")
			print("\n\n------------------------------------------------------------------------------\n\n")

			#Send certificate message
			response_data["messages"].append(self.certificate())
			print("Sent the certificate to client: ", response_data["messages"][1])
			print("\n\n------------------------------------------------------------------------------\n\n")

			# Send the server key exchange message to client
			response_data["messages"].append(self.server_key_exchange())
			print("Sent the server key exchange message to client: ", response_data["messages"][2])
			print("\n\n------------------------------------------------------------------------------\n\n")

			# Send the certificate request message to client
			response_data["messages"].append(self.certificate_request_message())
			print("Sent the certificate request to client: ", response_data["messages"][3])
			print("\n\n------------------------------------------------------------------------------\n\n")

			# Send the server done message to client
			response_data["messages"].append(self.server_done_message())
			print("Sent the server_done message to client: ", response_data["messages"][4])
			print("\n\n------------------------------------------------------------------------------\n\n")

			server_obj.handshake_messages.append(response_data["messages"])


		if (request_data["type"] == "phase-3"):

			server_obj.handshake_messages.append(request_data["messages"][0])
			server_obj.handshake_messages.append(request_data["messages"][1])

			byte_message = pickle.dumps(server_obj.handshake_messages)

			# Certificate Processing:
			server_obj.client_certificate_pem = request_data["messages"][0]["content"]
			server_obj.client_certificate = x509.load_pem_x509_certificate(server_obj.client_certificate_pem, server_obj.backend)

			print("Received the certificate from the client: ", request_data["messages"][0])
			print("Verifying the Certificate by using TTP public key")

			if not server_obj.verify_certificate(server_obj.client_certificate):
				print("The Certificate is Tempered, Closing the connection.")

			print("Verified the Certificate by using TTP public key")
			print("\n\n------------------------------------------------------------------------------\n\n")


			# Client Key Exchange Message
			if server_obj.session_parameters["cipher_suite"]["key_exchg_algo"] == "DH" :
				server_obj.serialized_client_dh_public_key = request_data["messages"][1]["content"]["parameters"]["dh_public_key"]
				server_obj.client_dh_public_key = serialization.load_pem_public_key(
					server_obj.serialized_client_dh_public_key, server_obj.backend)
				server_obj.client_public_key = server_obj.get_public_key(server_obj.client_certificate)
				server_obj.shared_key = server_obj.dh_private_key.exchange(server_obj.client_dh_public_key)
				server_obj.pre_master_key = HKDF(algorithm=hashes.SHA256(),
					length=32, salt=None, info=None, backend = server_obj.backend).derive(server_obj.shared_key)
			else:
				server_obj.client_public_key_pem = request_data["messages"][1]["content"]["parameters"]["ec_public_key"]
				server_obj.client_public_key = serialization.load_pem_public_key(server_obj.client_public_key_pem, server_obj.backend)
				server_obj.shared_key = server_obj.private_key.exchange(ec.ECDH(), server_obj.client_public_key)
				server_obj.pre_master_key = HKDF(algorithm=hashes.SHA256(),
					length=32, salt=None, info=None, backend = server_obj.backend).derive(server_obj.shared_key)

			print("Received the client key exchange message from client: ", request_data["messages"][1])

			# Verify the Signature
			print("Verifying the Signature on message by using client public key")

			signature = request_data["messages"][1]["content"]["signature"]

			# Generating the signed message
			message_content = request_data["messages"][1]["content"]
			del message_content["signature"]

			message_content = str.encode(server_obj.client_random) + str.encode(server_obj.server_random) + pickle.dumps(message_content)

			if server_obj.server_digital_signature == 1:
				try:
					server_obj.client_public_key.verify(signature = signature,
						data = message_content,
						padding = padding.PKCS1v15(),
						algorithm = hashes.SHA256())
				except Exception as e:
					print(e)
			else:
				try:
					server_obj.client_public_key.verify(signature = signature,
						data = message_content,
						signature_algorithm = ec.ECDSA(hashes.SHA256()))
				except Exception as e:
					print(e)

			print("Verified the Signature on message with client public key")
			print("\n\n------------------------------------------------------------------------------\n\n")

			print("Verifying the Handshake Messages by using client public key")

			signature = request_data["messages"][2]["content"]["signature"]

			if server_obj.server_digital_signature == 1:
				try:
					server_obj.client_public_key.verify(signature = signature,
						data = byte_message,
						padding = padding.PKCS1v15(),
						algorithm = hashes.SHA256())
				except Exception as e:
					print(e)
			else:
				try:
					server_obj.client_public_key.verify(signature = signature,
						data = byte_message,
						signature_algorithm = ec.ECDSA(hashes.SHA256()))
				except Exception as e:
					print(e)


			print("Verified the Handshake Messages with client public key")
			print("\n\n------------------------------------------------------------------------------\n\n")



			print("Generating the cryptographic parameters from the pre_master_key")
			print("--------------------------------------------------------------------------")

			hmac_util = hmac.HMAC(server_obj.pre_master_key, hashes.SHA256(), server_obj.backend)
			hmac_util.update(b"master_key" + str.encode(server_obj.client_random) + str.encode(server_obj.server_random))
			server_obj.master_key = hmac_util.finalize()

			hmac_util = hmac.HMAC(server_obj.pre_master_key, hashes.SHA256(), server_obj.backend)
			hmac_util.update(b"mac_secret" + str.encode(server_obj.client_random) + str.encode(server_obj.server_random))
			server_obj.mac_secret = hmac_util.finalize()

			hmac_util = hmac.HMAC(server_obj.pre_master_key, hashes.SHA256(), server_obj.backend)
			hmac_util.update(b"nonce" + str.encode(server_obj.client_random) + str.encode(server_obj.server_random))
			server_obj.nonce = hmac_util.finalize()[:16]

			print("pre_master_key", server_obj.pre_master_key)
			print("master_key", server_obj.master_key)
			print("mac_secret", server_obj.mac_secret)
			print("cipher_nonce", server_obj.nonce)

			print("\n\n------------------------------------------------------------------------------\n\n")

			response_data = ""

		if (request_data["type"] == "generate_otp"):
			print("The request for OTP sent received from client is ", request_data)
			print("-----------------------------------------------------------------------")

			received_message = server_obj.record_protocol(
				type = "receive", message = request_data["message"], length = request_data["length"])

			print("The plain text version of request received by server: ", str(received_message, "utf-8"))
			print("\n ----------------------------------------------------------------------- \n")

			otp = random.randint(100000,999999)
			sent_message = received_message + b" is : " + bytes(str(otp) + "\n", "utf-8")
			print("The plain text version of reply framed by server: ", str(sent_message, "utf-8"))
			print("\n ----------------------------------------------------------------------- \n")

			response_data = server_obj.record_protocol(type = "send", message = sent_message, length = None)
			print("The encrypted reply sent to client: ", response_data)
			print("-----------------------------------------------------------------------")

		response = pickle.dumps(response_data)
		self.request.sendall(response)


if __name__ == "__main__":

	server_obj = Server()
	print("The server is responding to transaction requests from client.")
	print("The subject have the following Identity, COMMON_NAME: SIL765.iitd.ac.in")

	print("\n ----------------------------------------------------------------------- \n")

	print("Requesting Trusted Third Party to generate a Certificate running on port 4444")
	print("-----------------------------------------------------------------------")
	server_obj.get_certificate()

	print("\n ----------------------------------------------------------------------- \n")

	with socketserver.TCPServer((host, server_port), ServerSocket) as sock_server:
		sock_server.allow_reuse_address = True
		sock_server.serve_forever()
import base64
import json
from isomdoc import create_mdoc
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.x509 import load_pem_x509_certificates
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

issuer_cert_chain_file = open("testdata/issuer_cert.pem", "rb").read()
issuer_cert_chain = load_pem_x509_certificates(issuer_cert_chain_file)
issuer_private_key_file = open("testdata/issuer_private_key.pem", "rb").read()
issuer_private_key = load_pem_private_key(issuer_private_key_file, None)

database_in_json = open("testdata/database_in.json", "rb").read()
database = json.loads(database_in_json)

for cred_id, cred in database.items():
    if cred["format"] == "mso_mdoc":
        mdoc_credential = cred["credential"]
        doctype = mdoc_credential["docType"]
        print("Creating {}".format(doctype))
        mdoc = create_mdoc(doctype, issuer_cert_chain, issuer_private_key)
        for namespace, elements in mdoc_credential["nameSpaces"].items():
            for element, value in elements.items():
                mdoc.add_data_item(namespace, element, value["value"])
        device_private_key = ec.generate_private_key(ec.SECP256R1())
        device_public_key = device_private_key.public_key()
        cred["issuerSigned"] = base64.urlsafe_b64encode(
            mdoc.generate_credential(device_public_key)
        ).decode("utf-8")
        cred["deviceKey"] = base64.urlsafe_b64encode(
            device_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ).decode("utf-8")

with open("testdata/database.json", "w") as f:
    json.dump(database, f, indent=4)
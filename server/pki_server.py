import os
import sys
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Importer utils.py en utilisant un import absolu
from utils import *

def process_message(message, type):
    """
    Traite les messages reçus depuis la file MQTT en fonction du type de message.
    
    Args:
        message (bytes): Le message reçu depuis la file MQTT.
        type (int): Le type de traitement à effectuer (1 pour la création de certificat, 2 pour la vérification de révocation).
    """
    print("Message reçu depuis la file MQTT \n")
    sys.stdout.flush()
    separator = b";!!;"
    pki_in_byte = b"PKI"
    sender_id, encrypted_message = extract_sender_id_and_message(message)
    
    # Vérifie si un secret est enregistré pour l'émetteur
    if os.path.exists(f"secret_pki_{sender_id}.pem"):
        secret_filename = f"secret_pki_{sender_id}.pem"
        with open(secret_filename, "rb") as secret_file:
            secret_key = secret_file.read().strip()
            if type == 1:
                decrypted_message, decrypted_key, decrypted_time = symmetric_decrypt_certificat(encrypted_message, secret_key)
                print(f"Réception des informations pour la création du certificat de {sender_id} !")
                sys.stdout.flush()
                private, public = load_key_pair()
                new_cert = create_server_cert(private, decrypted_message, decrypted_key, decrypted_time)
                print("Envoi du certificat signé !")
                sys.stdout.flush()
                publish_message(separator.join([pki_in_byte, symmetric_encrypt(new_cert, secret_key)]), "pki")
                
                # Si l'on est dans le scénario 4, on place le certificat dans la liste de révocation
                if status_cert == "revoked":
                    with open("revocation_list.pem", "wb") as revocation_list:
                        revocation_list.write(new_cert)
                        print("Ajout du certificat dans la liste de révocation.")
                        sys.stdout.flush()
                else:
                    with open("revocation_list.pem", "wb") as revocation_list:
                        revocation_list.write(b"vide")
            else:
                decrypted_message = symmetric_decrypt(encrypted_message, secret_key)
                print(f"Réception du certificat pour vérification de révocation envoyé par : {sender_id} !")
                sys.stdout.flush()
                with open("revocation_list.pem", "rb") as revocation_list:
                    revocation_text = revocation_list.read().strip()
                if revocation_text + b'\n' == decrypted_message:
                    print("Certificat présent dans la liste de révocation.")
                    sys.stdout.flush()
                    publish_message(separator.join([pki_in_byte, symmetric_encrypt("revoked certificat".encode("utf-8"), secret_key)]), "client")
                else:
                    print("Certificat valide non révoqué !")
                    sys.stdout.flush()
                    publish_message(separator.join([pki_in_byte, symmetric_encrypt("certificat toujours actif".encode("utf-8"), secret_key)]), "client")
    else:
        # Déchiffrement asymétrique du message avec la clé privée de la PKI
        decrypted_message = asymmetric_decrypt(encrypted_message, "private_key_PKI.pem")
        # Enregistre le secret pour l'ID de l'émetteur
        print(f"Réception de la clé secrète pour l'échange symétrique avec {sender_id} !")
        sys.stdout.flush()
        secret = decrypted_message
        secret_filename = f"secret_pki_{sender_id}.pem"
        with open(secret_filename, "wb") as secret_file:
            secret_file.write(secret)

def create_self_signed_cert(private_key):
    """
    Crée et auto-signe un certificat personnel.
    
    Args:
        private_key (RSAPrivateKey): La clé privée utilisée pour signer le certificat.
    
    Returns:
        bytes: Le certificat auto-signé au format PEM.
    """
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Certificat PKI"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Grand est"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Reims"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Université Reims Champagne-Ardennes"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Département informatique"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now()
    ).not_valid_after(
        # Certificat valide pour 365 jours
        datetime.now() + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    return cert_pem

def create_server_cert(private_key, information_server, decrypted_key, decrypted_time):
    """
    Crée et signe un certificat de serveur.
    
    Args:
        private_key (RSAPrivateKey): La clé privée utilisée pour signer le certificat.
        information_server (bytes): Les informations du serveur sous forme de bytes.
        decrypted_key (bytes): La clé publique du serveur sous forme de bytes.
        decrypted_time (bytes): La durée de validité du certificat sous forme de bytes.
    
    Returns:
        bytes: Le certificat signé au format PEM.
    """
    vendor_info = information_server.decode("utf-8").split(',')
    time_info = int(decrypted_time.decode("utf-8"))

    decrypted_key_final = serialization.load_pem_public_key(
        decrypted_key,
        backend=default_backend()
    )

    # Créer les attributs de nom en utilisant les éléments du tableau
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, vendor_info[0]),  # Nom commun
        x509.NameAttribute(NameOID.COUNTRY_NAME, vendor_info[1]),  # Pays
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, vendor_info[2]),  # État ou province
        x509.NameAttribute(NameOID.LOCALITY_NAME, vendor_info[3]),  # Localité
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, vendor_info[4]),  # Organisation
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, vendor_info[5]),  # Unité organisationnelle
    ])

    # Définition des attributs pour l'émetteur → entité qui a signé et émis le certificat
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Certificat PKI"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Grand est"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Reims"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Université Reims Champagne-Ardennes"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Département informatique")
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        # Clé du demandeur
        decrypted_key_final
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        date
    ).not_valid_after(
        # Nombre de jours voulu par le demandeur 
        date + timedelta(days=time_info)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Convertir le certificat en format PEM
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    return cert_pem

date = datetime

# Appel de la fonction principale du PKI
if __name__ == "__main__":
    date_obj = sys.argv[1], sys.argv[2]
    status_cert = sys.argv[3]
    date_str = ' '.join(date_obj)
    date = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S.%f')

    # Vérifier si la paire de clés existe déjà dans les fichiers
    private_key, public_key = load_key_pair()
    if private_key is None or public_key is None:
        # Si la paire de clés n'existe pas, générer une nouvelle paire de clés
        private_key, public_key = generer_cles_rsa()
        # Sauvegarder la paire de clés dans les fichiers
        save_key_pair(private_key, public_key, "PKI")

    # Créer et auto-signer le certificat personnel
    cert = create_self_signed_cert(private_key)
    save_certificate(cert, "PKI")

    # Démarrer l'écoute des messages MQTT dans un thread
    while True:
        # Attente d'une connexion ou d'un message
        print("\nPKI en attente d'une connexion ou d'un message...\n")
        sys.stdout.flush()
        message = listen_message("pki")
        sys.stdout.flush()
        process_message(message, 1)
        sys.stdout.flush()
        message = listen_message("pki")
        sys.stdout.flush()
        process_message(message, 1)
        while True:
            message = listen_message("client")
            sys.stdout.flush()
            process_message(message, 2)

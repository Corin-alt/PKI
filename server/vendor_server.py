from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import hashes
import os
import sys
import time
from utils import * 


#fonction pour creer les informations que l'on vas envoyer à la PKI pour creer notre certificat
def create_cert_info(public_key_Vendor):
    """
    Crée les informations nécessaires pour générer un certificat pour le vendeur.

    Args:
       public_key_Vendor (bytes): La clé publique du vendeur au format PEM.

    Returns:
        bytes: Les informations du certificat au format binaire, séparées par "!!!!".
    """
    # Description de l'émetteur
    subject = "Certificat Vendor,FR,Grand est,Reims,Université Reims Champagne-Ardennes,Département informatique"
    
    # Convertir subject en binaire
    subject_binary = subject.encode('utf-8')
    
    # Date d'expiration du certificat
    date = "30"
    date_binary = date.encode('utf-8')

    # Convertir la clé publique en format PEM (binaire directement ici)
    public_key_Vendor_pem = public_key_Vendor.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Concaténation des informations avec "!" comme séparateur en binaire
    separator = b"!!!!"
    cert_info_binary = separator.join([subject_binary, public_key_Vendor_pem, date_binary])
    
    return cert_info_binary



def process_message(message,private_key_serveur):
    """
    Traite un message reçu d'un client.

    Args:
        message (bytes): Le message chiffré reçu.
        private_key_serveur (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey): La clé privée du serveur.
    """

    sender_id, encrypted_message = extract_sender_id_and_message(message)
    # Vérifie si un secret est enregistré pour l'émetteur
    if os.path.exists(f"secret_vendor_{sender_id}.pem") :
        secret_filename = f"secret_vendor_{sender_id}.pem"
        with open(secret_filename, "rb") as secret_file:
            if sender_id == "Client1":
                secret_Client = secret_file.read()
                demande_decrypter = symmetric_decrypt(encrypted_message,secret_Client).decode('utf-8')
                print(f'message recu : {demande_decrypter}\n')
                sys.stdout.flush()
                if demande_decrypter == "achat d'un produit" :

                    message_v = "vente de l'article G42"
                    message_vente= message_v.encode("utf-8")
                    if os.path.exists(f"certificate_VENDOR.pem") :
                        cert_filename = f"certificate_VENDOR.pem"
                        with open(cert_filename, 'rb') as cert_file:
                            cert_binary = cert_file.read()
                            print(f'message envoyé : {message_vente.decode("utf-8")}\n')
                            sys.stdout.flush()
                            sign = signature(private_key_serveur,message_vente)
                            separator = b"!!!!"
                            message_retour = separator.join([cert_binary,sign,message_vente])
                            message_retour_encrypted = symmetric_encrypt(message_retour,secret_Client)
                            publish_message(message_retour_encrypted,"vendor")
                            



    else:
        # Déchiffrement asymétrique du message avec la clé privée du vendeur
        decrypted_message = asymmetric_decrypt(encrypted_message, "private_key_VENDOR.pem")
        # Enregistre le secret pour l'ID de l'émetteur
        print(f"Récéption de la clé secrète pour l'echange symmétrique avec {sender_id} !\n")
        sys.stdout.flush()
        secret = decrypted_message
        secret_filename = f"secret_vendor_{sender_id}.pem"
        with open(secret_filename, "wb") as secret_file:
            secret_file.write(secret)


if __name__ == "__main__":

    """
    Point d'entrée principal du programme.
    Génère les clés pour le vendeur, envoie la demande de certificat à la PKI et attend les messages des clients.
    """

    private_key_serveur, public_key_serveur = generer_cles_rsa()

    save_key_pair(private_key_serveur, public_key_serveur,"VENDOR")

    # Génération d'un random pour le chiffrement symétrique
    random_key = os.urandom(16)  # Générer une clé secrète de 256 bits pour AES
    #chiffrement asymétrique du secret
    random_key_chiffre = chiffrer_avec_cle_publique_PKI(random_key, "public_key_PKI.pem")
    separator = b";!!;"
    vendor_text="Vendor1"
    vendor_binary = vendor_text.encode('utf-8')
    random_key_chiffre_withid = separator.join([vendor_binary,random_key_chiffre])
    #publication du message dans la file MQTT
    print("secret envoyé à la PKI\n")
    sys.stdout.flush()
    publish_message(random_key_chiffre_withid,"pki")
    
    #creation du certificat 
    certificat_info_serveur = create_cert_info(public_key_serveur)
    #chiffrement symétrique de celui ci
    certificat_chiffre= symmetric_encrypt(certificat_info_serveur, random_key)
    separator = b";!!;"
    vendor_text="Vendor1"
    vendor_binary = vendor_text.encode('utf-8')
    sys.stdout.flush()
    certificat_chiffre_withid = separator.join([vendor_binary,certificat_chiffre])
    #publication du message dans la file MQTT
    time.sleep(1)

        #-----  PARTIE ECHANGE PKI -----#

    publish_message(certificat_chiffre_withid,"pki")
    print("information pour le certificat envoyé à la PKI !\n")
    sys.stdout.flush()
    #reception du message dans la file MQTT
    certificat_signe_chiffre = listen_message("pki")
    #dechiffrement symétrique
    
    sender,certificat_signe_chiffre = extract_sender_id_and_message(certificat_signe_chiffre)

    if sender == "PKI" :
        print("Récéption du certificat signé !\n")
        sys.stdout.flush()
        certificat_signe = symmetric_decrypt(certificat_signe_chiffre, random_key)
        save_certificate(certificat_signe, "VENDOR")

    #-----  PARTIE ENCHANGE CLIENT -----#

    while True:
        message_client = listen_message("vendor")
        process_message(message_client,private_key_serveur  )
    

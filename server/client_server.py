from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from PySide6.QtCore import QThread
from cryptography import x509
import os
import sys
import signal
from utils import *

def on_signal_received(signum, frame):
    """
    Gestionnaire pour les signaux reçus.

    Args:
        signum (int): Le numéro du signal.
        frame (FrameType): La frame de la pile actuelle.

    Affiche un message indiquant qu'un signal a été reçu.
    """
    print("\nSignal reçu pour l'exécution de l'achat")
    sys.stdout.flush()

# Définir le gestionnaire de signaux pour SIGUSR1
signal.signal(signal.SIGUSR1, on_signal_received)

def signal_handler(signum, frame):
    """
    Gère le signal SIGUSR1.

    Args:
        signum (int): Le numéro du signal.
        frame (FrameType): La frame de la pile actuelle.

    Affiche un message indiquant que le signal SIGUSR1 a été reçu.
    """
    print("Signal SIGUSR1 reçu, continuation du processus.")

def traitement_achat_retour(message_retour_encrypted, random_key_vendor):
    """
    Traite les données de retour d'un achat.

    Args:
        message_retour_encrypted (bytes): Le message de retour chiffré.
        random_key_vendor (bytes): La clé aléatoire du vendeur utilisée pour le déchiffrement.

    Returns:
        cert (x509.Certificate or None): Le certificat du vendeur s'il est valide, sinon None.
    """
    print("Réception des données de la vente depuis la file MQTT.\n")
    sys.stdout.flush()
    
    # Déchiffre les données du certificat, la signature et le message
    certif_data, signature, message = symmetric_decrypt_certificat(message_retour_encrypted, random_key_vendor)

    # Charge le certificat du vendeur
    cert = x509.load_pem_x509_certificate(certif_data, default_backend())
    public_key = cert.public_key()

    # Vérifie si le certificat est toujours valide
    not_valid_after = cert.not_valid_after
    current_datetime = datetime.utcnow()

    if current_datetime < not_valid_after:
        print(f"Le certificat du vendeur est actuellement valide. Il expire le : {not_valid_after}")
        sys.stdout.flush()
        verif_certif = 1
    else:
        print(f"Le certificat du vendeur a expiré le {not_valid_after}, Achat annulé.")
        sys.stdout.flush()
        verif_certif = 0

    if verif_certif == 1:
        try:
            # Vérifie la signature
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("La signature du vendeur est valide.\n")
            sys.stdout.flush()
        except Exception as e:
            print("La signature du vendeur est invalide, Achat annulé.\n", e)
            sys.stdout.flush()

        print(f'Message reçu : {message.decode("utf-8")}\n')
        sys.stdout.flush()

        return cert
    return None

if __name__ == "__main__":
    """
    Fonction principale pour la gestion des transactions d'achat et des signaux.

    - Génère des paires de clés RSA pour le client.
    - Chiffre les clés avec les clés publiques du PKI et du vendeur.
    - Publie les clés chiffrées sur les topics MQTT.
    - Attend des signaux pour procéder à l'achat.
    - Gère les transactions d'achat et vérifie les certificats des vendeurs.
    """
    # Récupère le statut du certificat depuis les arguments de la ligne de commande
    status_cert = sys.argv[3]

    # Génère une paire de clés RSA pour le client
    private_key_serveur, public_key_serveur = generer_cles_rsa()
    save_key_pair(private_key_serveur, public_key_serveur, "CLIENT")

    # Génère des clés aléatoires pour le chiffrement symétrique
    random_key_pki = os.urandom(16)  # Générer une clé secrète pour AES
    random_key_vendor = os.urandom(16)  # Générer une clé secrète pour AES

    # Chiffre les clés aléatoires avec les clés publiques du PKI et du vendeur
    random_key_pki_chiffre = chiffrer_avec_cle_publique_PKI(random_key_pki, "public_key_PKI.pem")
    random_key_vendor_chiffre = chiffrer_avec_cle_publique_PKI(random_key_vendor, "public_key_VENDOR.pem")

    # Prépare les messages avec l'ID du client et les clés chiffrées
    separator = b";!!;"
    client_text = "Client1"
    client_binary = client_text.encode('utf-8')
    random_key_pki_chiffre_withid = separator.join([client_binary, random_key_pki_chiffre])
    random_key_vendor_chiffre_withid = separator.join([client_binary, random_key_vendor_chiffre])

    # Publie les clés chiffrées sur les topics MQTT respectifs
    publish_message(random_key_pki_chiffre_withid, "client")
    publish_message(random_key_vendor_chiffre_withid, "vendor")

    while True:
        print("En attente du signal pour procéder à un achat.")
        sys.stdout.flush()

        # Attend le signal pour procéder à l'achat
        signal.pause()

        # Chiffre le message d'achat avec la clé aléatoire du vendeur
        message = symmetric_encrypt("achat d'un produit".encode('utf-8'), random_key_vendor)
        message_withID = separator.join([client_binary, message])
        publish_message(message_withID, "vendor")
        
        # Écoute le message de retour du vendeur
        achat_retour = listen_message("vendor")
        certif_vendor = traitement_achat_retour(achat_retour.payload, random_key_vendor)

        if certif_vendor is not None and status_cert != "scenar_1":
            # Chiffre le certificat du vendeur avec la clé aléatoire du PKI
            certif_vendor_chiffrer = symmetric_encrypt(certif_vendor.public_bytes(encoding=serialization.Encoding.PEM), random_key_pki)
            publish_message(separator.join([client_binary, certif_vendor_chiffrer]), "client")

            # Écoute le message de retour du client
            retour_pki_chiffrer = listen_message("client")
            sender, message_retour_chiffre = extract_sender_id_and_message(retour_pki_chiffrer)
            message_retour = symmetric_decrypt(message_retour_chiffre, random_key_pki).decode("utf-8")
            print(f"Retour de la PKI : {message_retour}")
            if "revoked" in message_retour:
                print("Achat annulé.\n")
            sys.stdout.flush()

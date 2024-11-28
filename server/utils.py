import sys
import os
import paho.mqtt.client as mqtt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.padding import PKCS7

# Paramètres de connexion MQTT
MQTT_BROKER_ADDRESS = "194.57.103.203"
MQTT_BROKER_PORT = 1883
MQTT_TOPIC_PKI = "vehicle/LMD/pki"
MQTT_TOPIC_VENDOR = "vehicle/LMD/vendor"
MQTT_TOPIC_CLIENT = "vehicle/LMD/client"
MQTT_TOPIC_UPPER_TEST = "vehicle/LMD/upper_test"

class MQTTClient:
    """
    Classe représentant un client MQTT pour gérer la connexion, la publication et la réception de messages.
    
    Attributes:
        broker_address (str): Adresse du serveur MQTT.
        broker_port (int): Port du serveur MQTT.
        client (mqtt.Client): Instance du client MQTT.
        received_message (mqtt.Message): Message reçu du serveur MQTT.
    """
    def __init__(self, broker_address, broker_port):
        """
        Initialise un client MQTT avec l'adresse du serveur et le port spécifiés.
        
        Args:
            broker_address (str): Adresse du serveur MQTT.
            broker_port (int): Port du serveur MQTT.
        """
        self.broker_address = broker_address
        self.broker_port = broker_port
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_publish = self.on_publish
        self.received_message = None

    def on_connect(self, client, userdata, flags, rc, properties=None):
        """
        Callback appelé lors de la connexion réussie au serveur MQTT.
        
        Args:
            client (mqtt.Client): Instance du client.
            userdata: Informations utilisateur (pas utilisées ici).
            flags: Indicateurs spécifiques à la connexion (pas utilisés ici).
            rc (int): Code retour de la connexion.
            properties: Propriétés MQTT (facultatif).
        """
        print(f"Connecté à la file MQTT")

    def on_message(self, client, userdata, message):
        """
        Callback appelé lors de la réception d'un message.
        
        Args:
            client (mqtt.Client): Instance du client.
            userdata: Informations utilisateur (pas utilisées ici).
            message (mqtt.Message): Message reçu du serveur MQTT.
        """
        self.received_message = message
        client.disconnect()

    def on_publish(self, client, userdata, mid, properties=None, reasonCode=None):
        """
        Callback appelé lors de la publication d'un message.
        
        Args:
            client (mqtt.Client): Instance du client.
            userdata: Informations utilisateur (pas utilisées ici).
            mid (int): ID du message publié.
            properties: Propriétés MQTT (facultatif).
            reasonCode: Code de raison pour la publication (facultatif).
        """
        print(f"Message publié sur la file MQTT")

    def connect(self):
        """
        Connecte le client au serveur MQTT spécifié.
        """
        self.client.connect(self.broker_address, self.broker_port)

    def disconnect(self):
        """
        Déconnecte le client du serveur MQTT.
        """
        self.client.disconnect()

    def publish_message(self, topic, message):
        """
        Publie un message sur un sujet MQTT spécifique.
        
        Args:
            topic (str): Sujet MQTT sur lequel publier.
            message (str): Contenu du message à publier.
        """
        self.connect()
        result = self.client.publish(topic, message)
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            print("Message publié avec succès")
        else:
            print(f"Échec de la publication du message. Code retour : {result.rc}")
        self.disconnect()

    def listen_message(self, topic):
        """
        Écoute et attend un message sur un sujet MQTT spécifique.
        
        Args:
            topic (str): Sujet MQTT à écouter.
            
        Returns:
            mqtt.Message: Message reçu.
        """
        self.connect()
        self.client.subscribe(topic)
        self.client.loop_forever()
        return self.received_message

# Création d'une instance unique du client MQTT
mqtt_client = MQTTClient(MQTT_BROKER_ADDRESS, MQTT_BROKER_PORT)

def publish_message(message, type):
    """
    Publie un message sur un sujet MQTT spécifique en fonction du type.
    
    Args:
        message (str): Contenu du message à publier.
        type (str): Type du message ('pki', 'client', 'vendor', 'upper_test_response').
    """
    topic = ""
    if type == "pki":
        topic = MQTT_TOPIC_PKI
    elif type == "client":
        topic = MQTT_TOPIC_CLIENT
    elif type == "vendor":
        topic = MQTT_TOPIC_VENDOR
    elif type == "upper_test_response":
        topic = MQTT_TOPIC_UPPER_TEST + "_response"
    
    mqtt_client.publish_message(topic, message)

def listen_message(type):
    """
    Attend un message sur un sujet MQTT en fonction du type.
    
    Args:
        type (str): Type du message ('pki', 'client', 'vendor', 'upper_test').
        
    Returns:
        mqtt.Message: Message reçu.
    """
    topic = ""
    if type == "pki":
        topic = MQTT_TOPIC_PKI
    elif type == "client":
        topic = MQTT_TOPIC_CLIENT
    elif type == "vendor":
        topic = MQTT_TOPIC_VENDOR
    elif type == "upper_test":
        topic = MQTT_TOPIC_UPPER_TEST
    
    return mqtt_client.listen_message(topic)

def generer_cles_rsa():
    """
    Génère une paire de clés RSA (privée et publique).
    
    Returns:
        tuple: Clé privée et clé publique générées.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def chiffrer_avec_cle_publique_PKI(random_key, fichier_cle_publique_PKI):
    """
    Chiffre une clé aléatoire avec une clé publique PKI (infrastructure à clés publiques).
    
    Args:
        random_key (bytes): Clé aléatoire à chiffrer.
        fichier_cle_publique_PKI (str): Chemin du fichier de la clé publique PKI.
        
    Returns:
        bytes: Texte chiffré.
    """
    with open(fichier_cle_publique_PKI, "rb") as key_file:
        public_key_PKI = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    
    ciphertext = public_key_PKI.encrypt(
        random_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def asymmetric_decrypt(encrypted_message, private_key_path):
    """
    Déchiffre un message asymétrique à l'aide d'une clé privée.
    
    Args:
        encrypted_message (bytes): Message chiffré à déchiffrer.
        private_key_path (str): Chemin vers le fichier de la clé privée.
        
    Returns:
        bytes: Message déchiffré.
    """
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(  
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return decrypted_message

def extract_sender_id_and_message(message):
    """
    Extrait l'ID de l'expéditeur et le message chiffré à partir d'un message formaté.
    
    Args:
        message (mqtt.Message): Message reçu.
        
    Returns:
        tuple: ID de l'expéditeur et message chiffré.
        
    Raises:
        ValueError: Si le message n'est pas dans le format attendu.
    """
    message_str = message.payload
    parts = message_str.split(b";!!;")
    if len(parts) != 2:
        raise ValueError("Format de message invalide. Le message doit être au format 'id|message_chiffré'.")
    sender_id = parts[0].decode("utf-8")
    encrypted_message = parts[1]
    return sender_id, encrypted_message

def symmetric_decrypt_certificat(ciphertext, random_key):
    """
    Déchiffre un certificat chiffré avec une clé symétrique.
    
    Args:
        ciphertext (bytes): Texte chiffré à déchiffrer.
        random_key (bytes): Clé symétrique utilisée pour le déchiffrement.
        
    Returns:
        tuple: Informations du certificat (partie 1, partie 2, partie 3).
    """
    cipher = Cipher(algorithms.AES(random_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded__info_binaire = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    certificat_info_binaire = unpadder.update(padded__info_binaire) + unpadder.finalize()
    parts = certificat_info_binaire.split(b"!!!!")
    return parts[0], parts[1], parts[2]

def symmetric_decrypt(ciphertext, random_key):
    """
    Déchiffre des données chiffrées avec une clé symétrique.
    
    Args:
        ciphertext (bytes): Texte chiffré à déchiffrer.
        random_key (bytes): Clé symétrique utilisée pour le déchiffrement.
        
    Returns:
        bytes: Données déchiffrées.
    """
    cipher = Cipher(algorithms.AES(random_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded__info_binaire = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    info_binaire = unpadder.update(padded__info_binaire) + unpadder.finalize()
    return info_binaire

def symmetric_encrypt(certificat_info_binaire, random_key):
    """
    Chiffre des données avec une clé symétrique.
    
    Args:
        certificat_info_binaire (bytes): Données à chiffrer.
        random_key (bytes): Clé symétrique utilisée pour le chiffrement.
        
    Returns:
        bytes: Données chiffrées.
    """
    cipher = Cipher(algorithms.AES(random_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(certificat_info_binaire) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def save_key_pair(private_key, public_key, type):
    """
    Sauvegarde une paire de clés (privée et publique) dans des fichiers PEM.
    
    Args:
        private_key (rsa.PrivateKey): Clé privée à sauvegarder.
        public_key (rsa.PublicKey): Clé publique à sauvegarder.
        type (str): Type de la clé pour nommer les fichiers.
    """
    with open(f"private_key_{type}.pem", "wb") as f_private, open(f"public_key_{type}.pem", "wb") as f_public:
        f_private.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )   
        )
        f_public.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print("Clés sauvegardées\n")
    sys.stdout.flush()

def load_key_pair():
    """
    Charge une paire de clés (privée et publique) depuis des fichiers PEM.
    
    Returns:
        tuple: Clé privée et clé publique chargées, ou (None, None) si les fichiers n'existent pas.
    """
    if os.path.exists("private_key_PKI.pem") and os.path.exists("public_key_PKI.pem"):
        with open("private_key_PKI.pem", "rb") as f_private, open("public_key_PKI.pem", "rb") as f_public:
            private_key = serialization.load_pem_private_key(
                f_private.read(),
                password=None,
                backend=default_backend()
            )
            public_key = serialization.load_pem_public_key(
                f_public.read(),
                backend=default_backend()
            )
            return private_key, public_key
    return None, None

def save_certificate(cert, nameServer):
    """
    Sauvegarde un certificat dans un fichier PEM.
    
    Args:
        cert (bytes): Certificat à sauvegarder.
        nameServer (str): Nom du serveur utilisé pour nommer le fichier.
    """
    with open(f"certificate_{nameServer}.pem", "wb") as f:
        f.write(cert)

def signature(private_key, message):
    """
    Crée une signature numérique à partir d'un message et d'une clé privée.
    
    Args:
        private_key (rsa.PrivateKey): Clé privée utilisée pour la signature.
        message (bytes): Message à signer.
        
    Returns:
        bytes: Signature numérique générée.
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def decode_certificate(cert_data):
    """
    Décode un certificat X.509 et extrait les informations principales.
    
    Args:
        cert_data (bytes): Données du certificat au format PEM.
        
    Returns:
        str: Informations formatées du certificat (sujet, émetteur, validité, clé publique).
    """
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    valid_from = cert.not_valid_before
    valid_until = cert.not_valid_after
    pub_key = cert.public_key()
    return f"Subject: {subject}\nIssuer: {issuer}\nValid from: {valid_from}\nValid until: {valid_until}\nPublic_key: {pub_key}"

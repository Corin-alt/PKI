import sys
import os
sys.path.append('..')  # Ajout du répertoire parent au chemin pour accéder aux modules
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from utils import publish_message, listen_message
import paho.mqtt.client as mqtt

def load_certificate(cert_type):
    """
    Charge un certificat à partir d'un fichier.

    :param cert_type: Type de certificat (ex : 'VENDOR', 'PKI')
    :return: Contenu du certificat ou None si le fichier n'est pas trouvé
    """
    try:
        with open(f"certificate_{cert_type}.pem", "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Fichier de certificat pour {cert_type} introuvable.")
        return None

def get_public_key(cert_type):
    """
    Extrait la clé publique d'un certificat.

    :param cert_type: Type de certificat
    :return: Clé publique au format PEM ou un message d'erreur
    """
    try:
        cert_data = load_certificate(cert_type)
        if cert_data:
            # Chargement du certificat X.509
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            # Extraction de la clé publique
            public_key = cert.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem.decode('utf-8')
        return f"Certificat pour {cert_type} introuvable"
    except Exception as e:
        return f"Erreur : {str(e)}"

def handle_request(data):
    """
    Gère les requêtes reçues.

    :param data: Données de la requête
    :return: Réponse appropriée en fonction de la requête
    """
    data = data.strip().lower()
    if data == "cert_pub_key_vendor":
        return get_public_key("VENDOR")
    elif data == "cert_pub_key_pki":
        return get_public_key("PKI")
    return "Requête inconnue"

def on_connect(client, userdata, flags, rc, properties=None):
    """
    Callback appelé lors de la connexion au broker MQTT.

    :param client: Instance du client MQTT
    :param userdata: Données utilisateur (pas utilisées ici)
    :param flags: Drapeaux de connexion (pas utilisés ici)
    :param rc: Code de retour de la connexion
    :param properties: Propriétés MQTT (facultatif)
    """
    if rc == 0:
        print("Connexion réussie au broker MQTT")
        print("Souscription au topic : vehicle/LMD/upper_test")
        client.subscribe("vehicle/LMD/upper_test")
    else:
        print(f"Échec de la connexion. Code retour : {rc}")

def on_message(client, userdata, msg):
    """
    Callback appelé lors de la réception d'un message.

    :param client: Instance du client MQTT
    :param userdata: Données utilisateur (pas utilisées ici)
    :param msg: Message reçu
    """
    print(f"Message reçu sur le topic {msg.topic}")
    print(f"Contenu du message : {msg.payload.decode()}")
    process_message(msg)

def on_subscribe(client, userdata, mid, granted_qos, properties=None):
    """
    Callback appelé après une souscription à un topic.

    :param client: Instance du client MQTT
    :param userdata: Données utilisateur (pas utilisées ici)
    :param mid: ID du message
    :param granted_qos: Qualité de service accordée
    :param properties: Propriétés MQTT (facultatif)
    """
    print(f"Souscription réussie.")

def process_message(message):
    """
    Traite le message reçu et envoie une réponse.

    :param message: Message MQTT reçu
    """
    print("Traitement du message...")
    data = message.payload.decode('utf-8').strip().lower()
    print(f"Message décodé : {data}")
    # Gestion de la requête et génération de la réponse
    response = handle_request(data)
    print(f"Envoi de la réponse : {response}")
    # Publication de la réponse sur le topic 'upper_test_response'
    publish_message(response.encode('utf-8'), "upper_test_response")

def start_server():
    """
    Démarre le serveur MQTT.
    """
    # Initialisation du client MQTT
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_subscribe = on_subscribe

    print("Connexion au broker MQTT à l'adresse 194.57.103.203:1883...")
    client.connect("194.57.103.203", 1883, 60)

    print("Démarrage de la boucle MQTT...")
    client.loop_forever()

if __name__ == "__main__":
    print("Démarrage du serveur upper_test.py...")
    start_server()

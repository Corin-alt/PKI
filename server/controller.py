import sys
import subprocess
import os
import signal
from datetime import datetime, timedelta
from PySide6.QtCore import QWaitCondition,QMutex, QThread, Signal, Slot, QTimer
from PySide6.QtWidgets import QApplication, QMainWindow, QGridLayout, QTextEdit, QPushButton, QWidget, QMessageBox
from PySide6.QtGui import QAction
from utils import *  
import os
import sys

# Obtenir le chemin absolu du répertoire racine
projet_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Ajouter le répertoire racine au sys.path
sys.path.append(projet_root)
date = None
status_cert = None
signal.signal(signal.SIGUSR1, signal.SIG_IGN)
pidClient = 0



class StopServersThread(QThread):
    """
    Classe pour arrêter les serveurs.

    Attributs:
        stop_signal (Signal): Signal émis pour indiquer que les serveurs doivent être arrêtés.
    """
    stop_signal = Signal()
    
    
    def run(self):
        """
        Méthode exécutée lors de l'exécution du thread.

        Émet le signal d'arrêt des serveurs.
        """
        self.stop_signal.emit()


class WorkerThread(QThread):
    """
    Classe pour exécuter une commande et gérer ses sorties.

    Attributs:
        output_received (Signal): Signal émis pour chaque ligne de sortie de la commande.
        command (str): La commande à exécuter.
        text_edit (QTextEdit): Widget d'édition de texte pour afficher les sorties.
    """
    output_received = Signal(str)
    
    
    def __init__(self, command, text_edit):
        """
        Initialise le thread avec une commande et un widget d'édition de texte.

        Args:
            command (str): La commande à exécuter.
            text_edit (QTextEdit): Widget d'édition de texte pour afficher les sorties.
        """
        super().__init__()
        self.command = command
        self.text_edit = text_edit

    def run(self):
        """
        Méthode exécutée lors de l'exécution du thread.

        Forme et exécute la commande, puis émet les lignes de sortie lues du processus.
        """
        self.command = f"{self.command} {date} {status_cert}"
        process = subprocess.Popen(self.command.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            self.output_received.emit(line.strip())
        global pidClient 
        pidClient = process.pid

    @Slot()
    def on_wakeup(self):
        """
        Slot pour réagir à un signal de réveil.
        
        Affiche un message indiquant que le thread a été réveillé.
        """
        print("Worker: Réveillé par le signal.")
        
def send_signal():
    """
    Envoie le signal SIGUSR1 à un groupe de processus.

    Envoie le signal aux processus dont les PIDs sont dans la plage [pidClient, pidClient+40], sauf le PID du processus courant.
    
    Permet de récupérer le PID du processus client pour envoyer des commandes 
    """
    global pidClient
    for a in range(pidClient,pidClient+80):
        if a != os.getpid():
            try:
                os.kill(a, signal.SIGUSR1)
            except ProcessLookupError:
                pass
            except PermissionError:
                pass

def signal_handler(signum, frame):
    """
    Gestionnaire pour le signal SIGUSR1.

    Affiche un message indiquant que le signal SIGUSR1 a été reçu et que le processus continue.

    Args:
        signum (int): Le numéro du signal reçu.
    """
    print("Signal SIGUSR1 reçu, continuation du processus.")
    
class PKIControllerWindow(QMainWindow):
    """
    Fenêtre principale pour le contrôle des serveurs PKI, client et vendeur.

    Attributs:
        selected_scenario (str): Le scénario actuellement sélectionné.
        pki_started (bool): État du serveur PKI (démarré ou non).
        client_started (bool): État du serveur client (démarré ou non).
        vendor_started (bool): État du serveur vendeur (démarré ou non).
        worker_threads (dict): Dictionnaire pour gérer les threads de travail.
    """
    def __init__(self):
        """
        Initialise la fenêtre principale et configure l'interface utilisateur.
        """
        super().__init__()
        
        self.selected_scenario = None
        # Variables pour suivre l'état de chaque serveur
        self.pki_started = False
        self.client_started = False
        self.vendor_started = False

        # Création de la fenetre du controller
        self.setWindowTitle("Projet RT802 - PKI - Controller")
        self.resize(1200, 800)
        layout = QGridLayout()
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)
        # ------------------------------------------------------------- Bouton et fenetre PKI

        # Bouton pour démarrer le serveur PKI
        self.startPKIButton = QPushButton("Démarrer le serveur PKI")
        self.startPKIButton.clicked.connect(self.start_pki_server)
        layout.addWidget(self.startPKIButton, 0, 0, 1, 4)

        # Fenêtre texte pour afficher les sorties du serveur PKI
        self.pkiTextEdit = QTextEdit()
        self.pkiTextEdit.setReadOnly(True)
        self.pkiTextEdit.setPlaceholderText("Sorties du serveur PKI")
        layout.addWidget(self.pkiTextEdit, 1, 0, 1, 4)

        # ------------------------------------------------------------- Bouton et fenetre PKI
        # ------------------------------------------------------------- Bouton et fenetre client

        # Bouton pour démarrer le serveur client
        self.startClientButton = QPushButton("Démarrer le serveur client")
        self.startClientButton.clicked.connect(self.start_client_server)
        self.startClientButton.setEnabled(False)
        layout.addWidget(self.startClientButton, 2, 0)

        # Bouton pour acheter (à côté du serveur client)
        self.buyButton = QPushButton("Acheter")
        self.buyButton.clicked.connect(self.buy_function)  # Remplacez buy_function par la fonction appropriée
        self.buyButton.setEnabled(False)
        layout.addWidget(self.buyButton, 2, 1)  # Ajouter le bouton à la ligne 2, colonne 0

        # Fenêtre texte pour afficher les sorties du serveur client
        self.clientTextEdit = QTextEdit()
        self.clientTextEdit.setReadOnly(True)
        self.clientTextEdit.setPlaceholderText("Sorties du serveur client")
        layout.addWidget(self.clientTextEdit, 3, 0, 1, 2)

        # ------------------------------------------------------------- Bouton et fenetre client
        # ------------------------------------------------------------- Bouton et fenetre vendeur

        # Bouton pour démarrer le serveur vendeur
        self.startVendorButton = QPushButton("Démarrer le serveur vendeur")
        self.startVendorButton.clicked.connect(self.start_vendor_server)
        self.startVendorButton.setEnabled(False)
        layout.addWidget(self.startVendorButton, 2, 2, 1, 2)

        # Fenêtre texte pour afficher les sorties du serveur vendeur
        self.vendorTextEdit = QTextEdit()
        self.vendorTextEdit.setReadOnly(True)
        self.vendorTextEdit.setPlaceholderText("Sorties du serveur vendeur")
        layout.addWidget(self.vendorTextEdit, 3, 2, 1, 2)

        # ------------------------------------------------------------- Bouton et fenetre client

        # Connectez le signal à une méthode pour mettre à jour le texte
        self.worker_threads = {}

        # ------------------------------------------------------------- Barre des taches 
        
        # Création de la barre des taches 
        menubar = self.menuBar()

        # --------------------------------- Bouton start/stop serveur
        # Bouton pour redémarrer tous les serveurs
        restart_action = QAction("Redémarrer", self)
        restart_action.triggered.connect(self.restart_servers)

        # Bouton pour arrêter tous les serveurs
        stop_action = QAction("Arrêter", self)
        stop_action.triggered.connect(self.stop_servers)

        serveurs_menu = menubar.addMenu("Serveurs")
        serveurs_menu.addAction(restart_action)
        serveurs_menu.addAction(stop_action)
        # --------------------------------- Bouton start/stop serveur

        # --------------------------------- Bouton scenario
        # Bouton pour lancer le scenario 1 
        Scenario_1_action = QAction("Scénario 1", self)
        Scenario_1_action.triggered.connect(self.start_scenario_1)

        # Bouton pour lancer le scenario 2 
        Scenario_2_action = QAction("Scénario 2", self)
        Scenario_2_action.triggered.connect(self.start_scenario_2)

        # Bouton pour lancer le scenario 3 
        Scenario_3_action = QAction("Scénario 3", self)
        Scenario_3_action.triggered.connect(self.start_scenario_3)
        
        # Bouton pour lancer le scenario 3 
        Scenario_4_action = QAction("Scénario 4", self)
        Scenario_4_action.triggered.connect(self.start_scenario_4)

        scénario_menu = menubar.addMenu("Scénarios")
        scénario_menu.addAction(Scenario_1_action)
        scénario_menu.addAction(Scenario_2_action)   
        scénario_menu.addAction(Scenario_3_action) 
        scénario_menu.addAction(Scenario_4_action)
        # --------------------------------- Bouton scenario

        # --------------------------------- Bouton clé et certificat
        # Bouton pour récupérer la clé et l'afficher pour le PKI
        pki_cert = QAction("Clé", self)
        pki_cert.triggered.connect(lambda: self.get_keys("PKI"))

        # Bouton pour récupérer la certificat et l'afficher pour le PKI
        pki_key = QAction("Certificat", self)
        pki_key.triggered.connect(lambda: self.get_cert("PKI"))

        pki_menu = menubar.addMenu("PKI")
        pki_menu.addAction(pki_cert)
        pki_menu.addAction(pki_key) 
        
        # Bouton récupérer la clé et l'afficher pour le vendeur
        vendor_cert = QAction("Clé", self)
        vendor_cert.triggered.connect(lambda: self.get_keys("VENDOR"))

        # Bouton récupérer la certificat et l'afficher pour le vendeur
        vendor_key = QAction("Certificat", self)
        vendor_key.triggered.connect(lambda: self.get_cert("VENDOR"))

        vendor_menu = menubar.addMenu("Vendeur")
        vendor_menu.addAction(vendor_cert)
        vendor_menu.addAction(vendor_key) 

        # Bouton pour récupérer la certificat et l'afficher pour le client
        client_key = QAction("Clé", self)
        client_key.triggered.connect(lambda: self.get_keys("CLIENT"))
        client_menu = menubar.addMenu("Client")
        client_menu.addAction(client_key) 


        # --------------------------------- Bouton clé et certificat 

        # Connecter le signal destroyed de la fenêtre à la méthode stop_servers
        self.destroyed.connect(self.stop_servers)

        # Connecter le signal closeEvent de la fenêtre à la méthode closeEvent
        self.closeEvent = self.closeEvent

    def closeEvent(self, event):
        """
        Méthode appelée lors de la fermeture de la fenêtre. Arrête les serveurs en appelant la fonction stop_servers.

        Args:
            event (QCloseEvent): L'événement de fermeture.
        """
        self.stop_servers()
        event.accept()


    def start_pki_server(self):
        """
        Démarre le serveur PKI. Vérifie d'abord si un scénario est choisi.
        Si aucun scénario n'est choisi, affiche un avertissement.
        """
        if not self.scenario_chosen():  # Vérifie si un scénario est choisi
            QMessageBox.warning(self, "Aucun scénario choisi", "Veuillez choisir un scénario avant de démarrer le serveur PKI.")
        else:
            self.worker_threads['pki'] = WorkerThread("python3 pki_server.py", self.pkiTextEdit)
            self.worker_threads['pki'].output_received.connect(self.update_text)
            self.worker_threads['pki'].start()
            self.pki_started = True
            self.startPKIButton.setEnabled(False)  # Désactiver le bouton
            QTimer.singleShot(3000, lambda: self.startVendorButton.setEnabled(True))

    def start_vendor_server(self):
        """
        Démarre le serveur vendeur. Met à jour l'interface utilisateur pour activer le bouton du serveur client.
        """
        self.worker_threads['vendor'] = WorkerThread("python3 vendor_server.py", self.vendorTextEdit)
        self.worker_threads['vendor'].output_received.connect(self.update_text)
        self.worker_threads['vendor'].start()
        self.vendor_started = True
        QTimer.singleShot(3000, lambda: self.startClientButton.setEnabled(True))
        
        self.startVendorButton.setEnabled(False)
 
    def start_client_server(self):
        """
        Démarre le serveur client. Met à jour l'interface utilisateur pour activer le bouton d'achat.
        """
        self.worker_threads['client'] = WorkerThread("python3 client_server.py", self.clientTextEdit)
        self.worker_threads['client'].output_received.connect(self.update_text)
        self.worker_threads['client'].start()
        self.client_started = True
        QTimer.singleShot(3000, lambda: self.buyButton.setEnabled(True))
        self.startClientButton.setEnabled(False)

    def update_text(self, text):
        """
        Met à jour la fenêtre de texte correspondante avec les sorties des serveurs.

        Args:
            text (str): Le texte à ajouter à la fenêtre de sortie.
        """
        sender_thread = self.sender()
        if sender_thread in self.worker_threads.values():
            for key, thread in self.worker_threads.items():
                if thread == sender_thread:
                    if key == 'pki':
                        self.pkiTextEdit.append(text)
                    elif key == 'client':
                        self.clientTextEdit.append(text)
                    elif key == 'vendor':
                        self.vendorTextEdit.append(text)

    def restart_servers(self):
        """
        Redémarre tous les serveurs et réinitialise l'interface utilisateur.
        """
        self.stop_servers()
        if self.pki_started:
            self.clear_terminal_windows()
            self.start_pki_server()
            self.start_client_server()
            self.start_vendor_server()
            
    def stop_servers(self):
        """
        Arrête tous les serveurs, supprime les fichiers .pem, et réinitialise l'interface utilisateur.
        """
        # Supprimer les fichiers .pem correspondants
        for filename in os.listdir("."):
            if filename.endswith(".pem"):
                os.remove(filename)

        for thread in self.worker_threads.values() :
            thread.terminate()
            thread.wait()

        self.clear_terminal_windows()
        self.pki_started = False
        self.client_started = False
        self.vendor_started = False
        self.startPKIButton.setEnabled(True)
        self.startClientButton.setEnabled(False)
        self.startVendorButton.setEnabled(False)
        self.buyButton.setEnabled(False)
        self.selected_scenario = None

    def clear_terminal_windows(self):
        """
        Efface le contenu des fenêtres de terminal et force le rafraîchissement des fenêtres.
        """
        # Effacer le contenu des fenêtres de terminal
        self.pkiTextEdit.setText('')
        self.clientTextEdit.setText('')
        self.vendorTextEdit.setText('')
        # Forcer le rafraîchissement des fenêtres
        self.pkiTextEdit.repaint()
        self.clientTextEdit.repaint()
        self.vendorTextEdit.repaint()

    def buy_function(self):
        """
        Fonction pour effectuer l'achat via le serveur client. Envoie un signal vers le client.
        """
        global pidClient
        send_signal()


    def get_cert(self, nameServer):
        """
        Récupère et affiche le certificat pour l'entité spécifiée.

        Args:
            nameServer (str): Le nom du serveur pour lequel récupérer le certificat (PKI, CLIENT, VENDOR).
        """
        # Afficher la clé privée dans une boîte de message
        cert_path = f"certificate_{nameServer}.pem"

        try:
            with open(cert_path, "r") as cert_file:
                cert = cert_file.read()
        except FileNotFoundError:
            cert = None

        self.show_cert_box(cert, nameServer)

    def show_cert_box(self, cert, nameServer):
        """
        Affiche une boîte de dialogue contenant le certificat encodé et ses informations décodées.

        Args:
            cert (str): Le certificat encodé.
            nameServer (str): Le nom du serveur auquel appartient le certificat.
        """
        if cert:
            decoded_cert = decode_certificate(cert.encode())
            # Afficher une boîte de message avec le titre et le message spécifiés
            msg_box = QMessageBox()
            msg_box.setWindowTitle(f"Certificat de {nameServer}")
            msg_box.setText(f"Certificat encodé : \n\n {cert} \n\n Informations du certificat : \n\n{decoded_cert}")
            msg_box.exec()
        else:
            QMessageBox.warning(self, "Erreur", "Certificat introuvable.")

    def get_keys(self, nameServer):
        """
        Récupère et affiche les clés privées et publiques pour l'entité spécifiée.

        Args:
            nameServer (str): Le nom du serveur pour lequel récupérer les clés (PKI, CLIENT, VENDOR).
        """
        # Afficher la clé privée dans une boîte de message
        private_key_path = f"private_key_{nameServer}.pem"
        public_key_path = f"public_key_{nameServer}.pem"
        print(private_key_path)
        print(public_key_path)

        try:
            with open(private_key_path, "r") as private_key_file:
                private_key = private_key_file.read()
        except FileNotFoundError:
            private_key = None
        try:
            with open(public_key_path, "r") as public_key_file:
                public_key = public_key_file.read()
        except FileNotFoundError:
            public_key = None
        
        self.show_keys_box(public_key, private_key, nameServer)

    def show_keys_box(self, private, public, nameServer):
        """
        Affiche une boîte de dialogue contenant les clés privées et publiques.

        Args:
            private (str): La clé privée.
            public (str): La clé publique.
            nameServer (str): Le nom du serveur auquel appartiennent les clés.
        """
        if private is None or public is None:
            # Afficher une boîte de message avec un message d'erreur
            QMessageBox.warning(self, "Erreur", "Les clés sont introuvables.")
        else:
            # Afficher une boîte de message avec les clés privées et publiques
            msg_box = QMessageBox()
            msg_box.setWindowTitle(f"Clé de {nameServer}")
            msg_box.setText(f"Clé privée : \n\n {private}\n\nClé publique : \n\n{public}")
            msg_box.exec()

    def start_scenario_1(self):
        """
        Démarre le scénario 1. Arrête d'abord les serveurs en cours.
        """
        self.stop_servers()
        global date, status_cert
        self.selected_scenario = 1
        status_cert = "scenar_1"
        date = datetime.now()

    def start_scenario_2(self):
        """
        Démarre le scénario 2. Arrête d'abord les serveurs en cours.
        """
        self.stop_servers()
        global date, status_cert
        status_cert = "valid"
        self.selected_scenario = 2
        date = datetime.now()
    
    def start_scenario_3(self):
        """
        Démarre le scénario 3. Arrête d'abord les serveurs en cours.
        """
        self.stop_servers()
        global date, status_cert
        self.selected_scenario = 3
        date = datetime.now() - timedelta(days=45)
        status_cert = "valid"
        
    def start_scenario_4(self):
        """
        Démarre le scénario 4. Arrête d'abord les serveurs en cours.
        """
        self.stop_servers()
        global date, status_cert
        self.selected_scenario = 4
        date = datetime.now()
        status_cert = "revoked"
        
    def scenario_chosen(self):
        """
        Vérifie si un scénario est choisi.

        Returns:
            bool: True si un scénario est choisi, False sinon.
        """
        # Vérifie si un scénario est choisi
        if self.selected_scenario is not None:
            return True
        else:
            return False

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PKIControllerWindow()
    window.show()
    sys.exit(app.exec())

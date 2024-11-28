# PKI
Git du projet RT802 PKI

Pour faire fonctionner le programme il y a plusieurs dépendance à avoir. Pour les obtenir il suffit de se rendre dans le dossier “projet_RT802” et  d’exécuter la commande ci dessous : 

python3 install_dependencies.py

Une fois que les dépendances sont installées nous pouvons lancer le programme principal en commençant par se déplacer dans le dossier “server”. 

cd server 

puis en exécutant la commande suivante : 

python3 controller.py

Une fois que le programme est lancé, l’ensemble des actions se déroule directement dans la fenêtre qui vient de s’ouvrir. Il faut donc maintenant choisir un scénario avec le menu déroulant. Une fois que le scénario est choisi, nous pouvons directement lancer PKI puis le vendeur et finalement le client. Un délai d'attente est prévu pour laisser le temps au serveur de démarrer correctement.
Pour déclencher un achat, il suffit alors de cliquer sur le bouton au-dessus du client et un achat est validé ou non en fonction de la validité du certificat.
Si une erreur apparaît sur un des serveurs au cours de l'exécution, il faut redémarrer le programme avec le bouton en haut à droite dans le menu déroulant.


# Upper test

## Installer mosquitto-clients

```
sudo apt-add-repository ppa:mosquitto-dev/mosquitto-ppa
sudo apt update
sudo apt install mosquitto-clients
```

## Test

### Sur la première machine

Lancer : ``python3 projet_RT802/server/uper_test.py``

Cela va lancer le thread du "mouchard" qui va écouter la file MQTT lorsqu'une requête va arriver.

### Sur la seconde machine

Lancer : ``mosquitto_pub -h 194.57.103.203 -p 1883 -t "vehicle/LMD/upper_test" -m "cert_pub_key_vendor"``

Cela va publier un message sur la file pour envoyé au mouchard la clé publique du certificat

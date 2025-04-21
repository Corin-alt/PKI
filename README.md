# PKI

To make the program work, there are several dependencies to have. To obtain them, simply go to the “projet_RT802” folder and execute the command below:

```bash
python3 install_dependencies.py
```

Once the dependencies have been installed, we can launch the main program by first moving to the “server” folder.

```bash
cd server 
```

Then run the following command:

```bash
python3 controller.py
```

Once the program has been launched, all actions take place directly in the window that has just opened. We now need to choose a scenario from the drop-down menu. Once the scenario has been chosen, we can launch PKI directly, then the vendor and finally the customer. A timeout is provided to give the server time to start up correctly.
To trigger a purchase, simply click on the button above the client, and a purchase is validated or not, depending on the validity of the certificate.
If an error occurs on one of the servers during execution, restart the program using the button at the top right of the drop-down menu.

# Upper test

## Install mosquitto-clients

```
sudo apt-add-repository ppa:mosquitto-dev/mosquitto-ppa
sudo apt update
sudo apt install mosquitto-clients
```

## Test

### On the first machine

Run : ``python3 projet_RT802/server/uper_test.py``

This will launch the "snitch" thread, which will listen to the MQTT queue when a request arrives.

### On the second machine

Run : ``mosquitto_pub -h 194.57.103.203 -p 1883 -t "vehicle/LMD/upper_test" -m "cert_pub_key_vendor"``

This will publish a message on the queue to send the snitch the certificate's public key.

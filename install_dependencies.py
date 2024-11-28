import subprocess

def install_pip():
    try:
        subprocess.run(["sudo", "apt-get", "install", "python3-pip"], check=True)
        print("pip installé avec succès.")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'installation de pip : {e}")

def install_libGL():
    try:
        subprocess.run(["sudo", "apt-get", "install", "libgl1-mesa-glx"], check=True)
        print("pip installé avec succès.")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'installation de pip : {e}")

def install_libxk():
    try:
        subprocess.run(["sudo", "apt-get", "install", "libxkbcommon-x11-0"], check=True)
        print("pip installé avec succès.")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'installation de pip : {e}")

def install_libegl1():
    try:
        subprocess.run(["sudo", "apt-get", "install", "libegl1"], check=True)
        print("pip installé avec succès.")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'installation de pip : {e}")

def install_qtwayland5():
    try:
        subprocess.run(["sudo", "apt-get", "install", "qtwayland5"], check=True)
        print("qtwayland5 installé avec succès.")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'installation de qtwayland5 : {e}")

def install_libxcbCursor0():
    try:
        subprocess.run(["sudo", "apt-get", "install", "libxcb-cursor0"], check=True)
        print("libxcb-cursor0 installé avec succès.")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'installation de libxcb-cursor0 : {e}")

def install_dependencies():
    try:
        subprocess.run(["pip", "install", "-r", "requirements.txt"], check=True)
        print("Dépendances installées avec succès.")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'installation des dépendances : {e}")

if __name__ == "__main__":
    install_pip()
    install_libGL()
    install_libxk()
    install_libegl1()
    install_qtwayland5()
    install_libxcbCursor0()
    install_dependencies()


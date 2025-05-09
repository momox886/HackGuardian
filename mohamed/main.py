import os
import subprocess
import sys
from dotenv import load_dotenv

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

load_dotenv()

DOSSIER_SCRIPTS = "mohamed"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def color(text, style=Fore.GREEN):
    return style + text + Style.RESET_ALL if COLOR else text

def afficher_menu():
    print("\n" + "="*50)
    print(color("MENU PRINCIPAL - OUTIL DE GESTION CVE".center(50), Fore.CYAN))
    print("="*50)
    print(color("1.", Fore.YELLOW) + " Rechercher une CVE spécifique")
    print(color("2.", Fore.YELLOW) + " Lister les CVE par vendeur")
    print(color("3.", Fore.YELLOW) + " Envoyer un email personnalisé")
    print(color("4.", Fore.YELLOW) + " Tester le scraping web de CVE")
    print(color("5.", Fore.YELLOW) + " Lister les vendeurs disponibles")
    print(color("6.", Fore.YELLOW) + " Envoyer les CVEs d'un vendeur par email")
    print(color("7.", Fore.YELLOW) + " Envoyer les CVEs critiques par email")
    print(color("8.", Fore.RED) + " Quitter")
    print("="*50)

def executer_script(script_name, *args):
    chemin_script = os.path.join(DOSSIER_SCRIPTS, script_name)
    print(f"\nLancement de {chemin_script}...\n")
    try:
        subprocess.run([sys.executable, chemin_script] + list(args), check=True)
    except subprocess.CalledProcessError as e:
        print(color(f"Erreur lors de l'exécution de {chemin_script} : {e}", Fore.RED))
    except FileNotFoundError:
        print(color(f"Script {chemin_script} introuvable !", Fore.RED))
    input("\nAppuyez sur Entrée pour revenir au menu...")


def main():
    scripts = {
        "1": "cv.py",
        "2": "ll.py",
        "3": "mail.py",
        "4": "test.py",
        "5": "vendo.py",
        "6": "vendor_cve_mail.py",
        "7": "critical_cve_mail.py"
    }

    while True:
        clear_screen()
        afficher_menu()
        choix = input("\nVotre choix (1-8): ").strip()

        if choix in scripts:
            executer_script(scripts[choix])
        elif choix == "8":
            print(color("\nMerci d'avoir utilisé l'outil. Au revoir!", Fore.CYAN))
            break
        else:
            print(color("Choix invalide. Veuillez entrer un chiffre entre 1 et 8.", Fore.RED))
            input("Appuyez sur Entrée pour continuer...")

if __name__ == "__main__":
    main()
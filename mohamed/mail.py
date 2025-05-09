import smtplib
import os
from dotenv import load_dotenv
from email.message import EmailMessage

load_dotenv()

def send_email(subject, content, recipient):
    mdp = os.getenv('MDP')
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = 'habibdiallo2306@gmail.com'
    msg['To'] = recipient
    msg.set_content(content)

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login('habibdiallo2306@gmail.com', mdp)
            smtp.send_message(msg)
            print("E-mail envoyé avec succès !")
    except Exception as e:
        print(f"Erreur lors de l'envoi du mail : {e}")

if __name__ == "__main__":
    subject = input("Entrez le sujet du mail: ")
    content = input("Entrez le contenu du mail: ")
    recipient = input("Entrez l'email destinataire: ")
    send_email(subject, content, recipient)
# Projet Sécurité Système d'Information

## les fonctionnalités :

- Création d'un Compte
- Login avec mot de passe et code de vérification (envoyer par email).
- Codage / Decodage d'un message (base16, base32, base64,...).
- Hachage d'un message (sha1, sha224, sha256, md5,...).
- Craquage d'un message haché.
- Chiffrement symétrique (AES256 et DES).
- Chiffrement asymétrique (RSA et ELGAMEL).
- Chat room sécurisé ( End to End ecnryption).

## Langage : 

 - [Python](https://www.python.org) 
 - pour l'interface GUI, j'ai utilisé le module [Tkinter](https://python.doctor/page-tkinter-interface-graphique-python-tutoriel) de python
 
##  Structure de .env

```

  CONNECTION_STRING = "mongodb connection string"
  DATABASE_NAME="nom de la base de donnée"
  COLLECTION_NAME="nom de la collection"

  PORT = 587
  SMTP_SERVER = "smtp.gmail.com"
  SENDER_EMAIL = "addresse_email@gmail.com
  PASSWORD = "mot de passe"
  
```
## Craquage 
 
Le craquage d'un message haché se fait à partir d'un dictionnaire généré avec `crunch`, ce sont les addresses de type `nom.prenom@insat.ucar.tn` de taille `26` avec : 
  - nom sur 6 caractères
  - prénom sur 5 caractères
  - se termine par @insat.ucar.tn
  
``` 
crunch 26 26 -t @@@@@@.@@@@@@insat.ucar.tn -l aaaaaa.aaaaa@insat.ucar.tn -s robert.smith@insat.ucar.tn -o randomEmails -c 100
```
  - `-l`: pour noter le caractère @ qui ne doit pas être remplacé par une lettre.
  - `-s`: chaine initiale
  - `-o`: fichier output
  - `-c`: nombre de ligne
  
## Le principe de la "chat room" 
 
 1- L'utilisateur fournit sa clé privée RSA.
 
 2- Sa clé publique générée sera envoyé vers le serveur.Il a une liste des clés qu'est diffusé à chaque nouvelle connexion.
 
 3- Le client ainsi chiffre le message avec la clé publique de son récepteur avant de l'envoyer.
 
 => une communication sécurisée.
 
 NB: le chiffrement se fait au choix par l'utilisateur avec le boutton `Encrypt and send`,ceci pour visualiser la différence.

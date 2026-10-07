# Installer FlowScope sur Windows

FlowScope observe le trafic réseau de votre machine, identifie les communications, explique en
langage humain ce qui s'y passe et détecte certains comportements inhabituels.

Cette page vous emmène de « je viens de télécharger le projet » à « le tableau de bord est
ouvert ». **Trois étapes, aucune ligne de commande à taper.**

---

## Avant de commencer : deux logiciels à installer

### 1. Python 3.11 ou plus récent — obligatoire

Téléchargez-le sur **https://www.python.org/downloads/**

> **Le point qui fait échouer la moitié des installations** : sur la **première page** de
> l'installeur Python, une case à cocher en bas dit **« Add python.exe to PATH »**. Elle est
> **décochée par défaut**. Cochez-la.
>
> Sans elle, Windows sait que Python est installé, mais ne sait pas *où*. Le script vous dira
> alors « Python n'est pas installé » alors qu'il l'est. Vous pouvez réparer après coup en
> relançant l'installeur et en choisissant « Modify ».

### 2. Npcap — pour la capture réelle

Npcap est le pilote qui permet à Windows de laisser un programme lire les paquets qui passent.
Sans lui, FlowScope s'installe et démarre, mais **ne verra aucun paquet**.

Téléchargez-le sur **https://npcap.com/#download** et installez-le en cochant
**« WinPcap API-compatible Mode »**.

> **Cette installation demande les droits d'administrateur.** Si vous ne les avez pas sur votre
> machine, FlowScope restera utilisable — mais en mode démonstration seulement, sans capture.

Le script d'installation vérifie ce point et vous prévient, sans bloquer : vous pouvez tout
installer d'abord et ajouter Npcap plus tard.

---

## Étape 1 — Récupérer le projet

**Sans Git :** ouvrez **https://github.com/laviOGOU/network-analyzer**, cliquez sur le bouton
vert **`Code`**, puis **`Download ZIP`**. Décompressez l'archive où vous voulez — un dossier
comme `C:\FlowScope` fait très bien l'affaire.

**Avec Git :**

```
git clone https://github.com/laviOGOU/network-analyzer.git
```

> **Évitez de le mettre dans un dossier synchronisé** (OneDrive, Dropbox, un dossier réseau).
> L'environnement Python contient des milliers de petits fichiers, et la synchronisation les
> ralentit énormément, parfois jusqu'à empêcher l'installation.

---

## Étape 2 — Installer

**Double-cliquez sur `installer-windows.bat`.**

Une fenêtre noire s'ouvre et vous explique ce qu'elle va faire. Appuyez sur une touche, puis
laissez-la travailler **deux à trois minutes**. Voici ce qu'elle fait, dans l'ordre :

| Étape | Ce qu'elle vérifie |
|---|---|
| 1 | Python est présent et assez récent (3.11 minimum) |
| 2 | Elle crée un environnement isolé `.venv` — **rien n'est installé dans Windows** |
| 3 | Elle installe les dépendances du projet dans cet environnement |
| 4 | Elle crée le fichier `.env` avec un **jeton unique** pour votre machine |
| 5 | Elle vérifie que la capture réseau est possible |

**Rien n'est modifié en dehors du dossier du projet.** Pas de clé de registre, pas de fichier
système, pas de programme ajouté au démarrage. Tout vit dans le dossier, et supprimer le dossier
suffit à tout désinstaller.

À la fin, la fenêtre affiche `Installation terminée` et se ferme quand vous appuyez sur une touche.

---

## Étape 3 — Lancer

**Double-cliquez sur `lancer.bat`.**

La fenêtre affiche `FlowScope demarre...` puis attend quelques secondes — **c'est normal**.
Le serveur se connecte à la base de données avant d'être prêt, et avec une base distante cela
prend dix à quinze secondes. Le lanceur sonde le port chaque seconde, et **ouvre le navigateur
dès que le serveur répond**. Vous verrez le nombre de secondes qu'il a fallu.

Votre navigateur s'ouvre alors sur **http://127.0.0.1:8000** et le tableau de bord apparaît.

**Deux fenêtres s'ouvrent.** La première affiche la marche à suivre puis peut être fermée sans
conséquence. La seconde, minimisée et nommée **`FlowScope - serveur`**, fait tourner le serveur :
**tant qu'elle est ouverte, FlowScope tourne**. Pour tout arrêter, fermez celle-là.

---

## Ensuite : capturer du trafic

Dans la barre **« Capture en direct »**, en haut du tableau de bord :

1. Choisissez une interface dans la liste — **`Wi-Fi`** si vous êtes en sans-fil, **`Ethernet`** si
   vous êtes branché par câble
2. Laissez le filtre de capture vide pour tout voir
3. Cliquez sur **`Démarrer`**

Les paquets défilent. Vous pouvez **`Pause`** pour figer l'affichage sans arrêter la capture, ou
cliquer sur une ligne pour lire le détail d'un paquet — ses couches, leur rôle, et les octets des
en-têtes.

> **La liste des interfaces est celle de votre machine.** Si vous n'en voyez qu'une ou deux, ou
> des noms étranges comme `lo`, c'est que Npcap n'est pas installé.

---

## Conserver les données (facultatif)

Par défaut, FlowScope garde tout **en mémoire** : les données disparaissent quand vous fermez le
serveur. C'est volontaire — on peut essayer le logiciel sans rien installer d'autre.

Pour conserver l'historique, ouvrez le fichier **`.env`** avec le Bloc-notes et renseignez :

```
ANALYZER_DATABASE_URL=postgresql://utilisateur:motdepasse@hote:5432/base
```

FlowScope fonctionne avec **n'importe quel PostgreSQL** — celui de votre machine, ou un projet
Supabase en ligne. Le fichier `.env` contient aussi la liste des autres réglages possibles, avec
leur explication.

> **Le `.env` n'est jamais envoyé sur GitHub.** Il contient votre jeton et vos mots de passe, et
> le projet l'exclut explicitement. Ne le copiez jamais dans un dépôt.

---

## Lancer sans navigateur : la fenetre Windows

Il existe une seconde facon de lancer FlowScope, pour ceux qui ne veulent ni navigateur ni
ligne de commande : **`FlowScope.exe`**.

1. Telechargez `FlowScope.exe` depuis la page des versions :
   https://github.com/laviOGOU/network-analyzer/releases/latest
2. Double-cliquez dessus. C'est tout : il n'y a rien a installer.

**Le premier demarrage prend trente a quarante secondes.** L'executable se decompresse en
memoire, puis se connecte a la base. Les fois suivantes sont plus rapides.

### Ou il range sa configuration

Dans `%LOCALAPPDATA%\FlowScope`, c'est-a-dire :

```
C:\Users\<votre nom>\AppData\Local\FlowScope\.env
```

Ce dossier survit a la fermeture de l'application. Au tout premier lancement, l'executable
**reprend la configuration qu'il trouve a cote de lui** s'il y en a une : vous n'avez rien a
ressaisir.

### Windows affiche un avertissement au lancement

C'est attendu, et ce n'est pas un virus. L'executable n'est pas signe numeriquement : Microsoft
ne connait donc pas son editeur. Cliquez sur **Informations complementaires**, puis sur
**Executer quand meme**. Le meme message peut apparaitre dans Chrome ou Edge au moment du
telechargement : choisissez **Conserver**.

### Ce que l'executable ne sait pas faire

**Demarrer une capture.** L'application lance l'agent de capture comme un programme separe, ce
qui n'existe plus une fois tout empaquete. L'executable sert a **consulter, analyser et
expliquer** ce qui est deja en base.

Pour capturer, utilisez `lancer.bat` et le mode navigateur, decrit plus haut : c'est l'agent
complet, avec les treize interfaces de votre machine.

## Si quelque chose ne marche pas

**« Python n'est pas installe, ou n'est pas dans le PATH »**
Python est installé mais Windows ne le trouve pas. Relancez l'installeur Python, choisissez
**`Modify`**, et cochez **« Add python.exe to PATH »**.

**« pip absent de cet environnement : installation... »**
Ce n'est pas une erreur, c'est une réparation. Un environnement créé par **`uv`** au lieu de
`python -m venv` ne contient pas pip. Le script l'installe lui-même avec `ensurepip`, livré avec
Python, puis poursuit. Laissez-le faire.

**« L'installation des dependances a echoue »**
Pas de connexion Internet, ou un proxy d'entreprise qui bloque. Si vous êtes sur un réseau
d'entreprise, renseignez le proxy avant de relancer :

```
.venv\Scripts\pip.exe install -r requirements.txt --proxy http://votre-proxy:8080
```

**Le tableau de bord s'ouvre mais aucun paquet n'apparaît**
La capture n'est pas active, ou Npcap manque. Vérifiez que vous avez bien cliqué sur `Démarrer`,
et que l'interface choisie correspond à votre connexion réelle.

**« Le port 8000 est deja utilise »**
Un autre programme occupe le port. Ouvrez `lancer.bat` avec le Bloc-notes et changez
`set "ANALYZER_PORT=8000"` en `set "ANALYZER_PORT=8001"`.

**La fenêtre se ferme instantanément au lancement**
Vous avez probablement double-cliqué sur `lancer.bat` avant d'installer. Installez d'abord avec
`installer-windows.bat`.

---

## Désinstaller

Supprimez le dossier du projet. C'est tout.

Si vous voulez aussi retirer Npcap : `Panneau de configuration` → `Programmes` → `Désinstaller un
programme` → `Npcap`.

---

## Ce que FlowScope fait — et ce qu'il ne fait pas

**Ce qu'il fait** : il lit les **en-têtes** des paquets qui passent sur votre réseau — qui parle à
qui, sur quel port, avec quel protocole, pendant combien de temps. Il les regroupe en
communications, explique chacune en français, et signale certains comportements inhabituels.

**Ce qu'il ne fait pas** : il **ne conserve jamais le contenu** des messages. Il ne déchiffre
rien, n'intercepte rien, ne modifie rien. Il observe des métadonnées, comme une enveloppe : on
sait qui l'a envoyée, à qui, quand, et quel poids — jamais ce qu'il y a dedans.

**Un point pour les jurys et les curieux** : cette limite n'est pas un oubli, c'est une décision,
et elle est vérifiable dans le code. Aucune charge utile n'est écrite en base, et la vue des
octets est reconstruite à partir des en-têtes analysés — pas recopiée du paquet.

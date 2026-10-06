# Télécharger FlowScope depuis GitHub

FlowScope est un analyseur de paquets réseau : il observe le trafic de votre machine, regroupe
les paquets en communications, et explique en français ce qui s'y passe.

Cette page ne parle que du **téléchargement**. Une fois le projet récupéré, la suite est dans
**[INSTALLATION-WINDOWS.md](INSTALLATION-WINDOWS.md)**.

---

## L'adresse

```
https://github.com/laviOGOU/network-analyzer
```

Le dépôt est **public** : aucune inscription, aucun compte GitHub n'est nécessaire. Vous pouvez
consulter le code, le télécharger, et le lire avant de l'exécuter — ce qui est la moindre des
choses pour un outil qui observe votre réseau.

---

## Méthode 1 — Télécharger l'archive (la plus simple)

**1.** Ouvrez l'adresse ci-dessus.

**2.** Cliquez sur le bouton vert **`Code`**, en haut à droite de la liste des fichiers.

**3.** Dans le menu qui s'ouvre, cliquez sur **`Download ZIP`**.

**4.** Décompressez l'archive où vous voulez. Windows crée un dossier
`network-analyzer-main` — vous pouvez le renommer en `FlowScope`.

**5.** Ouvrez le dossier et double-cliquez sur **`installer-windows.bat`**.

C'est tout. Le détail de ce que fait l'installateur est dans
**[INSTALLATION-WINDOWS.md](INSTALLATION-WINDOWS.md)**.

> **Sous Windows, faites attention à la décompression.** Windows ouvre les archives ZIP comme si
> c'était des dossiers, et un double-clic sur `installer-windows.bat` **à l'intérieur de
> l'archive non décompressée** ne fonctionne pas. Clic droit sur le ZIP → **`Extraire tout…`**
> avant d'aller plus loin.

---

## Méthode 2 — Avec Git (pour suivre les mises à jour)

Si Git est installé sur votre machine :

```
git clone https://github.com/laviOGOU/network-analyzer.git
cd network-analyzer
installer-windows.bat
```

Ensuite, pour récupérer les corrections sans tout retélécharger :

```
git pull
```

---

## Ce qu'il vous faudra en plus

**Python 3.11 ou plus récent** — obligatoire. Sur la première page de l'installeur Python, cochez
**« Add python.exe to PATH »**. Cette case est décochée par défaut et c'est la cause la plus
fréquente d'échec d'installation.

**Npcap** — pour la capture réelle. Sans lui, FlowScope démarre mais ne voit aucun paquet. Il est
téléchargeable sur **https://npcap.com/#download**, et son installation demande les droits
d'administrateur.

Les deux sont détaillés, avec les messages d'erreur et leur solution, dans
**[INSTALLATION-WINDOWS.md](INSTALLATION-WINDOWS.md)**.

---

## Que contient le dépôt

| Dossier | Ce qu'il contient |
|---|---|
| `agent/` | Le programme qui capture les paquets sur votre machine |
| `backend/` | Le serveur et le moteur d'explication |
| `web/` | Le tableau de bord |
| `tests/` | Les tests — 358 vérifications automatiques |
| `sql/` | Le schéma de la base, pour conserver l'historique |
| `docs/` | Documentation, dont ce guide et celui d'installation |
| `installer-windows.bat` | L'installation automatique |
| `lancer.bat` | Le démarrage |

---

## Une chose à savoir avant d'exécuter

FlowScope **ne conserve jamais le contenu** des messages qui passent sur votre réseau. Il lit les
**en-têtes** : qui parle à qui, sur quel port, avec quel protocole, pendant combien de temps. Il
ne déchiffre rien, n'intercepte rien, ne modifie rien.

C'est une décision de conception, pas une limite technique — et elle est vérifiable dans le code :
aucune charge utile n'est écrite en base, et la vue des octets du tableau de bord est
**reconstruite** à partir des en-têtes analysés, jamais recopiée du paquet.

Un outil qui observe un réseau doit dire ce qu'il observe. Celui-ci l'écrit.

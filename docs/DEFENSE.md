# Dossier de défense — Intelligent Network Packet Analyzer

Ce document s'adresse à l'auteur du projet. Il explique ce qui a été construit, pourquoi
chaque choix a été fait, comment les morceaux communiquent, et répond aux questions que
le jury posera probablement.

Il est écrit **par phase** : chaque phase ajoute sa section, sans effacer la précédente.

---

# Phase 1 — Observer et afficher

## 1. Ce qui a été construit

Un agent local qui capture le trafic réseau, transforme chaque paquet en fiche
structurée, et l'envoie par lots à un backend qui l'affiche dans une page web rafraîchie
chaque seconde.

**Ce qui marche, vérifié sur le réseau réel :** 1 264 paquets capturés en une trentaine de
secondes, TCP / UDP / DNS / ICMP / ICMPv6 / ARP, IPv4 et IPv6, avec deux machines du
réseau observées, 2 analyses partielles sur 1 264 (0,16 %), corrigées depuis.

**Ce qui n'existe pas encore, et c'est voulu :** les communications regroupées (flows), les
explications, la détection, l'enrichissement, la base de données, le déploiement. Chacun
arrive dans sa phase, conformément à la méthode de travail imposée.

## 2. Les cinq modules, expliqués simplement

### `agent/capture.py` — parler au réseau

C'est le seul module qui touche au pilote réseau. Il fait trois choses : lister les
interfaces, en choisir une, et ouvrir une capture en arrière-plan.

**Point à retenir :** lister les interfaces ne suffit pas à prouver qu'on peut capturer.
Le pilote Npcap peut autoriser la liste et refuser l'ouverture. Le module traduit donc
l'erreur en instructions (« relancez en administrateur » ou « réinstallez Npcap sans
l'option restrictrice ») au lieu de laisser passer un `PermissionError`.

### `agent/parser.py` — transformer un paquet en fiche

Il prend un paquet Scapy et rend un dictionnaire à clés fixes. Règle absolue : **aucun
champ obligatoire, aucune valeur inventée.** Un champ absent vaut `None`.

**Point à retenir :** il ne lève jamais d'exception. Si l'analyse échoue, la fiche porte
`analyse_partielle=True` et un motif. Un parseur qui plante sur un paquet malformé
permettrait à un attaquant de faire taire toute la surveillance avec un seul paquet bien
choisi.

### `agent/sender.py` — transmettre sans bloquer la capture

Il place les fiches dans une file, les regroupe par lots de 200, et les envoie. Si le
backend est injoignable, la file se remplit ; au-delà de 5 000 fiches, **les plus
anciennes sont abandonnées**, et le nombre d'abandons est affiché.

### `backend/` — recevoir, conserver, présenter

- `models.py` valide les données reçues (adresse IP réelle, port dans les bornes, textes
  bornés, champ inconnu refusé) ;
- `storage.py` les conserve dans un tampon circulaire borné ;
- `securite.py` exige un jeton d'agent pour écrire, et limite le débit ;
- `api/` expose les routes, sans aucune règle métier ;
- `main.py` assemble, sert les pages, et empêche toute trace technique de sortir.

### `web/` — montrer

Une page, deux thèmes, un tableau, des graphiques en barres. Le JavaScript interroge
l'API une fois par seconde.

## 3. Comment les fonctions communiquent

```
   RÉSEAU
      │  (paquets bruts, lus par le pilote Npcap)
      ▼
 capture.py ── appelle pour chaque paquet ──▶ parser.py
      │                                          │  rend un dictionnaire
      │◀─────────────────────────────────────────┘
      │
      ▼
 sender.py : file d'attente ──▶ regroupement par lots ──▶ HTTPS + jeton
      │
      │  (le réseau, encore — mais dans l'autre sens)
      ▼
 backend/main.py ──▶ api/ingestion.py ──▶ models.py (validation)
                              │                    │ si valide
                              ▼                    ▼
                        securite.py           storage.py
                       (jeton, débit)     (tampon circulaire)
                              │
                              ▼
                        web/ : la page interroge /api/v1/packets chaque seconde
```

**Le sens des dépendances est à sens unique.** `parser.py` ne connaît personne. `capture.py`
connaît `parser`. `main.py` connaît les trois. Aucun module de l'agent ne connaît le
backend. C'est ce qui permet de tester l'analyse sans réseau, et la file d'attente sans
backend.

**La seule chose qui traverse la frontière** entre l'agent et le backend, c'est un
dictionnaire JSON dont la forme est décrite dans `backend/models.py`. Un test
(`test_fiche_produite_par_le_parseur_est_acceptee`) vérifie que ce que l'agent produit, le
backend l'accepte. Sans ce test, un renommage de clé d'un seul côté ferait échouer tous
les envois en production.

## 4. Pourquoi ces choix

| Choix | Raison | Ce qu'on renonce à |
|---|---|---|
| **Scapy** | décode Ethernet, IP, TCP, UDP, DNS, ARP, ICMP, IPv6. L'écrire soi-même représente plusieurs milliers de lignes | plus lent qu'un décodeur en C : inadapté au-delà de quelques centaines de Mbit/s |
| **FastAPI** | validation par les types, documentation OpenAPI automatique, donc une API démontrable sans effort | un cadre plus lourd que Flask pour cette taille |
| **Pydantic** | refuse à l'entrée ce qui n'est pas conforme, avec un message précis sur le champ fautif | un peu de rigueur en plus à écrire, récompensée au premier incident |
| **httpx** | délai maximal en une ligne ; même famille que FastAPI côté serveur | `urllib` suffirait, mais sans délai lisible |
| **Jinja2 + JS vanilla** | aucune compilation, aucune dépendance à un cadre : le code du navigateur se lit tel quel | pas de composants réutilisables ; tenable à cette taille, pas au-delà |
| **Tampon en mémoire** | la phase 1 doit prouver la plomberie, pas la persistance | tout est perdu au redémarrage — assumé, la phase 5 branche Supabase |
| **File d'attente bornée** | la mémoire ne peut pas exploser ; l'abandon est chiffré | on perd des paquets anciens plutôt que récents — choix explicite |

## 5. Les deux défauts trouvés par la capture réelle

Ce sont les meilleurs arguments de cette phase : ils n'auraient pas été trouvés en
laboratoire.

### Défaut 1 — Les réponses mDNS d'une télévision

**Symptôme :** 2 paquets sur 1 264 marqués « analyse partielle », motif
`IndexError: list index out of range`.

**Cause :** la section « question » d'un message DNS n'existe pas toujours. Les réponses
mDNS d'une télévision du réseau n'en ont pas, et Scapy lève une erreur d'index en la
lisant, au lieu de rendre une valeur vide.

**Correction :** une fonction `_enregistrements_dns` qui normalise une section DNS —
absente, vide, ou contenant un seul enregistrement non indexable — en une liste. Elle
sert désormais à lire la question *et* les réponses.

**Leçon :** une lecture qui suppose une liste plante sur un élément unique, et
l'inverse est vrai aussi.

### Défaut 2 — Le compteur de réponses lu à la place du contenu

**Symptôme :** le nombre de réponses DNS valait `None` alors que la réponse en contenait une.

**Cause :** Scapy ne calcule les compteurs d'en-tête (`ancount`, `qdcount`) qu'au moment
où le paquet est **sérialisé**. Sur un paquet fraîchement construit, le champ vaut `None`.

**Correction :** on compte les enregistrements réellement présents dans la section, au
lieu de lire le champ d'en-tête.

**Leçon :** un compteur lu à la place du contenu est exactement le genre de valeur qui
devient fausse sans prévenir.

## 6. Cinq questions de défense probables

### Q1. Pourquoi un agent local, et pas simplement une capture depuis le serveur ?

Parce que c'est physiquement impossible. Un paquet ne quitte jamais le réseau local s'il
est destiné à une machine de ce réseau : le serveur en ligne ne le voit pas passer. Il
faudrait que la box lui envoie tout le trafic, ce qui n'est possible que sur un réseau
qu'on administre entièrement, et ce serait pire en termes de confidentialité.

Conséquence de conception : l'agent est le seul à voir les données brutes, et c'est lui
qui décide ce qui sort — des métadonnées, jamais de contenu.

### Q2. Pourquoi ne pas stocker les paquets dès la phase 1 ?

Parce qu'une base de données mal conçue coûte plus cher à corriger qu'à écrire au bon
moment. La phase 2 établit le schéma à partir des besoins réels (quels champs on
interroge, quels index sont utiles), une fois qu'on sait ce qu'on manipule. Le stockage
est déjà isolé derrière une classe : la phase 5 remplacera l'implémentation sans toucher
aux routes.

### Q3. Que se passe-t-il si le backend tombe pendant une capture ?

L'agent continue de capturer et d'analyser. Les fiches s'accumulent dans la file, qui est
bornée à 5 000 entrées. Au-delà, les plus anciennes sont abandonnées et **comptées** —
l'interface affiche le nombre d'abandons, jamais un silence.

Au retour du backend, les lots suivants partent normalement. Ce qui a été abandonné l'est
définitivement : le démonstrateur le dit plutôt que de le cacher.

### Q4. Un paquet malformé peut-il faire tomber l'analyseur ?

Non, et c'est un choix explicite. Le parseur est enveloppé dans un `except` volontairement
large : en cas d'échec, il rend une fiche avec `analyse_partielle=True` et un motif, au
lieu de lever une exception. Si l'exception remontait, elle arrêterait le fil de capture
de Scapy — et un seul paquet bien construit suffirait alors à faire taire toute la
surveillance. C'est exactement ce qu'un attaquant chercherait à obtenir.

Le cas réel des réponses mDNS, décrit plus haut, montre que ce filet sert vraiment.

### Q5. Le tableau de bord est public : n'est-ce pas une fuite de données ?

En partie, et c'est assumé. La page affiche des adresses IP, des ports et des noms de
domaines d'un réseau local. Trois protections limitent la portée : aucun contenu de
message n'est conservé (métadonnées seules), la page porte un avertissement visible, et
les données sont effacées après trente jours.

Deux points à savoir défendre : les **noms de domaines résolus** révèlent les sites
consultés — c'est l'information la plus sensible de l'ensemble, davantage que les adresses
IP ; et l'écriture est protégée par un jeton, mais la lecture est ouverte. Si le projet
devait servir hors exercice, il faudrait une authentification en lecture et une
anonymisation des adresses internes.

## 7. Vérifications à montrer au jury

```
.venv\Scripts\python.exe -m pytest tests/ -q          # 65 tests
.venv\Scripts\python.exe agent\main.py --interfaces   # que voit-on ?
.venv\Scripts\python.exe agent\main.py --interface "Wi-Fi" --a-blanc
```

Le mode `--a-blanc` est le plus utile à montrer : il prouve la capture et l'analyse sans
backend et sans jeton. Si la démonstration échoue, c'est la première chose à refaire isolément.

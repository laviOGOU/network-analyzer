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
.venv\Scripts\python.exe -m pytest tests/ -q          # tests du parseur et de l'API
.venv\Scripts\python.exe agent\main.py --interfaces   # que voit-on ?
.venv\Scripts\python.exe agent\main.py --interface "Wi-Fi" --a-blanc
```

Le mode `--a-blanc` est le plus utile à montrer : il prouve la capture et l'analyse sans
backend et sans jeton. Si la démonstration échoue, c'est la première chose à refaire isolément.

---

# Phase 2 — Analyser et structurer

## 1. Ce qui a été construit

Deux choses, et une seule idée : **un paquet seul ne dit presque rien**.

**Le regroupement en communications** (`agent/flows.py`) : les paquets sont rassemblés en
conversations entre deux machines. Chaque communication porte son initiateur, sa durée,
ses compteurs **par sens**, et un état déduit des indicateurs observés.

**Le schéma de base de données** (`sql/schema.sql`) : six tables commentées, avec
contraintes, index, sécurité au niveau des lignes et purge automatique. Il a été **exécuté
et éprouvé** sur un PostgreSQL réel avant d'être confié à Supabase, et
`sql/verifier-schema.sql` rejoue dix-sept contrôles de comportement.

Mesures sur trafic réel : **540 paquets → 56 communications**, dont 3 avec ouverture
complète observée (« établie »), 20 fermées, 31 en cours, 2 en tentative — et **18 marquées
d'état incertain**.

## 2. Les trois décisions qui portent tout le reste

### La clé des communications est triée

`(TCP, 93.184.216.34:443, 192.168.1.5:49703)` et
`(TCP, 192.168.1.5:49703, 93.184.216.34:443)` désignent **la même conversation**.

Sans ce tri, chaque connexion compterait deux fois — une pour l'aller, une pour le retour —
et toutes les statistiques seraient fausses d'un facteur deux. Une seule ligne de code,
et tout le reste en dépend.

### L'incertitude est une donnée, pas une gêne

Quand la capture commence au milieu d'une conversation, on n'a pas vu son ouverture. On ne
peut donc pas affirmer qu'elle s'est établie normalement. La communication porte
`etat_certain = false` et une phrase qui dit ce qui manque :

> « Capture commencée après le début de cette communication : son ouverture n'a pas été
> observée. »

**C'est le champ le plus important du projet.** Il aurait été plus simple d'afficher
« en cours » sans rien préciser : le tableau de bord aurait paru plus net, et il aurait
menti. L'interface affiche cet état avec une pastille en pointillés et le texte complet.

### La base refuse plutôt que d'espérer

Trois exemples, tous vérifiés par `sql/verifier-schema.sql` :

- une **adresse IP privée** ne peut pas entrer dans le cache d'enrichissement : une
  contrainte SQL l'interdit, plutôt que de compter sur la vigilance du code Python ;
- une **clé de communication en double** est refusée : c'est ce qui rend sans danger le
  fait que l'agent renvoie la même conversation à chaque lot ;
- une **alerte dont le niveau n'est ni « observation », ni « hypothèse », ni « alerte »**
  est refusée : la distinction imposée par l'énoncé est protégée par le schéma, pas
  seulement par la bonne volonté du développeur.

## 3. Comment les fonctions communiquent

```
   capture ──▶ parser.analyser(paquet) ──▶ fiche
                  │
                  ▼
           flows.SuiviCommunications.ajouter(fiche)
                  │   crée ou met à jour la communication
                  │   flows.maj_etat(communication)  ──▶ état + note + certitude
                  ▼
         file d'attente (sender.py)
                  │   le lot porte les paquets ET les communications à jour
                  ▼
   POST /api/v1/ingest ──▶ models.py valide ──▶ storage.enregistrer_communications()
                  │                                   (refonte par clé)
                  ▼
   GET /api/v1/flows ──▶ tableau de bord (vue Connections)
```

**Pourquoi les communications voyagent dans le même lot que les paquets** : elles
décrivent ces paquets-là. Les envoyer séparément ouvrirait la porte à un affichage où une
conversation apparaîtrait avant les paquets qui la composent.

**Pourquoi l'agent renvoie les communications en cours à chaque lot** : elles évoluent.
Le backend les refond par clé ; la dernière version reçue est la bonne. L'agent envoie
aussi une dernière fois celles qui viennent de se terminer — sans quoi l'état final, le
plus intéressant, ne partirait jamais.

## 4. Cinq questions de défense probables

### Q1. Pourquoi trier la clé plutôt que garder le sens de la conversation ?

Parce que le regroupement et le sens sont deux besoins différents. Le regroupement demande
une identité stable : c'est le rôle de la clé triée. Le sens demande de savoir qui a parlé
le premier : c'est le rôle du champ `initiateur`, conservé séparément.

Garder deux clés (une par sens) obligerait ensuite à les réunir pour chaque statistique —
et toute réunion incomplète donnerait un chiffre faux.

### Q2. Comment déduisez-vous l'état d'une connexion TCP ?

À partir des indicateurs observés, et du fait qu'on a vu — ou non — le début :

| Ce qui est observé | État | Certain ? |
|---|---|---|
| SYN seul | tentative | oui |
| SYN seul, plus de 3 secondes | échec probable | oui |
| SYN + SYN-ACK + ACK | établie | oui |
| SYN + SYN-ACK, sans le 3ᵉ message | tentative | non |
| Un FIN (un seul côté) | fermée | non |
| Un FIN des deux côtés | fermée | oui |
| Un RST | fermée | oui |
| Première observation = un ACK ou des données | en cours | non |

Le délai de trois secondes pour « échec probable » correspond au moment où une pile TCP
réémet en général. Il n'est pas mesuré par rapport à l'horloge de la machine mais par
rapport **au dernier paquet observé** : c'est ce qui rend le mode replay juste. Sinon,
rejouer une capture d'hier ferait passer chaque SYN sans réponse pour un échec, alors que
la réponse est peut-être dans le fichier.

### Q3. Pourquoi 60 secondes pour TCP et 30 pour UDP ?

Une connexion TCP inactive plus d'une minute est presque toujours morte, même sans FIN.
UDP n'a pas de notion de connexion : un silence veut dire « c'est fini », et 30 secondes
suffisent.

Après un FIN ou un RST, on n'attend que **2 secondes** : la fin est explicite, et une
nouvelle conversation entre les mêmes machines ne doit pas être confondue avec l'ancienne.

Ces valeurs sont réglables (`par défaut : 60 / 30 / 2 secondes`), parce qu'elles dépendent
du réseau observé. Sur un réseau lent, 60 secondes couperaient des conversations encore
vivantes.

### Q4. Pourquoi ne pas stocker tous les paquets en base ?

Parce que ce serait absurde en pratique. Un foyer produit facilement 2 à 5 millions de
paquets par jour ; à 300 octets de métadonnées par ligne, cela fait plus d'un gigaoctet
quotidien, pour une information que personne ne relit.

Le schéma conserve donc une ligne par paquet jusqu'à un plafond par communication, plus
ceux qui portent un fait notable, et le reste est résumé dans les compteurs de `flows`.
Le plafond est un réglage, pas une constante cachée.

### Q5. La purge à trente jours : pourquoi, et comment est-elle garantie ?

Parce que le tableau de bord est public : des adresses IP et des noms de domaines ne
doivent pas s'accumuler indéfiniment.

`analyzer.purger(30)` supprime les captures anciennes, et **tout le reste suit par
cascade** — communications, paquets, alertes, explications. C'est la raison pour laquelle
les clés étrangères ont été déclarées en `ON DELETE CASCADE` : un effacement de données
doit être complet ou ne pas être. Le contrôle correspondant est dans
`sql/verifier-schema.sql`, et il échoue si une seule ligne survit.

## 5. Vérifications à montrer au jury

```bat
.venv\Scripts\python.exe -m pytest tests/ -q                     :: 103 tests
psql -v ON_ERROR_STOP=1 -d analyzer_test -f sql/verifier-schema.sql :: 17 contrôles SQL
```

Puis, sur trafic réel : lancer le backend et l'agent, et observer la section
**Connections** du tableau de bord. Les pastilles en pointillés sont les états incertains —
celles qu'il faut savoir expliquer.

---

# Phase 3 — Comprendre et expliquer

## 1. Ce qui a été construit

Le module que l'énoncé désigne comme le plus important : **`backend/explain/rules.py`**.

| Élément | Contenu |
|---|---|
| Base des services | 60 ports documentés — nom, usage, et caractère sensible |
| Base des protocoles | TCP, UDP, ICMP, ICMPv6, ARP, IP, et un cas « non reconnu » |
| Base des états | les six états produits en phase 2, chacun expliqué en une phrase |
| Règles | 8 règles, chacune portant un nom (`port_service_connu`, `dns_resolution`, `connexion_entrante`…) |

Plus `backend/explain/llm.py` : la couche IA facultative, et l'interface qui affiche les
explications en séparant les faits de l'interprétation.

## 2. Pourquoi ces choix

**La règle absolue : ne jamais présenter une hypothèse comme une certitude.** Le port 443
ne prouve pas HTTPS — il existe un consensus très fort, mais rien n'interdit d'y faire
tourner autre chose. Écrire « HTTPS » serait faux dans le principe, même en tombant juste
neuf fois sur dix. On écrit donc « probablement HTTPS », et on écrit *pourquoi* on le pense.
Un test vérifie cette propriété sur le texte produit : il exige le mot « probablement » et
la mention qu'un port est une convention, pas une preuve.

Ce choix a une conséquence assumée : l'outil paraît moins affirmatif qu'il pourrait l'être.
C'est voulu. Un outil d'analyse qui affirme des choses fausses avec assurance cesse d'être
consulté, et à juste titre.

**La structure fixe.** Chaque explication a exactement cinq parties — titre, faits observés,
interprétation, confiance, explication simple. Une seule fabrique (`_explication`) les
produit toutes : la forme ne peut donc pas dériver au fil des ajouts. C'est cette structure
qui permet à l'interface de séparer visuellement ce qui a été **mesuré** de ce qui a été
**déduit** — la distinction la plus importante de tout l'outil.

**L'ordre des règles décide de l'explication principale.** La première règle applicable
devient « ce que l'on peut en dire ». Les règles précises passent donc avant les règles
générales. Ce détail a été corrigé après observation : dans la première version, une
requête DNS vers la box recevait pour toute explication « échange interne au réseau
local » — vrai, et parfaitement inutile. La règle générale s'applique à tout, elle ne doit
donc jamais masquer une règle précise.

**L'IA vient après les règles, jamais à leur place.** Un modèle de langage ne connaît pas
ce qui circule sur votre réseau : interrogé seul, il produirait une réponse plausible et
fausse. Les règles observent, l'IA reformule. Trois garde-fous : elle n'est active que si
une clé est configurée ; sa réponse est rejetée si elle contient un chiffre absent des
faits ; et toute panne ramène au texte des règles sans erreur visible. Dans les trois cas
de repli, l'utilisateur obtient une explication complète — seule la formulation change.

**Le rappel de prudence est systématique.** Une phrase accompagne chaque détail affiché :
« identifications déduites du numéro de port : probables, jamais certaines ». Elle est
présente même quand la confiance est haute, parce que c'est précisément là qu'on l'oublie.

## 3. Comment les fonctions communiquent

    paquets (phase 1) → flows.py (phase 2) → une communication
                                                  │
                                                  ▼
                                    explain/rules.py  ──► explications (structure fixe)
                                                  │
                                                  ▼
                                    api/paquets.py  ──► /api/v1/flows (résumé, en cache)
                                                        /api/v1/flows/explications (détail)
                                                  │
                                                  ▼
                                    dashboard.js  ──► blocs « Faits observés » /
                                                       « Interprétation » / « En clair »
                                                  │
                                          (facultatif, sur demande explicite)
                                                  ▼
                                    explain/llm.py  ──► reformulation, ou repli

Un point sur les deux chemins d'explication : celui de la **liste** est mis en cache, parce
qu'il ne dépend que de trois valeurs (protocole, port, état) et qu'il est calculé pour cent
cinquante lignes toutes les trois secondes. Celui du **détail** tient compte des adresses,
des volumes et du sens de l'échange — c'est le plus riche, et il n'est calculé qu'au clic.

## 4. Cinq questions de défense

**1. Pourquoi ne pas avoir confié les explications à un modèle de langage, qui écrit mieux ?**

Parce qu'il ne sait pas ce qui circule sur le réseau. Sa réponse serait plausible et non
fondée — exactement ce qu'un outil de sécurité ne doit pas produire. Ici, la
responsabilité du contenu reste du côté vérifiable : les règles observent et produisent
les faits, l'IA ne fait que reformuler, et sa sortie est rejetée si elle introduit un
chiffre qui n'était pas dans les faits.

**2. Le port 443, ce n'est pas HTTPS ?**

Presque toujours, oui. Mais « presque toujours » n'est pas « toujours » : un port est une
convention, pas une preuve. Rien n'empêche un service quelconque d'écouter sur 443. La
phrase exacte de l'outil est « généralement associé à HTTPS », suivie de la raison, et le
contenu échangé n'est pas analysé — c'est écrit dans l'interface.

**3. Comment savez-vous que vos explications sont justes ?**

Trois raisons. Le moteur est **déterministe** : les mêmes paquets produisent toujours les
mêmes phrases, donc une explication peut être rejouée et comparée. Chaque phrase cite un
**fait nommé** — « port de destination = 443 » — que n'importe qui peut vérifier dans les
paquets. Et les tests vérifient des **propriétés** plutôt que des tournures : la présence
du mot « probablement », la cohérence entre confiance et certitude de l'observation,
l'absence de chiffre inventé. Un test qui vérifierait le texte exact casserait à la
première reformulation, sans rien protéger.

**4. Que se passe-t-il si une règle plante ?**

Les autres restent appliquées, et l'incident est visible : une explication intitulée
« Règle en échec » nomme la fonction fautive. Le principe est le même que celui du parseur
en phase 1 : un élément fautif se signale, il n'emporte pas tout le reste. Sur un tableau
de bord public, une case vide est un moindre mal ; une erreur cinq cents ne l'est pas.

**5. Pourquoi l'ordre des règles est-il important ?**

Parce que la première règle applicable devient l'explication principale. Une règle générale
s'applique partout : placée en tête, elle masque tout le reste. C'est arrivé — une requête
DNS vers la box s'affichait « échange interne au réseau local », ce qui est exact et
n'apprend rien. Les règles précises passent donc avant, et un test verrouille cet ordre.

## 5. Ce qui a été trouvé en écrivant cette phase

- **Un manque dans la base de règles** : la situation « machine du réseau vers Internet »
  n'était pas couverte — ni local-contre-local, ni public-contre-public. C'est pourtant le
  trafic le plus fréquent qui existe. Le cas de la connexion entrante, plus rare et plus
  intéressant, a été ajouté dans la même passe.
- **Un défaut d'accessibilité réel** : le tableau se reconstruit toutes les trois secondes,
  ce qui détruisait le bouton ayant le focus. Un lecteur au clavier perdait sa place sans
  rien avoir fait. Le focus est désormais noté et restitué après chaque reconstruction, et
  un test automatisé l'éprouve en laissant passer plus d'un cycle complet.
- **Une incohérence typographique** : « 1.8 ko » à l'anglaise au milieu d'un texte français.

---

# Phase 4 — Détecter

## 1. Ce qui a été construit

`agent/detection.py` : **huit règles**, trois niveaux, et une règle de synthèse.

| Règle | Ce qu'elle repère | Niveau |
|---|---|---|
| `scan_ports` | une machine frappe à de nombreux ports d'une même cible | hypothèse |
| `connexions_repetees` | la même connexion revient à intervalles rapprochés | hypothèse |
| `volume_sortant` | un envoi important vers l'extérieur, avec peu de retour | hypothèse |
| `echecs_repetes` | des ouvertures restées sans réponse | observation |
| `service_sensible_entrant` | une connexion d'Internet vers un service qui ouvre une machine | observation |
| `multiplication_destinations` | une machine joint beaucoup d'adresses différentes | observation |
| `dns_volume` | beaucoup de demandes de résolution de noms | observation |
| `machine_inconnue` | un appareil du réseau apparaît pour la première fois | observation |
| `faisceau_indices` | **plusieurs indices convergents sur une même machine** | **alerte** |

## 2. Pourquoi ces choix

**Les niveaux disent le degré de certitude, pas le degré de danger.** C'est la distinction
la plus importante du module, et la plus souvent ratée :

- **observation** — un fait mesuré dont on ne conclut rien ;
- **hypothèse** — une forme qui ressemble à quelque chose, et que des usages ordinaires
  produisent aussi ;
- **alerte** — plusieurs hypothèses de familles différentes qui convergent sur une même
  machine.

**Aucune règle isolée ne produit une alerte.** C'est le cœur du module. Chacune des formes
détectées se produit naturellement plusieurs fois par jour sur un réseau domestique : un
navigateur ouvre dix connexions par minute, une télévision vérifie ses mises à jour toutes
les heures, un téléphone interroge le DNS en boucle. Exiger trois indices convergents fait
tomber le bruit à presque rien — et le peu qui reste mérite vraiment un regard. Un test
éprouve cette propriété **forme par forme** : chacune, prise seule, ne doit jamais produire
d'alerte.

**Deux règles d'une même famille ne comptent pas deux fois.** « Vingt ports contactés » et
« vingt connexions répétées » décrivent le même phénomène sous deux angles. Les compter
séparément gonflerait artificiellement le faisceau et ferait passer une seule observation
pour trois. Le module compte des familles, pas des règles.

**Les observations ne comptent pas du tout.** Elles décrivent des faits sans rien supposer ;
les faire converger serait compter deux fois la même chose. Un navigateur qui ouvre une page
produit « beaucoup de destinations » et « beaucoup de résolutions » : ce n'est pas un
faisceau d'indices, c'est une page web.

**Chaque détection nomme ses faux positifs.** C'est une exigence du sujet, et c'est surtout
ce qui rend une détection utilisable. Un scanner de ports peut être un administrateur qui
vérifie son parc ; un volume sortant peut être une sauvegarde. Une détection qui cacherait
ce qu'elle peut avoir de faux laisserait croire à une conclusion. Un test vérifie que ce
champ est rempli pour **toutes** les règles, et qu'il est consistant — pas une phrase vide.

**Les seuils sont tous au même endroit**, au début du fichier. Un jury qui demande
« pourquoi quinze ports ? » obtient une réponse en une ligne, pas une chasse dans le code.

## 3. Comment les fonctions communiquent

    paquets → flows.py → communications ──────────► detection.py ──► détections
                                │                         │
                                │                         └── analyse l'ensemble des
                                │                             conversations vivantes, et
                                │                             non le seul lot courant
                                ▼
                          sender.py ──► POST /api/v1/ingest ──► storage.py
                                                                     │
                                            GET /api/v1/alerts ◄─────┘
                                                     │
                                                     ▼
                                              dashboard.js  ──► cartes « Alerts »

**Pourquoi la détection reçoit la table entière et non le lot courant.** Un balayage
répartit ses tentatives sur plusieurs lots : si la détection ne voyait que le lot en cours,
elle ne verrait jamais les quinze ports ensemble, et la règle la plus utile du module ne se
déclencherait jamais. C'est un point de conception, pas un détail d'implémentation.

**Pourquoi le faisceau se calcule en dernier.** C'est un jugement sur ce que les autres
règles viennent de trouver, et il doit voir l'ensemble des détections connues, y compris
celles des lots précédents : une convergence peut se former sur plusieurs minutes.

## 4. Cinq questions de défense

**1. Pourquoi une seule règle ne suffit-elle pas à déclencher une alerte ?**

Parce que chacune se déclenche sur un réseau normal. J'ai vérifié cette propriété forme par
forme avec un test dédié : un balayage seul, des connexions répétées seules, un envoi
massif seul ne produisent jamais d'alerte. Il faut trois familles différentes sur la même
machine. Un outil qui crie au loup cesse d'être lu — et un outil d'analyse qu'on ne lit plus
ne sert à rien, quelle que soit la finesse de ses règles.

**2. Votre règle de balayage ne va-t-elle pas signaler du bruit ?**

Si, et c'est écrit dans la détection elle-même. Un logiciel qui cherche son serveur en
essayant plusieurs ports, une application mal configurée qui réessaie, un téléviseur en
recherche produisent la même forme. C'est pour cela que le niveau est **hypothèse** et non
alerte, et que les faux positifs sont affichés dans l'interface à côté de l'observation.
Le lecteur a les deux informations et décide.

**3. Comment savez-vous que vos seuils sont bons ?**

Je ne le sais pas de façon absolue, et je ne le prétends pas. Ils viennent du trafic réel
observé pendant la mise au point : quinze ports en soixante secondes, huit connexions en
cinq minutes, cinq mégaoctets dans une communication. Ils sont tous regroupés au début du
fichier pour pouvoir être ajustés en une ligne. Ce qui est vérifié, en revanche, c'est
qu'ils **sont respectés** : un port de moins que le seuil ne déclenche rien, et un test le
vérifie.

**4. Pourquoi la règle « nouvel appareil » ne se déclenche-t-elle pas au premier lot ?**

Parce que, au premier lot, toutes les machines sont nouvelles : le signaler n'apprendrait
rien et noierait le reste. Le premier lot sert de référence. Un test le vérifie — c'est le
premier piège d'un module de détection, et il est facile à ne pas voir.

**5. Pourquoi le niveau « observation » existe-t-il, si on n'en conclut rien ?**

Parce que savoir est déjà utile. « Cette machine est apparue pour la première fois » ne
suppose rien, mais évite de s'étonner d'un trafic inconnu. « Cette adresse publique a
contacté votre réseau sur le port 445 » ne dit pas qu'il y a eu intrusion, mais mérite
d'être su. Les confondre avec des alertes serait aussi fautif que de les taire.

## 5. Ce qui a été trouvé en écrivant cette phase

- **Des faux appareils à chaque capture.** Le premier essai sur trafic réel a annoncé
  « nouvel appareil » pour `255.255.255.255`, pour `0.0.0.0`, pour `169.254.x` et pour des
  adresses IPv6 locales de lien (`fe80::`). Aucune ne désigne une machine : ce sont des
  adresses de service, et elles apparaissent **en premier**, avant toute machine réelle.
  Quatre faux appareils au démarrage suffisent à ce qu'on ne lise plus les détections. La
  règle ne considère désormais que les adresses qui identifient durablement un appareil.
- **Une table partagée sans verrou.** La table des communications est écrite par le fil de
  capture et parcourue par le fil d'envoi — qui, depuis cette phase, l'interroge encore
  plus souvent pour lancer la détection. Sans protection, la parcourir pendant qu'une
  communication s'y ajoute lève « dictionary changed size during iteration ». Un verrou a
  été ajouté sur les quatre points d'accès.
- **Un test de mon outil de vérification devenait faux tout seul.** Les sélecteurs du
  script cherchaient les blocs « faits observés » dans toute la page ; depuis que les cartes
  de détection en affichent aussi, il ramenait le premier bloc venu — celui d'une alerte.
  Les sélecteurs sont maintenant cadrés sur le panneau concerné.
- **Une dépendance interdite entre les deux moitiés du projet.** Le backend lisait les
  seuils de l'agent par un import direct. L'agent tourne sur la machine surveillée, le
  backend en ligne : une dépendance obligatoire ferait échouer le déploiement en ligne pour
  une information d'agrément. L'import est désormais facultatif.

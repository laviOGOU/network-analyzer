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

---

# Phase 5 — Enrichir, conserver, rejouer, déployer

## 1. Ce qui a été construit

| Élément | Ce qu'il fait |
|---|---|
| `backend/enrichment.py` | situe une adresse (ipinfo.io) et rapporte sa réputation (AbuseIPDB) |
| `agent/replay.py` | rejoue un fichier `.pcap` par **la même chaîne** que la capture |
| `backend/stockage_postgres.py` | conserve tout dans PostgreSQL — donc dans Supabase |
| `sql/schema.sql` | la clé qui empêche les doublons d'alerte, et la purge à 30 jours |

## 2. Pourquoi ces choix

**L'enrichissement n'envoie jamais une adresse privée à un service tiers.** Ni 192.168.x,
ni 10.x, ni fe80::. Ces adresses ne sortent pas sur Internet : aucun tiers ne peut rien en
dire, et les interroger reviendrait à publier chez deux fournisseurs la topologie de votre
réseau local. Le schéma interdit déjà ces lignes par une contrainte ; le code les écarte en
amont. Et un test ne vérifie pas seulement que la fonction rend `None` : il vérifie
qu'**aucune requête HTTP n'a été tentée** — car une fonction qui interrogerait le service
avant de renoncer aurait déjà divulgué ce qu'il fallait protéger.

**L'enrichissement est facultatif, et tout fonctionne sans lui.** Sans clé configurée, rien
ne se passe : les adresses s'affichent sans contexte, et le reste de l'outil est intact. Un
outil d'analyse qui cesserait de marcher sans accès à un service tiers serait inutilisable
au pire moment — et sur un réseau isolé, il ne fonctionnerait pas du tout.

**Le mode replay n'est pas une démonstration à part : c'est la preuve de l'architecture.**
Il traverse exactement la même chaîne que la capture — même analyseur, même table de
communications, même détection, même transmission. Seule la source des paquets change. Un
outil dont tout le raisonnement serait soudé à la capture en direct ne pourrait pas rejouer
un fichier ; celui-ci le fait en trois lignes de configuration.

**Supabase est PostgreSQL.** Il n'y a donc pas de code « Supabase » : il y a du code
PostgreSQL, et une chaîne de connexion. `ANALYZER_DATABASE_URL` pointe vers Supabase en
ligne, vers une base locale pendant la mise au point. C'est ce qui a permis d'éprouver la
persistance pour de vrai — écriture, mise à jour, purge, cascade — **avant** de la déployer.

**Le choix du stockage se fait à un seul endroit**, dans la couche de dépendances. Aucune
route ne sait si elle lit en mémoire ou dans PostgreSQL : elles appellent les mêmes
méthodes. C'est la promesse que cette couche faisait dès la phase 1, et elle est tenue.

## 3. Comment les fonctions communiquent

    fichier .pcap ──► replay.py ──┐
                                  ├──► parser.py ──► flows.py ──► detection.py
    interface réseau ──► capture.py ──┘                    │              │
                                                           ▼              ▼
                                              sender.py ──► POST /api/v1/ingest
                                                           │
                                    ┌──────────────────────┴────────────┐
                                    ▼                                   ▼
                          stockage_postgres.py                  enrichment.py
                          (Supabase en ligne)                   (ipinfo.io, AbuseIPDB)
                                    │                                   │
                                    └──────────────► GET /api/v1/* ◄────┘
                                                            │
                                                            ▼
                                                     dashboard.js

## 4. Cinq questions de défense

**1. Pourquoi ne pas enrichir toutes les adresses, y compris locales ?**

Parce qu'aucun service externe ne peut dire quoi que ce soit d'une adresse privée : elle
n'existe que dans votre réseau. L'interroger enverrait à un tiers une information qu'il ne
peut pas traiter, et qui décrit votre réseau. C'est une perte de quota et une fuite
d'information, pour un résultat vide. Le code l'écarte, la base l'interdit, et un test
vérifie qu'aucune requête n'est tentée.

**2. En quoi le mode replay prouve-t-il quelque chose sur l'architecture ?**

Il rejoue un fichier en traversant la même chaîne que la capture : même analyseur, même
table de communications, même détection, même envoi. Si le raisonnement avait été soudé à la
capture en direct — par exemple en lisant les paquets directement dans la boucle de capture
—, le replay serait impossible sans réécrire la moitié du code. Il tient en une option.

**3. Un score de réputation élevé signifie-t-il que l'adresse est malveillante ?**

Non, et l'interface le dit. Un score est l'avis d'un service tiers, à un instant donné, sur
des signalements qui peuvent être anciens ou erronés. Une adresse partagée par des milliers
d'utilisateurs — un opérateur mobile, un hébergeur — accumule des signalements sans qu'aucun
de ses utilisateurs actuels ne soit en cause. Le score est affiché comme un contexte, jamais
comme une conclusion.

**4. Où sont les données, et combien de temps ?**

Dans une base PostgreSQL — Supabase en ligne. Trente jours par défaut, configurable. La
purge supprime les sessions anciennes, et la cascade emporte leurs paquets, leurs
communications et leurs détections. Un test vérifie que rien ne subsiste après la purge :
une cascade incomplète ferait grossir la base en silence pendant des mois.

**5. Que se passe-t-il si la base de données est indisponible ?**

Le backend démarre quand même, et le dit : le schéma absent est signalé avec la commande
qui le crée. Les lots suivants échouent proprement au lieu de faire tomber le service. Le
choix est assumé : un backend qui refuse de démarrer parce que la base est momentanément
injoignable est plus difficile à diagnostiquer qu'un backend qui démarre en annonçant ce
qui ne va pas.

## 5. Ce qui a été trouvé en écrivant cette phase

- **Le défaut le plus important du projet, trouvé par le mode replay.** La table des
  communications comparait les paquets à l'horloge de la machine. En direct, les deux
  coïncident ; en rejeu, elles diffèrent de plusieurs mois — et **toutes** les connexions
  d'un fichier ancien ressortaient en « échec probable ». Le rejeu produisait exactement le
  contraire de ce que contenait le fichier. Les deux sources exposent maintenant un
  « maintenant » qui leur est propre : l'heure courante pour la capture, la date du dernier
  paquet lu pour un fichier.
- **Une contrainte d'unicité inventée.** Le stockage PostgreSQL utilisait une clé
  d'unicité `(session, titre, adresse)` qui n'existait pas dans le schéma. La base a refusé,
  à raison : c'est le schéma qui décide, pas le code. La bonne clé — `(session, règle,
  adresse)` — a été ajoutée au schéma, ce qui a révélé que le schéma ne protégeait pas
  encore contre le doublon d'alerte que la phase 4 évitait déjà en mémoire.
- **Une session manquante faisait échouer tout un lot.** Les communications et les
  détections ne créaient pas la session dont elles dépendent : un agent envoyant un lot
  partiel voyait sa clé étrangère rejetée, et l'information était perdue pour une ligne
  absente.
- **Un `NameError` au premier paquet rejoué.** `main.py` n'importait pas les dates, et une
  exception dans le traitement d'un paquet tuait tout le rejeu **en silence**. Le rejeu
  compte désormais les échecs et s'arrête au bout de cinq consécutifs en disant pourquoi,
  plutôt que de parcourir un million de paquets sans rien envoyer.


---

# Lot A — Voir et trier

## 1. Ce qui a été construit

| Élément | Où |
|---|---|
| Filtres d'affichage `proto:tcp port:443` | `backend/filtres.py`, `backend/filtres_sql.py` |
| Légende des couleurs et des niveaux | `web/templates/index.html` (classes réelles) |
| Vue par couche avec explication | `backend/explain/couches.py` |
| Vue des octets des en-têtes | rendue depuis `/api/v1/layers` |
| Export CSV et JSON | `backend/export.py` |
| Validation du filtre de capture BPF | `agent/bpf.py` |

## 2. Pourquoi ces choix

**Le filtre est une donnée, jamais du texte.** L'expression devient des couples
(champ, valeur) ; les valeurs deviennent des **paramètres liés** en SQL, et les noms de
colonnes viennent d'une table écrite dans le code. Rien de ce que l'utilisateur écrit ne
peut devenir une requête. Un test vérifie la forme des critères, un autre vérifie qu'une
valeur hostile n'atteint jamais le fragment SQL, et un troisième l'exécute contre un vrai
PostgreSQL : cinq tentatives d'injection, aucune ligne ramenée, base intacte.

**Un filtre incompris est refusé, avec la liste des champs valides.** 400, et non une
liste vide. Un filtre silencieusement ignoré ferait lire des résultats complets en croyant
lire des résultats filtrés — l'utilisateur conclurait quelque chose de faux sur son réseau.

**Un seul filtre pour trois listes, et rien n'est tu.** `proto` ne veut rien dire pour une
détection. Trois comportements étaient possibles, deux sont mauvais : lever une erreur
prive la vue d'affichage ; ignorer en silence fait mentir la liste. Le troisième est
retenu : on applique ce qui s'applique, et l'interface annonce ce qui a été écarté.

**La légende emploie les classes CSS réellement affichées.** Une légende recopiée à la main
devient fausse au premier changement de couleur sans que personne ne s'en aperçoive. Un
contrôle automatisé compare les couleurs calculées des deux côtés.

**La vue des octets est reconstruite, et ses trous sont visibles.** Aucun octet brut ne
circule dans ce projet : les octets affichés sont recalculés depuis les champs analysés.
Ce que l'outil n'extrait pas — séquence, acquittement, fenêtre, sommes — s'affiche `??`.
Les combler par des zéros donnerait un affichage plus complet et faux. Cette vue ne prétend
pas montrer le paquet : elle montre **ce que l'analyseur en a compris**.

**Le CSV commence par une marque d'encodage et sépare par des points-virgules.** Sans le
BOM, Excel affiche « Ã© » à la place de « é » ; avec des virgules, un tableur français met
tout dans une colonne. C'est le détail qui fait qu'un export correct « ne marche pas ».

**Le filtre de capture est validé par la bibliothèque qui filtrera.** On ne réécrit pas un
analyseur de syntaxe BPF : on demande à libpcap de compiler l'expression — la seule
validation qui garantisse que ce qui est accepté ici le sera là. Une erreur de filtre de
capture est irréversible : ce qui est exclu n'existe plus.

## 3. Trois questions de défense

**1. Pourquoi deux syntaxes de filtre différentes ?**

Parce qu'elles ne font pas la même chose. Le filtre **d'affichage** trie ce qu'on regarde :
il agit après coup, sur des données déjà reçues, et peut être changé à tout moment. Le
filtre **de capture** décide de ce qui est enregistré : ce qu'il exclut n'existe plus. Le
premier a des champs nommés et se cumule avec un ET ; le second est du BPF, évalué par
libpcap avant même que le paquet remonte. Les confondre donnerait à croire qu'on peut
« rattraper » une capture trop restrictive — c'est faux, et c'est la raison du message
d'erreur qui rappelle la syntaxe de l'autre.

**2. Votre vue hexadécimale est incomplète, avec des `??` partout. Quel intérêt ?**

Elle est incomplète **parce qu'elle est honnête**. L'outil ne transporte aucun octet brut —
c'est une règle du projet, pas un oubli — donc il ne peut montrer que ce qu'il a analysé.
Afficher des zéros à la place des numéros de séquence serait plus joli et faux. Et la vue
a une valeur pédagogique inattendue : elle montre exactement ce que l'analyseur comprend
d'un paquet, ce qui est précisément le sujet du projet. Le jour où l'analyseur extraira
`seq` et `ack` — prérequis de la détection des retransmissions — la vue se complétera
d'elle-même, et un test échouera pour le rappeler.

**3. Le filtre est-il protégé contre l'injection ?**

Oui, et de trois façons qui se cumulent. L'expression est découpée en couples
(champ, valeur) : il n'y a jamais de chaîne de requête à construire. Les valeurs passent
par des paramètres liés, jamais par concaténation. Et les noms de colonnes viennent d'une
table figée dans le code : une valeur ne peut pas devenir une colonne. Trois tests le
vérifient — la forme des critères, l'absence de valeur utilisateur dans le fragment SQL, et
l'exécution réelle de cinq tentatives contre PostgreSQL.

## 4. Ce qui a été trouvé en écrivant ce lot

- **Un champ sans objet dans une vue levait une erreur non rattrapée** : 500 sur le tableau
  de bord, pour un critère qui ne concernait même pas cette liste. C'est ce qui a fait
  naître la règle « on applique ce qui s'applique, et on annonce ce qui est écarté ».
- **Un paquet dont l'adresse source et la destination sont identiques** violait une
  contrainte du schéma — qui avait raison — et faisait échouer **tout le lot** en 500. La
  ligne est désormais écartée avant l'insertion : le schéma reste la dernière ligne de
  défense plutôt que la première.
- **Un bouton effacé par le rendu** : le texte du détail d'un paquet était écrit dans la
  cellule, ce qui remplaçait le bouton « Couches » qu'elle contient. Le texte va maintenant
  dans un élément interne.
- **Mon outil de vérification attendait des délais fixes**, et deux attentes impossibles
  (`waitForSelector` attend la visibilité : un élément caché ne peut jamais la satisfaire).
  Il attend désormais des états.


---

# Lot B — Comprendre (première partie : DNS → connexion)

## 1. Ce qui a été construit

`backend/noms.py` : relier une adresse IP au nom que le réseau lui a donné.

    avants : 2001:42d8:379d:e500:e9a1:7431:a059:e96a:49687:443
    après  : api.telegram.org

Sur la capture de démonstration : **26 communications sur 94** portent désormais un nom.

## 2. Pourquoi ces choix

**Le nom vient du réseau observé, jamais d'un annuaire.** Avant de joindre un serveur, une
machine demande « quelle adresse porte ce nom ? » ; la réponse contient le nom **et**
l'adresse. Ces réponses sont déjà dans les paquets conservés — il suffit de les relire à
l'envers. Aucune requête externe n'est émise, aucun annuaire n'est interrogé : le nom
affiché est celui que la machine observée a réellement demandé.

**L'adresse n'est jamais remplacée, seulement accompagnée.** Le nom est une commodité,
l'adresse est le fait. Masquer l'adresse derrière un nom rendrait impossible la
vérification de ce qui a été observé — et un outil d'analyse dont on ne peut pas vérifier
les dires ne sert à rien. L'interface affiche le nom au-dessus, l'adresse dessous.

**Un nom invraisemblable est écarté.** Un nom sans point n'est pas un nom de domaine ; une
chaîne de mille caractères est un enregistrement détourné ou une donnée malformée ; un
caractère de contrôle est une donnée hostile. Ces valeurs viennent du réseau : elles sont
filtrées avant d'être affichées, jamais après.

**Quand une adresse porte plusieurs noms, le plus récent gagne.** Les hébergeurs et les
fermes de serveurs en portent des dizaines sur une même adresse. Le module **trie lui-même**
au lieu de supposer que l'appelant l'a fait — voir ce qui a été trouvé ci-dessous.

**Le cache est court — quinze secondes.** Reconstruire l'index à chaque rafraîchissement du
tableau de bord ferait relire des milliers de paquets pour retrouver les mêmes noms. Trop
long, il retarderait l'apparition d'un nom nouveau.

## 3. Trois questions de défense

**1. D'où viennent vos noms de domaine ? D'un service externe ?**

Non, et c'est le point important. Ils viennent des réponses DNS observées sur le réseau
lui-même : une machine demande « quelle adresse porte github.com ? », la réponse contient
`github.com` et `140.82.121.4`, et c'est cette paire que l'outil réutilise. Aucune requête
n'est émise vers l'extérieur pour nommer quoi que ce soit — pas même une résolution inverse.
C'est ce qui permet à l'outil de fonctionner sur un réseau isolé.

**2. Une adresse peut porter plusieurs noms. Lequel affichez-vous ?**

Le plus récemment observé, et c'est un choix assumé : c'est celui qui a le plus de chances
de correspondre au trafic en cours. L'interface ne prétend pas donner le nom « officiel » de
l'adresse — elle dit « d'après le DNS », et l'adresse reste affichée dessous. Un lecteur qui
veut vérifier regarde l'adresse, qui est le fait vérifiable.

**3. Pourquoi ne pas avoir simplement fait une résolution inverse (PTR) ?**

Parce qu'elle serait une requête émise vers l'extérieur — ce que le projet évite —, qu'elle
échoue la plupart du temps sur les adresses partagées, et qu'elle donnerait un nom
d'hébergeur, pas le nom demandé. La résolution inverse dit « cette adresse appartient à
Amazon » ; le DNS observé dit « cette machine cherchait api.telegram.org ». C'est la seconde
information qui explique ce qui se passe.

## 4. Ce qui a été trouvé en écrivant cette partie

- **La donnée nécessaire n'était pas conservée.** La réduction des détails à l'ingestion ne
  gardait que huit clés, choisies **avant** que cette fonctionnalité existe : `dns_adresse`
  et `dns_reponse_nom` étaient jetés à l'entrée. La fonctionnalité aurait paru « ne pas
  marcher » alors que la donnée n'avait jamais été stockée. C'est ce que la vérification sur
  trafic réel a montré — **0 communication nommée** au premier essai, sur une capture qui
  contenait pourtant des résolutions DNS. La liste des clés a été élargie, et la limite
  portée de huit à dix, en gardant le principe : ce qui vient du réseau ne doit pas pouvoir
  faire grossir la base à volonté.
- **Un ordre non garanti n'est pas un ordre.** L'index annonçait « le plus récent gagne »
  mais se fiait à l'ordre des paquets fourni par l'appelant. Il fonctionnait avec un
  stockage et donnait le mauvais nom avec un autre. Il trie désormais lui-même, et le
  commentaire dit pourquoi.


---

# Lot B — Comprendre (suite et fin)

## 1. Ce qui a été construit

**DNS → connexion** (`backend/noms.py`, voir plus haut) : `api.telegram.org` au lieu d'une
adresse nue.

**Métadonnées TLS** (`agent/parser.py`) : le nom du serveur visé, extrait de l'extension SNI
d'un ClientHello, et la version TLS annoncée. C'est **la seule** information lisible d'une
session chiffrée, et l'outil explique pourquoi le reste ne l'est pas.

**Sessions HTTP en clair** (`agent/parser.py`) : méthode, hôte, chemin, code de réponse. Ni
`Authorization`, ni `Cookie`, ni corps de message — non pas masqués après coup, mais **jamais
lus**.

**Récit d'une conversation** (`backend/recit.py`, `GET /api/v1/flows/recit`) : la chronologie
des événements — ouverture, acceptation, fermeture, rupture, avec leur délai — puis le récit
en français, où **chaque phrase porte son genre**, `fait` ou `lecture`.

    [FAIT]    À 14:16:02, 2001:42d8:...:49688 a engagé une conversation TCP avec 64:ff9b::5bd:a496:443.
    [FAIT]    L'ouverture a été acceptée : la conversation a bien été établie dans les deux sens.
    [FAIT]    6,3 ko ont été échangés : 2,0 ko dans un sens, 4,2 ko dans l'autre.
    [LECTURE] Un RST peut signaler un port fermé, un logiciel qui coupe la connexion, ou un
              intermédiaire réseau qui la refuse. Le paquet seul ne le dit pas.

## 2. Pourquoi ces choix

**Lire le moins possible.** Pour HTTP, la règle n'est pas de masquer les en-têtes sensibles,
mais de **ne pas les extraire**. Ce qu'on ne lit pas ne peut pas fuir, et il n'y a pas de
liste de champs sensibles à tenir à jour — donc pas de champ oublié dans cette liste. Les
tests le vérifient sur un message contenant réellement un jeton : le mot est absent de tout
ce qui est retenu.

**La chronologie ne garde que les événements.** Quarante échanges de données ne racontent
rien de plus que le premier ; les compter, si. Ne retenir que l'ouverture, l'acceptation et
la fin rend le récit lisible sans jamais cacher l'essentiel.

**Chaque phrase dit ce qu'elle est.** `fait` ou `lecture`. C'est la règle n°4 du projet
appliquée à la phrase : un lecteur doit pouvoir dire, à chaque ligne, ce qui a été vu et ce
qui a été pensé. Une phrase comme « c'est le profil d'une consultation » est une lecture, et
elle est présentée comme telle.

**L'ordre des conditions compte.** Un SYN observé interdit d'écrire que le début n'a pas été
vu. La première version testait la certitude avant l'ouverture et pouvait se contredire dans
la même page — c'est exactement ce que la vérification sur trafic réel a montré.

## 3. Trois questions de défense

**1. Vous dites que le HTTPS n'est pas déchiffré. Alors à quoi bon afficher le SNI ?**

Parce que le SNI est en clair **par nécessité de fonctionnement** : avant de chiffrer, le
client doit annoncer le nom du serveur qu'il veut joindre, sans quoi un hébergeur ne saurait
pas quel certificat présenter. Ce nom suffit à répondre à « quel service cette machine
contacte-t-elle ? », qui est la question du projet. Le contenu reste illisible, et l'outil
l'explique plutôt que de le taire. Déchiffrer demanderait un proxy d'interception — une
position d'homme du milieu, que ce projet refuse par principe.

**2. Pourquoi ne pas stocker le corps des échanges HTTP ? C'est du clair, ce serait utile.**

Parce qu'un outil qui stocke le contenu d'un échange en clair finit par stocker un mot de
passe, un jeton ou une donnée personnelle — et il suffit d'une fois. Le projet conserve des
**métadonnées** : qui parle à qui, quand, combien, par quel protocole. C'est ce qui permet de
le déployer sur un réseau d'entreprise sans qu'il devienne lui-même un risque.

**3. Votre récit est-il une analyse automatique ? Peut-on s'y fier ?**

Il ne conclut rien seul. Le récit **relate** des faits mesurés — heures, volumes, drapeaux,
états — et **sépare** explicitement les lectures, qui portent toujours leur critère (« plus de
trois fois plus de données dans un sens ») et leur réserve (« cela ne veut pas dire qu'elle
est encore ouverte »). Aucune phrase n'affirme une cause. Un RST est présenté avec ses causes
possibles, pas avec une conclusion.

## 4. Ce qui a été trouvé en vérifiant sur trafic réel

Cette partie a produit **quatre défauts**, tous invisibles dans les tests, tous visibles sur
des données réelles :

- **`dns_adresse` et `dns_reponse_nom` jetés à l'ingestion** — la réduction des détails ne
  gardait que huit clés, choisies avant que la fonctionnalité existe. Zéro communication
  nommée au premier essai.
- **Les drapeaux TCP sont une chaîne**, `"SYN, ACK"`, pas une liste. Le code les parcourait
  comme une liste de caractères : aucun drapeau reconnu, chronologie vide, et un récit qui
  affirmait « l'ouverture n'a pas été observée » alors qu'un SYN avait été vu. **Une
  affirmation fausse**, le pire défaut possible dans un outil d'analyse.
- **Trois noms de champs inventés** (`premier_vu`, `dernier_vu`, `octets_a` au lieu de
  `debut`, `dernier_paquet`, `octets_a_vers_b`) : le récit ne pouvait ni dater ni peser une
  conversation, et écrivait « à un moment non daté ».
- **`int()` refuse les octets** — Scapy rend certains champs numériques en octets (`b"404"`),
  donc le code de réponse HTTP n'était jamais lu.

**La leçon, et elle vaut méthode : quatre fois de suite, un test qui forgeait lui-même la
structure des données a validé un code qui ne pouvait pas fonctionner sur les vraies. Un test
qui invente la forme des données ne teste que lui-même.** Les tests adoptent désormais la
forme relevée sur une réponse réelle de l'API.

## 5. Ce qui reste imparfait, et qui est écrit ici plutôt que caché

La chronologie peut afficher **deux fois** une acceptation lorsque deux paquets portent le
même horodatage : le dédoublonnage des événements répétés n'est pas encore fiable. C'est
cosmétique — le récit reste juste — mais c'est faux, et c'est noté comme tel.


---

# Lot B — L'affichage

## Ce qui a été ajouté

**Un bouton « Raconter »** sur chaque ligne de communication. Il ouvre un panneau qui montre
la chronologie des événements puis le récit, **chaque phrase portant son genre** : « fait
observé » ou « lecture ». La distinction ne repose pas sur la couleur seule — l'intitulé est
écrit, sinon une partie des lecteurs ne verrait pas la différence.

**« HTTPS vers <nom> »** dans la colonne « Détail » d'un paquet, dès qu'un ClientHello a
livré son SNI. Et « HTTP GET <hôte><chemin> → <code> » pour un échange en clair.

**L'export CSV suit le filtre courant** : on exporte ce que l'on voit.

## Pourquoi ces choix

**Le récit ne se calcule pas à chaque rafraîchissement.** Le tableau de bord se rafraîchit
toutes les trois secondes ; raconter demande de relire les paquets d'une conversation. Le
récit est donc obtenu **à la demande**, au clic — le tableau de bord reste fluide, et le
travail se fait quand quelqu'un le demande.

**La clé de la conversation est posée sur le bouton**, pas gardée dans un tableau à part. Le
tableau est reconstruit à chaque rafraîchissement : un élément du document disparaît, et un
index calculé au moment du clic désignerait la mauvaise ligne si une communication est
apparue entre-temps.

**Les blocs « fait » et « lecture » réemploient les classes déjà employées par les
explications.** Une même idée se présente partout de la même façon, et une correction de
couleur n'a qu'un endroit à changer.

## Deux questions de défense

**1. Pourquoi le récit n'est-il pas calculé d'avance, comme le reste ?**

Parce que le coût n'est pas le même. Compter des paquets par protocole se fait une fois pour
toutes ; raconter une conversation demande de retrouver ses paquets et de les parcourir. Le
faire toutes les trois secondes pour cent lignes serait un gaspillage invisible — et un
tableau de bord qui rame sans qu'on sache pourquoi. À la demande, le travail se fait pour la
seule conversation qu'on regarde.

**2. Le panneau dit « aucun événement observé ». Est-ce une erreur ?**

Non, et c'est une information. Cela veut dire qu'aucun SYN, FIN ou RST n'a été vu dans les
paquets relus : la conversation était déjà en cours au début de la fenêtre analysée. Le
récit l'écrit explicitement plutôt que de laisser croire à une absence de trafic. C'est la
même règle que partout ailleurs : ce qui n'a pas été vu est dit comme non vu, jamais comblé
par une supposition.

## Un défaut trouvé ici aussi

`raconterCommunication` était défini dans la portée du module principal et appelé depuis un
bloc séparé : le clic n'aurait **rien fait, sans la moindre erreur visible**. C'est le même
piège que `formaterOctets` au lot A — le second module ne voit pas la fermeture du premier.
Les deux fonctions sont maintenant exposées explicitement, avec le commentaire qui explique
pourquoi. **Une interface qui ne fait rien en silence est plus difficile à diagnostiquer
qu'une interface qui plante.**


---

# Lot C — Expert Info (première partie)

## 1. Ce qui a été construit

**Le prérequis structurel d'abord.** L'analyseur n'extrayait ni `seq`, ni `ack`, ni la
fenêtre, ni la taille de charge utile — sans quoi aucune analyse de retransmission n'est
possible. Ces quatre valeurs sont désormais lues, et placées **en tête** de la liste des
détails conservés, pour qu'elles survivent à la réduction.

`longueur_transport` contenait `tcp.dataofs`, c'est-à-dire la longueur de l'**en-tête** : la
confondre avec la charge utile aurait faussé tout calcul de volume applicatif.

**`agent/anomalies.py`** — quatre anomalies mesurables, chacune avec ses critères écrits :

    retransmission     même sens, même numéro de séquence, charge utile non nulle
    poignee_incomplete un SYN, et aucun SYN-ACK en réponse
    reset_inattendu    un RST en PREMIER paquet de la conversation
    fenetre_nulle      champ « fenêtre » à zéro

**`GET /api/v1/anomalies`** — l'Expert Info du projet, avec son compte par famille et le
nombre de paquets examinés.

## 2. Pourquoi ces choix

**Une anomalie est un fait, jamais une conclusion.** Une retransmission signale presque
toujours un réseau lent, pas une attaque. Le niveau rendu est donc `observation`, et aucune
anomalie isolée ne produit une alerte — la règle des trois indices convergents reste
entière, et c'est `detection.py` qui en décide.

**Le nombre de paquets examinés accompagne toujours le résultat.** Sans lui, une liste vide
ne distingue pas « rien d'anormal » de « rien à analyser ». C'est le silence trompeur que ce
projet refuse partout ailleurs.

**La charge utile n'est jamais conservée — seulement sa taille.** Un analyseur qui stockerait
le contenu d'un échange finirait par stocker un mot de passe, et il suffirait d'une fois. Une
longueur suffit à repérer une retransmission ou une fenêtre saturée.

**Le faux positif est traqué autant que le vrai.** Un accusé de réception pur reprend
souvent le numéro de séquence du paquet précédent : sans la condition sur la charge utile, la
liste des retransmissions se remplirait de bruit — et une liste qu'on ne peut pas croire ne
sert à rien.

## 3. Trois questions de défense

**1. Une retransmission, est-ce un problème de sécurité ?**

Presque jamais. C'est le plus souvent un paquet perdu sur le chemin, un Wi-Fi instable ou un
récepteur saturé — c'est-à-dire le fonctionnement normal d'un réseau qui se rattrape. La
présenter comme une menace serait une faute : un outil qui crie au loup à chaque
retransmission cesse d'être lu, et cesse donc d'être utile le jour où quelque chose de
sérieux se produit.

**2. Pourquoi une fenêtre à zéro est-elle signalée si c'est normal ?**

Parce que « normal » n'est pas « sans intérêt ». Une fenêtre à zéro explique une pause
inexpliquée : le récepteur demande à l'autre de s'arrêter parce que son tampon est plein.
Sans cette observation, l'utilisateur voit un trou de plusieurs secondes et ne comprend pas.
Signalée comme observation, avec la mention « mécanisme de régulation normal », elle
éclaire au lieu d'inquiéter.

**3. Pourquoi ne pas détecter davantage d'anomalies ?**

Parce qu'une règle qu'on ne peut pas expliquer ne vaut rien ici. Les quatre retenues sont
mesurables avec ce que l'analyseur conserve, et chacune correspond à un phénomène qu'un
débutant peut retrouver dans les paquets et vérifier lui-même. Une détection qu'on ne peut
pas défendre ligne par ligne serait un gadget.

## 4. Ce qui a été trouvé en écrivant cette partie

- **Mon code fusionnait les drapeaux de toute une conversation**, donc un ACK ordinaire
  suffisait à innocenter une demande d'ouverture restée sans réponse. Or un ACK apparaît sur
  presque tous les paquets d'une conversation établie : la détection ne pouvait pas
  fonctionner. **C'est mon propre test qui a exprimé la bonne exigence** — « un ACK seul ne
  prouve pas une réponse » — et le code a été corrigé pour chercher un SYN-ACK, c'est-à-dire
  un paquet portant SYN *et* ACK.
- **Trois fixtures de test employaient des noms de drapeaux abrégés** (`S`, `A`, `R`) là où
  les données réelles portent `SYN`, `ACK`, `RST`. Les tests échouaient, pas le code — mais
  le temps perdu était le même. La forme des données se relève sur une réponse réelle, elle
  ne se devine pas.


---

# Lot C — Statistiques et affichage (fin du lot)

## 1. Ce qui a été construit

**`backend/statistiques.py`** — trois vues calculées sur les paquets :

- la **répartition par protocole**, en comptes et en pourcentages ;
- les **machines les plus actives**, avec émis et reçus **distingués** ;
- le **débit dans le temps**, par intervalles réguliers.

**`GET /api/v1/statistiques`** les sert toutes les trois.

**L'affichage** : une section « Répartitions et débit » et une section « Expert Info », avec
pour chacune les barres, les chiffres écrits et les critères de chaque anomalie.

## 2. Pourquoi ces choix

**Le calcul est dans le backend, pas dans le stockage.** Les mêmes chiffres doivent sortir
du stockage en mémoire et de PostgreSQL. Écrire le calcul deux fois, c'est garantir qu'il
divergera : un pourcentage corrigé d'un côté, oublié de l'autre, et deux tableaux de bord
qui ne disent pas la même chose sans que personne ne sache lequel croire.

**Les pourcentages retombent sur 100.** Le reste de la division est absorbé par la part la
plus grande, jamais réparti au hasard. Un lecteur qui additionne une colonne et trouve 99 ou
101 cesse de croire au tableau — et il a raison. Un test le vérifie sur six répartitions
différentes, y compris celles qui tombent mal.

**Les paquets d'analyse partielle sont comptés à part, jamais classés.** Leur attribuer un
protocole serait inventer ce que le parseur n'a pas su lire. Un chiffre faux est plus
difficile à repérer qu'une ligne manquante.

**Émis et reçus sont distingués dans le classement des machines.** Un classement sur le seul
volume total confondrait un serveur qui répond beaucoup et une machine qui interroge
beaucoup — or c'est précisément la distinction qui intéresse quand on cherche ce qui parle.

**Des barres en CSS, pas une bibliothèque de graphiques.** La même information, le chiffre
écrit à côté (donc lisible par un lecteur d'écran, ce qu'une barre n'est pas), et pas une
dépendance de plus à charger et à maintenir. Le survol d'une barre de débit donne le détail
de l'intervalle.

**Ces deux vues se chargent à part du cycle principal.** Elles demandent de relire trois
mille paquets : les rafraîchir toutes les trois secondes serait un gaspillage invisible, et
c'est exactement ce qui fait qu'un tableau de bord rame sans qu'on sache pourquoi.

## 3. Trois questions de défense

**1. Pourquoi ne pas utiliser Chart.js, comme le suggérait l'énoncé ?**

Parce que trois barres et un histogramme ne justifient pas une bibliothèque de plusieurs
centaines de kilo-octets, une dépendance de plus à mettre à jour et une source d'échec de
plus au chargement. Surtout : une barre dessinée en CSS porte **le chiffre écrit à côté**,
donc elle est lisible par un lecteur d'écran — ce qu'un graphique en toile ne permet pas
sans travail supplémentaire. Si le besoin d'un vrai graphique se présente un jour (courbes,
comparaison de sessions), la décision se réexaminera.

**2. Vos statistiques portent sur quoi exactement ?**

Sur les paquets conservés dans la fenêtre relue, et le total est **toujours** affiché. Une
répartition sans son total est un chiffre qui ne veut rien dire : « 62 % de TCP » ne dit pas
si les 38 % restants sont de l'UDP, de l'ARP, ou des paquets non analysés. Les paquets
d'analyse partielle sont d'ailleurs comptés comme une famille à part, jamais fondus dans un
protocole connu.

**3. Le classement des machines est-il un indicateur de menace ?**

Non, et l'interface ne le présente pas comme tel. Une machine qui émet beaucoup est une
machine qui parle beaucoup — un serveur de mise à jour, un service de sauvegarde, ou un
téléphone qui se synchronise. Le classement sert à **savoir où regarder**, pas à désigner un
coupable. Y voir une menace demanderait d'autres indices, et c'est le rôle des détections.

## 4. Ce qui a été trouvé ici

Mon outil de vérification cherchait le texte « paquet(s) examiné(s) » avec une expression
régulière dont les parenthèses étaient doublement échappées : elle cherchait des barres
obliques littérales. **L'affichage était juste, la vérification était fausse.** Une recherche
de texte simple fait le même travail sans piège — et un contrôle qui échoue pour une mauvaise
raison coûte plus cher qu'il ne rapporte, puisqu'il apprend à ignorer les échecs.

## 5. Ce qui reste imparfait

Le graphique de débit n'affiche pas d'axe des temps : chaque barre porte son décalage en
secondes au survol, mais l'œil ne peut pas situer un pic dans le temps sans survoler. C'est
suffisant pour repérer une accélération, insuffisant pour la dater — et c'est noté comme tel.


---

# Lot C — Port → processus : état réel

## 1. Ce qui a été construit

`agent/processus.py` associe un port local au programme qui le tient, à partir de
`psutil.net_connections()`. L'enrichissement se fait dans `Envoyeur.ajouter()` — le seul
point par lequel **tous** les paquets passent, et le dernier moment où la fiche est fraîche.
L'interface affiche le programme **en tête** de la colonne « Détail ».

**Ce que cette machine autorise, mesuré et non supposé** : sans droits administrateur,
Windows laisse lire les connexions de l'utilisateur courant. Relevé ici : **313 connexions
lues, 202 avec un processus identifié, 111 sans**. Un tiers du trafic ne sera jamais nommé —
ce n'est pas un défaut à corriger, c'est une limite du système. L'interface n'écrit jamais
« inconnu » pour combler le vide.

## 2. Ce qui est PROUVÉ

- **15 tests** couvrent la détermination du côté local, la construction de la table, la
  normalisation des adresses et la dégradation sans `psutil`.
- **Le mécanisme fonctionne**, vérifié directement : sur une connexion locale réelle,
  `Envoyeur.ajouter()` pose `{'processus_local': 'svchost.exe', 'processus_pid': 1848}`.
- **La propriété centrale est testée** : le port 443 est tenu par `chrome.exe` *et* par le
  serveur distant. Le côté local se détermine par l'**adresse**, jamais par le port seul —
  sinon on nommerait le mauvais programme une fois sur deux.

## 3. Ce qui n'allait pas — et la cause réelle

**Sur cinq captures réelles, aucune fiche ne portait de nom de programme.** J'ai écrit ici,
dans la version précédente de ce document, que la cause était probablement la durée de vie
des connexions face à la validité du cache. **C'était faux.**

Deux hypothèses ont été testées, et écartées par la mesure :

- *les adresses locales ne correspondaient pas* — écartée : 327 paquets sur 1000 venaient
  bien de l'adresse de la machine et étaient reconnus comme tels ;
- *les connexions étaient trop brèves* — écartée par une expérience contrôlée : un émetteur
  maintenant une connexion vivante et parlant toutes les 200 ms a produit huit paquets dont
  aucun ne portait de nom, alors que la connexion était ouverte depuis le début.

**La cause réelle : un backend périmé servait le port 8000.** Deux processus avaient survécu
aux redémarrages et répondaient avec l'ancien code, dont la liste de détails conservés
n'incluait pas `processus_local`. La clé était donc écrite par l'agent, reçue par l'API,
puis **jetée à l'ingestion** — sans erreur, sans trace, et de façon parfaitement silencieuse.

Ce qui a permis de le prouver : ingérer un paquet contenant la clé, puis relire ce que la
base en avait gardé. Réponse : `['ack', 'charge_utile', 'fenetre', 'seq']` — quatre clés, pas
la sixième attendue. **Le test qui tranche n'est pas celui qu'on croit** : il ne fallait pas
observer le réseau, mais vérifier ce que la base retient de ce qu'on lui donne.

**Après redémarrage propre du backend : 953 paquets sur 1000 portent un nom de programme**
(95 %), dans les deux sens de la conversation.

## 4. Deux défauts trouvés en écrivant cette partie

- **La comparaison d'adresses se faisait sur des chaînes.** Une même IPv6 s'écrit de
  plusieurs façons ; `fe80::1` et `fe80:0:0:0:0:0:0:1` désignent la même interface. La table
  était construite, les paquets passaient, **aucune correspondance n'avait lieu — sans le
  moindre message d'erreur**. Le trafic de cette machine étant très majoritairement en IPv6,
  le module était muet presque partout. Les deux côtés sont désormais normalisés, et un test
  le verrouille.
- **Mon propre test injectait une table vide**, que le cache considérait comme absente et
  reconstruisait — en écrasant celle du test. Un dictionnaire vide est faux en Python : le
  test ne testait rien.

## 5. Trois questions de défense

**1. Comment saviez-vous que ça ne marchait pas ?**

Parce que je l'ai mesuré au lieu de le supposer : sur cinq captures réelles, comptage des
fiches portant un nom de programme — zéro. Deux explications plausibles ont été écrites,
puis **testées et écartées l'une après l'autre**. La vraie cause était ailleurs, et elle
n'avait rien à voir avec le réseau : un processus périmé.

**La leçon vaut plus que le correctif** : une fonctionnalité qui ne produit rien sans erreur
n'a pas forcément son défaut là où on le cherche. Ici, tout le raisonnement portait sur les
connexions et le cache, alors que la donnée était correcte jusqu'à la porte de la base — et
jetée à l'intérieur.

**2. Lire la table des connexions du système, n'est-ce pas intrusif ?**

C'est une lecture locale, faite par un programme qui tourne déjà sur la machine, avec les
droits de l'utilisateur qui l'a lancé. Aucune donnée ne quitte le poste, et le système
refuse de lui-même ce que l'utilisateur n'a pas le droit de voir — un tiers des connexions
ici. C'est la différence entre observer ce qu'on a le droit de voir et forcer une porte.

**3. Pourquoi ne pas interroger le système à chaque paquet, pour ne rien manquer ?**

Parce que ce serait trois mille appels système par capture, pour retrouver la même table
dans l'immense majorité des cas — et que le fil de capture doit rester assez rapide pour ne
pas perdre de paquets. Le compromis retenu (un instantané toutes les cinq secondes) est
peut-être trop lent : c'est précisément ce qu'il reste à mesurer.

## 6. Ce qu'il reste à faire pour conclure

Mesurer le délai réel entre l'ouverture d'une connexion et sa disparition de la table, puis
choisir : raccourcir la validité du cache, ou enrichir à l'ouverture d'une conversation
plutôt qu'à chaque paquet — les flux étant suivis par l'analyseur, une connexion longue y
est connue au moment où elle s'établit.


---

# Lot C — Profils d'analyse (fin du plan d'amélioration)

## 1. Ce qui a été construit

**`backend/profils.py`** — un profil est un **nom**, un **filtre** et une **phrase qui dit à
quoi il sert**. Cinq sont proposés d'emblée : *Tout*, *Web chiffré*, *Résolutions DNS*,
*Trafic sortant vers l'extérieur*, *Conversations terminées*.

**L'API** : `GET /api/v1/profils` (lecture publique, comme tout le reste), `POST` et `DELETE`
pour écrire — **jeton exigé**, comme pour l'ingestion.

**L'interface** : un sélecteur dans la barre de filtre. Choisir un profil **remplit le champ
de filtre** au lieu de filtrer dans son coin.

## 2. Pourquoi ces choix

**Un profil ne peut pas être enregistré avec un filtre invalide.** La validation se fait à
l'enregistrement, par le **même parseur** que celui qui appliquera le filtre — le parseur du
lot A. S'il existe, son filtre est applicable. C'est la différence entre refuser une erreur
quand celui qui la commet est encore devant l'écran, et la découvrir en pleine analyse.

**Un filtre s'applique à plusieurs listes, et chaque critère est appliqué là où il a un
sens.** `port:443` concerne un paquet, `etat:fermée` une communication. La validation accepte
donc un filtre qui s'applique **quelque part**, pas partout.

**Choisir un profil remplit le champ, il ne filtre pas en secret.** Ce qui s'applique reste
visible et modifiable. Un filtre appliqué derrière l'écran serait impossible à vérifier — et
un résultat qu'on ne peut pas vérifier ne vaut rien dans un outil d'analyse.

**Les profils ne sont pas versionnés.** Ils vivent dans `profils.json`, à côté du projet, et le
fichier est dans `.gitignore` : c'est la configuration d'un poste, pas une propriété du
logiciel. Aucun secret n'y entre — un profil décrit une façon de regarder, rien d'autre, et un
test le vérifie.

**Un fichier abîmé ne met pas l'application en panne.** Illisible, il fait retomber sur les
profils proposés ; une entrée fautive est écartée sans perdre les autres.

## 3. Trois questions de défense

**1. Pourquoi ne pas mettre les profils dans la base de données ?**

Parce qu'ils ne décrivent pas la capture, mais la façon de la regarder — et qu'ils
appartiennent au poste, pas aux données. Les mettre en base les ferait dépendre d'une
connexion, d'un schéma et d'une migration, pour une poignée de préférences. Si le besoin de
les partager entre plusieurs postes apparaît, la décision se réexaminera : c'est un fichier,
pas une architecture.

**2. Un profil enregistré peut-il cesser de fonctionner ?**

Non, et c'est tout l'intérêt de valider à l'enregistrement. Le filtre est vérifié par le
parseur qui l'appliquera. La seule évolution possible serait qu'un champ disparaisse du
parseur : la validation refuserait alors les nouveaux profils, et les anciens seraient écartés
à la lecture sans faire échouer le reste.

**3. Pourquoi une limite de profils ?**

Parce qu'une liste qu'on ne lit plus ne sert plus. La limite porte sur la liste entière,
profils proposés compris, et le refus est **explicite** : « Trop de profils : 40 au maximum.
Supprimez-en un avant d'en ajouter. » Un refus muet laisserait croire à une panne.

## 4. Deux défauts trouvés — dans mes propres données

- **Un profil proposé avait un filtre invalide** : `etat:en cours`, sans guillemets, alors que
  la syntaxe du lot A exige `etat:"en cours"` — la valeur contient une espace. Un profil livré
  qui ne peut pas s'enregistrer serait une promesse en l'air.
- **Ma validation était plus stricte que l'application.** Elle ne regardait que les paquets et
  refusait donc « Conversations terminées » (`etat:fermée`), un profil parfaitement légitime.
  Une validation plus stricte que ce qu'elle valide interdit des choses qui marchent : c'est un
  défaut, pas de la prudence.


---

# Présentation — trois zones nommées, comme dans les outils de référence

## Ce qui a changé

La vue des paquets est désormais organisée en **trois zones qui se lisent ensemble**, et qui
portent les noms attendus :

- **Liste des paquets** — le tableau (heure, protocole, source, destination, détail, taille) ;
- **Détail du paquet sélectionné** — l'arbre des couches, chacune avec sa phrase de rôle ;
- **Contenu du paquet — octets des en-têtes** — les octets, avec `??` là où l'outil n'extrait
  rien.

Le volet du détail n'est plus une fenêtre qui s'ouvre : il est **visible en permanence** et se
remplit. Quand rien n'est sélectionné, il affiche un message d'attente qui dit quoi faire.

## Pourquoi ce changement

Le contenu était le même, mais il fallait **ouvrir une fenêtre** pour le voir, puis la fermer
pour revenir à la liste — obligeant à retenir ce qu'on venait de quitter. Une analyse se fait
en comparant ce qu'on lit à ce qu'on voit : les trois zones doivent être à l'écran ensemble.

## Un défaut trouvé en vérifiant

Le titre du volet était **écrasé à chaque sélection** par la description du paquet
(`Paquet ARP — 192.168.1.116 → 192.168.1.1`). L'étiquette « Détail du paquet sélectionné »
disparaissait donc dès le premier clic — et une zone sans nom ne se reconnaît plus d'un coup
d'œil, ce qui est exactement ce qu'on cherchait ici. Le titre est maintenant **fixe** : il
nomme la zone ; le paquet est décrit sur la ligne suivante.

C'est un contrôle automatique qui l'a montré, en comparant les titres réellement affichés aux
noms attendus — pas une relecture à l'œil.

## Deux questions de défense

**1. Pourquoi un volet permanent plutôt qu'une fenêtre ?**

Parce qu'analyser consiste à confronter deux choses : la ligne dans la liste et le détail du
paquet. Si les deux ne sont jamais à l'écran ensemble, chaque comparaison demande deux
actions — et l'attention se perd entre les deux. Les trois zones empilées sont précisément ce
qui rend cette confrontation immédiate.

**2. Pourquoi garder l'étiquette fixe au-dessus du détail ?**

Parce qu'une zone doit dire ce qu'elle est, pas ce qu'elle contient. Le titre « Détail du
paquet sélectionné » indique la nature du contenu **avant** qu'on ait cliqué : un lecteur qui
découvre l'écran sait à quoi sert le volet vide. Un titre qui décrit le contenu ne renseigne
que ceux qui savent déjà.


---

# Vues nommées — la page suit enfin la structure du sujet

## Ce qui a changé

La page n'est plus une suite de neuf blocs : elle porte **cinq vues nommées**, celles du
sujet.

| Vue | Ce qu'elle rassemble |
|---|---|
| **Traffic** | les chiffres, les principales sources, le débit, les statistiques, l'historique |
| **Connections** | les communications observées, le récit d'une conversation |
| **Protocols** | les protocoles, leur rôle, la vue par couche |
| **Alerts** | les détections, l'Expert Info et ses critères |
| **Paquets** | la liste des paquets et le détail du paquet sélectionné |

**La barre de capture reste visible dans toutes les vues.** C'est le point de départ du sujet :
on ne peut pas la cacher parce qu'on a changé d'onglet.

## Pourquoi ces choix

**La vue choisie est dans l'adresse.** Elle peut donc être mise en favori, partagée, et un
rafraîchissement ramène où l'on était. Sans cela, un visiteur qui recharge la page perd le fil
— et pendant une démonstration, c'est exactement le moment où l'on ne veut pas se perdre.

**La vue courante se reconnaît par un trait de trois pixels *et* par son contraste.** Pas par
la seule couleur : un trait reste visible en niveaux de gris, une différence de teinte non.

**Au clavier, les flèches passent d'une vue à l'autre**, comme dans un groupe d'onglets. Sans
cela, il faut tabuler sur chaque onglet pour en changer — et un jury qui navigue au clavier
voit immédiatement la différence.

**Une vue inconnue dans l'adresse retombe sur la première.** Un lien mal recopié ne doit pas
ressembler à une panne.

## Ce qui n'est pas encore fait

**La vue détaillée unifiée du §9** — *Technical information + Analysis + Human explanation +
Risk / status* **au même endroit**. Les quatre blocs existent, mais ils restent répartis entre
la table des communications, les explications et le récit. C'est la prochaine étape, et c'est
celle qui manque pour que la démonstration se déroule sans changer d'écran.

**L'affichage de l'enrichissement** (§8, étape 7 de la démonstration) : l'appel à l'API
externe existe et fonctionne, mais son résultat n'est montré nulle part.

## Deux questions de défense

**1. Pourquoi des onglets plutôt qu'une seule page qui défile ?**

Parce que le sujet nomme lui-même cette structure, et parce qu'une page unique de neuf blocs
ne dit pas où commencer. Des onglets imposent un premier choix, et un premier choix est
exactement ce qui manquait. Le revers — on ne voit plus tout d'un coup d'œil — est compensé par
l'adresse : chaque vue a la sienne, et se partage.

**2. Pourquoi ne pas avoir caché la barre de capture dans la vue Traffic ?**

Parce qu'elle n'est pas une information sur le trafic : c'est le contrôle qui **produit** le
trafic. La ranger dans une vue ferait qu'on ne pourrait plus l'arrêter depuis les autres —
c'est-à-dire au moment précis où l'on regarde autre chose.


---

# Vue détaillée : les blocs nommés, et le contexte externe

## Ce qui a été ajouté

**Les blocs du §9 sont maintenant intitulés** dans le panneau de détail : *Informations
techniques* au-dessus des chiffres mesurés, *Analyse et explication* au-dessus des
explications. Les blocs *Faits observés* et *Interprétation* portaient déjà leur nom — c'est le
reste qui ne le portait pas, et un lecteur qui découvre l'écran ne sait pas ce qu'il regarde.

**Le contexte externe** (§8, étape 7 de la démonstration) : le panneau interroge
`/api/v1/enrichment` pour l'adresse publique de la communication et affiche ce que le service
renvoie — pays, organisation, réseau, réputation, signalements, source.

## Pourquoi ces choix

**Une seule adresse est enrichie : celle qui n'appartient pas au réseau local.** Envoyer une
adresse privée à un service externe ne renseignerait personne et révélerait la structure du
réseau observé. Le module d'enrichissement la refuserait de toute façon — mais on ne la demande
même pas.

**L'absence de résultat est annoncée telle quelle.** « Non disponible » n'est pas la même chose
que « rien à signaler » : confondre les deux ferait croire qu'une adresse est propre alors que
le service n'a simplement pas répondu. L'attente est visible (« interrogation… »), et l'échec
est écrit avec son motif.

**L'ajout est additif.** Rien de l'existant n'a été réorganisé : les intitulés sont posés
au-dessus de ce qui était déjà là. Une refonte du panneau aurait fait courir le risque de
casser une vue qui fonctionne, pour un gain de présentation.

## Ce qui reste imparfait — écrit ici plutôt que sous-entendu

Les quatre blocs du §9 sont **nommés**, mais pas encore **séparés en quatre panneaux** :
l'état de la communication et sa certitude restent sur la ligne des informations techniques au
lieu de former un bloc *Risque / état* distinct. C'est suffisant pour une lecture, insuffisant
pour une démonstration qui veut montrer les quatre blocs l'un après l'autre.

## Trois questions de défense

**1. Pourquoi enrichir une seule adresse et pas les deux ?**

Parce que l'autre est celle du réseau local, et qu'un service externe ne connaît pas votre
réseau. Lui envoyer `192.168.1.116` reviendrait à lui transmettre la structure interne du
réseau observé pour ne rien apprendre en retour.

**2. Que se passe-t-il si l'API externe est absente ou en panne ?**

Le panneau écrit « non disponible » avec le motif, et la communication reste entièrement
lisible : les informations techniques, l'explication et les faits observés ne dépendent pas du
service externe. L'enrichissement **ajoute**, il ne conditionne rien — c'est ce qui permet à
l'outil de fonctionner sur un réseau isolé.

**3. Pourquoi ne pas avoir fusionné les explications en un seul bloc ?**

Parce qu'une communication peut porter **plusieurs** explications, chacune avec son niveau de
confiance et sa source (règle écrite ou reformulation par IA). Les fondre en un texte unique
ferait perdre cette distinction — or c'est précisément ce que le §4 demande de préserver :
savoir ce qui est observé et ce qui est interprété.


---

# Message d'accueil et guide d'utilisation

## Ce qui a été ajouté

Une **boîte de dialogue d'accueil** s'affiche à la première visite : ce que fait l'outil, puis
**six étapes** pour s'en servir — choisir l'interface, démarrer, comprendre Pause et Arrêter,
parcourir les vues, demander une explication, filtrer l'affichage. Deux boutons :
*Commencer l'analyse* et *Ne plus afficher au démarrage*.

Un bouton **Guide** dans l'en-tête la rouvre à tout moment.

## Pourquoi ces choix

**Le guide reste accessible.** Un guide qu'on ne peut voir qu'une fois ne sert qu'une fois —
et pendant une démonstration, on veut pouvoir le remontrer sans effacer quoi que ce soit.

**Il est caché par défaut dans le HTML** et révélé par le JavaScript. Si le script échoue, la
page reste utilisable : un voile plein écran qui ne se referme pas serait pire que pas de guide
du tout.

**Trois précautions d'accessibilité**, parce qu'une fenêtre modale mal faite enferme celui qui
navigue au clavier : le focus **entre** dans la boîte à l'ouverture, **revient** d'où il venait
à la fermeture, et Échap ferme. Le fond ne défile pas non plus derrière — sinon on croit que le
guide *est* la page.

**Le stockage du choix ne bloque pas.** En navigation privée, `localStorage` peut être refusé :
le guide s'affichera de nouveau, et rien d'autre ne casse.

**La boîte défile en interne**, elle ne dépasse jamais la fenêtre : sur un téléphone, un guide
qu'on ne peut pas lire en entier ne sert à rien.

## Ce que le guide dit aussi, et qui compte

Le dernier paragraphe énonce les **limites** : l'outil n'obéit qu'aux ordres venus de cette
machine, il ne déchiffre aucune session, il ne conserve aucun contenu — seulement des
métadonnées — et ce qu'il n'a pas su extraire est écrit « non extrait » plutôt que comblé par
une valeur inventée.

Un guide qui ne présenterait que les capacités laisserait découvrir les limites au pire moment,
devant quelqu'un qui pose la question.

## Deux questions de défense

**1. Pourquoi une fenêtre plutôt qu'un encart en haut de page ?**

Parce qu'un encart en haut de page est sauté : l'œil va au tableau, qui est plus bas et plus
intéressant. Une fenêtre impose un premier choix — et un premier choix est exactement ce qui
manquait à cette interface, qui présentait neuf blocs sans dire par où commencer.

**2. Pourquoi proposer « Ne plus afficher » ?**

Parce que quelqu'un qui ouvre l'outil tous les jours n'a pas besoin du guide tous les jours, et
qu'une fenêtre qu'on ferme mécaniquement cesse d'être lue — y compris le jour où elle dirait
quelque chose d'important. Le choix est mémorisé, et le bouton *Guide* reste là.

# Intelligent Network Packet Analyzer

> **État : phase 2 sur 5.** Sont construits et vérifiés à ce jour : la capture réelle,
> l'analyse des paquets, le regroupement en communications avec déduction d'état, le
> schéma de base de données, la transmission et l'affichage en direct.
> Les explications, la détection, l'enrichissement et le branchement sur Supabase
> arrivent dans les phases suivantes — le README est mis à jour à chaque phase, et la
> section « Limites » dit exactement ce qui n'existe pas encore.

Capturer le trafic réseau, le structurer, le comprendre, et l'expliquer à quelqu'un qui
n'est pas spécialiste.

---

## Présentation

Un serveur en ligne ne peut pas voir le trafic d'un réseau local : les paquets destinés à
une machine de ce réseau ne quittent jamais ce réseau. L'outil est donc coupé en deux.

- Un **agent local** (Python + Scapy) capture les paquets, les analyse, et envoie des
  **métadonnées** — jamais de contenu — à un backend, sur une connexion chiffrée,
  authentifiée par un jeton.
- Un **backend en ligne** (FastAPI) reçoit ces fiches, les conserve et les présente dans
  un tableau de bord public.

Un **mode replay** (import d'un fichier `.pcap`) permettra de rejouer une capture pour des
tests reproductibles. Il arrive après la phase 2, quand le format d'entrée sera figé.

## Aperçu

![Tableau de bord — vue Traffic et Connections](docs/capture-phase2.png)

*Capture réelle : trafic Wi-Fi, IPv4 et IPv6 mêlés. La section **Connections** regroupe
les paquets en conversations ; les pastilles en pointillés signalent les états déduits
d'une observation incomplète.*

## Fonctionnement

```
   ┌──────────────────── VOTRE RÉSEAU ────────────────────┐
   │                                                      │
   │   [box] ──── Wi-Fi ────┬──── [téléphone]             │
   │                        │                             │
   │                   [votre poste]                      │
   │                        │                             │
   │                   ┌────▼─────────────────┐           │
   │                   │  AGENT LOCAL         │           │
   │                   │  capture  (Scapy)    │           │
   │                   │  analyse  (parser)   │           │
   │                   │  envoi    (file)     │           │
   │                   └────┬─────────────────┘           │
   └────────────────────────┼─────────────────────────────┘
                            │  HTTPS + jeton d'agent
                            │  (métadonnées uniquement)
   ┌────────────────────────▼─────────────────────────────┐
   │                    EN LIGNE                          │
   │   BACKEND FastAPI                                    │
   │     /api/v1/ingest   ← écriture protégée             │
   │     /api/v1/packets  → lecture publique              │
   │     tableau de bord (Jinja2 + JavaScript)            │
   └──────────────────────────────────────────────────────┘
```

## Architecture du dépôt

```
network-analyzer/
  agent/                # tourne sur votre machine
    capture.py          #   lister/choisir une interface, démarrer/arrêter, droits
    parser.py           #   paquet Scapy → fiche structurée, jamais d'exception
    flows.py            #   regroupement en communications, état TCP, expiration
    sender.py           #   file d'attente bornée, regroupement par lots, réessai
    main.py             #   ligne de commande, assemblage, compteurs
  backend/              # tourne en ligne
    main.py             #   application, pages, traitement des erreurs
    api/
      ingestion.py      #   POST /ingest  (jeton obligatoire)
      paquets.py        #   GET  /packets, /stats, /sessions, /health
    config.py           #   lecture des réglages et des secrets
    models.py           #   validation Pydantic : le contrat avec l'agent
    storage.py          #   conservation (mémoire en phase 1, Supabase en phase 5)
    securite.py         #   jeton d'agent, limitation de débit
    dependances.py      #   ce que les routes reçoivent (remplaçable en test)
  web/
    templates/          #   page du tableau de bord, page d'erreur
    static/             #   feuille de style, script
  sql/
    schema.sql          #   schéma Supabase commenté (6 tables, contraintes, RLS, purge)
    verifier-schema.sql #   autotest du schéma : 17 contrôles de comportement
  tests/                #   pytest : paquets forgés, communications, API, file d'attente
  docs/
    DEFENSE.md          #   dossier de soutenance
    SCENARIOS-TEST.md   #   dix scénarios manuels et leur résultat attendu
  requirements.txt
  .env.example
```

## Technologies, et pourquoi

| Bibliothèque | Rôle | Pourquoi elle, et ce qu'elle coûte |
|---|---|---|
| **Scapy** | capture et décodage | décode Ethernet, IP, TCP, UDP, DNS, ARP, ICMP, IPv6. L'écrire soi-même serait plusieurs milliers de lignes et autant d'erreurs. **Coût :** lent — inadapté au-delà de quelques centaines de Mbit/s. |
| **FastAPI** | serveur HTTP | la validation vient des types, et la documentation OpenAPI est produite automatiquement : l'API est démontrable sans effort. **Coût :** plus de notions à connaître que Flask. |
| **Uvicorn** | serveur d'exécution | standard, éprouvé, asynchrone. |
| **Pydantic** | validation | refuse à l'entrée une adresse IP impossible ou un port hors bornes, en nommant le champ fautif. **Coût :** une étape de plus à écrire, payée au premier incident. |
| **httpx** | appels sortants | un délai maximal en une ligne : sans lui, un backend injoignable bloque l'agent. |
| **Jinja2** | gabarits HTML | fourni avec FastAPI, aucune compilation. |
| **python-dotenv** | secrets | aucun secret dans le code ; le fichier `.env` n'est jamais versionné. |
| **pytest** | tests | 65 tests, exécutés en dix secondes. |
| **Npcap** | pilote Windows | *externe, non Python.* Scapy en a besoin sous Windows ; c'est lui qui parle à la carte réseau. |

Aucune bibliothèque compilée n'est requise côté Python. Aucune n'impose de compte en ligne
pour la phase 1.

## API

| Méthode | Adresse | Droit | Rôle |
|---|---|---|---|
| `POST` | `/api/v1/ingest` | **jeton d'agent** | recevoir un lot de paquets |
| `GET` | `/api/v1/packets` | public | derniers paquets, filtrables (`limite`, `protocole`, `session`, `recherche`) |
| `GET` | `/api/v1/flows` | public | communications regroupées, filtrables (`etat`, `protocole`, `recherche`) |
| `GET` | `/api/v1/stats` | public | compteurs, répartitions, classements |
| `GET` | `/api/v1/sessions` | public | sessions de capture reçues |
| `GET` | `/api/v1/health` | public | état du service |

Documentation interactive produite par FastAPI : `http://127.0.0.1:8000/docs`

**Pourquoi le jeton est dans un en-tête et non dans l'adresse :** une adresse est
journalisée par tous les intermédiaires (proxy, hébergeur, journaux du navigateur). Un
en-tête ne l'est pas.

**Pourquoi l'écriture est protégée et la lecture ouverte :** le tableau de bord est public
par décision du projet. Ce qui doit être protégé, c'est l'écriture — sans jeton, n'importe
qui pourrait remplir la base de paquets inventés, et le tableau de bord deviendrait un
écran de fiction.

## Base de données

Le schéma complet est dans [`sql/schema.sql`](sql/schema.sql) — six tables commentées,
une par question à laquelle elles répondent :

| Table | La question à laquelle elle répond |
|---|---|
| `capture_sessions` | quand et où a-t-on observé ? |
| `flows` | qui a parlé à qui, combien, et comment cela s'est-il terminé ? |
| `packets` | que contenait cette communication ? (plafonné, métadonnées seules) |
| `alerts` | qu'est-ce qui mérite un regard ? (observation / hypothèse / alerte) |
| `ip_enrichments` | que sait-on déjà de cette adresse ? (cache des API externes) |
| `explanations` | qu'est-ce que cela veut dire ? (faits observés, interprétation, confiance) |

**Trois choix structurants, défendus dans `docs/DEFENSE.md` :** une adresse IP privée ne
peut pas entrer dans le cache d'enrichissement (une contrainte SQL l'interdit) ; une même
communication ne peut pas exister en double (clé unique, ce qui rend l'envoi répété sans
danger) ; et la sécurité au niveau des lignes est active **sans aucune politique**, ce qui
signifie que seule la clé de service du backend peut lire — le navigateur ne reçoit jamais
de clé Supabase.

Le schéma s'éprouve lui-même :

```bat
psql -v ON_ERROR_STOP=1 -d analyzer_test -f sql/verifier-schema.sql
```

**Dix-sept contrôles de comportement** : une adresse privée est refusée, une clé de
communication en double aussi, un port hors bornes aussi, un niveau d'alerte inventé
aussi, la cascade emporte bien communications et paquets, et la purge supprime au-delà de
trente jours en conservant le reste.

**En phase 2, la conservation reste en mémoire** : le schéma est écrit et éprouvé, mais le
backend n'y écrit pas encore. Le stockage est isolé derrière une classe
(`backend/storage.py`) dont les routes ne connaissent que les méthodes : le branchement
sur Supabase, en phase 5, ne touchera aucune route.

## Installation

**Prérequis :** Python 3.11 ou plus, et le pilote **Npcap** sous Windows
(https://npcap.com/#download — pendant l'installation, décocher « Restrict Npcap driver's
access to Administrators only » si l'on souhaite capturer sans élever les droits).

```bat
git clone <adresse-du-depot>
cd network-analyzer

python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt

copy .env.example .env
```

Renseigner ensuite `ANALYZER_AGENT_TOKEN` dans `.env`, en engendrant une valeur :

```bat
.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
```

Sans jeton renseigné, le backend en engendre un au démarrage et l'affiche dans la console —
pratique pour un essai, à éviter en production puisque le jeton changerait à chaque
redémarrage.

## Utilisation

**1. Le backend**, dans un premier terminal :

```bat
.venv\Scripts\python.exe -m backend.main
```

Le tableau de bord est sur `http://127.0.0.1:8000`.

**2. Quelle interface capturer ?**

```bat
.venv\Scripts\python.exe agent\main.py --interfaces
```

**3. Vérifier la capture, sans rien envoyer :**

```bat
.venv\Scripts\python.exe agent\main.py --interface "Wi-Fi" --a-blanc
```

**4. Capturer et transmettre :**

```bat
.venv\Scripts\python.exe agent\main.py --interface "Wi-Fi" ^
    --backend http://127.0.0.1:8000 --jeton <JETON>
```

Options utiles : `--duree 30` (arrêt automatique), `--filtre "tcp or udp"` (filtre BPF),
`-v` (journal détaillé).

> **Autorisation.** Ne capturez que sur un réseau que vous administrez, ou pour lequel
> vous disposez d'une autorisation écrite. Capturer le trafic d'un réseau qui ne vous
> appartient pas est illégal.

## Tests

```bat
.venv\Scripts\python.exe -m pytest tests/ -q
```

**103 tests**, dont :

- **parseur** — poignée de main TCP complète, SYN sans réponse, RST, DNS (question et
  réponse), mDNS sans section question, ICMP, ARP, UDP, IPv6, paquet tronqué, protocole
  inconnu, charge utile binaire, scan de ports forgé ;
- **modèles** — adresse impossible, port hors bornes, TTL hors bornes, champ inconnu,
  texte non borné, et un **test de contrat** vérifiant que ce que l'agent produit est
  accepté par le backend ;
- **API** — écriture sans jeton, avec un faux jeton, avec le bon ; lot vide ; paquet
  invalide ; filtres et recherche ; limitation de débit ;
- **file d'attente** — regroupement par lots, débordement borné, backend injoignable,
  réponse d'erreur non prise pour un succès ;
- **communications** — clé identique dans les deux sens, compteurs par sens, ouverture
  complète puis état « établie », SYN sans réponse, RST, un seul FIN, conversation vue en
  cours de route (état incertain), expiration TCP et UDP, délais réglables ;
- **API des communications** — refonte par clé au lieu de la duplication, filtres par état
  et par protocole, refus d'un total incohérent.

Dix scénarios manuels, avec leur résultat attendu, sont décrits dans
[`docs/SCENARIOS-TEST.md`](docs/SCENARIOS-TEST.md).

## Limites actuelles

Rédigées honnêtement, comme demandé. **Aucune de ces limites n'est cachée par le code :
ce qui n'est pas fait n'est pas simulé.**

- **Pas d'explication en langage humain** — « TCP 443 » est affiché, pas expliqué, et
  l'état d'une communication est décrit en une phrase, pas encore accompagné d'une
  explication structurée (titre, faits observés, interprétation, confiance). *Phase 3.*
- **Pas de détection** — un scan de ports est visible dans les données, mais rien ne le
  signale. *Phase 4.*
- **Pas d'enrichissement** — aucune adresse n'est rattachée à un pays ou à une
  organisation. *Phase 4.*
- **Pas de persistance** — le schéma est écrit et éprouvé, mais le backend n'y écrit pas
  encore : tout est perdu au redémarrage, et les tampons sont bornés (2 000 paquets,
  2 000 communications). *Phase 5.*
- **Les communications ICMP et ARP sont regroupées par adresses seulement.** Ces protocoles
  n'ont pas de port : deux échanges ICMP entre les mêmes machines comptent donc comme une
  seule communication, même s'il s'agit d'un ping et d'un message d'erreur distincts.
  C'est une limite du regroupement par 5-uplet, imposé par l'énoncé.
- **Une communication n'est décrite que par ce qui a été capturé.** Si l'agent démarre au
  milieu d'une conversation, celle-ci est marquée incertaine — c'est honnête, mais cela
  signifie qu'un rapport sur une courte capture contiendra beaucoup d'états incertains.
- **Pas de déploiement** — tout tourne en local. *Phase 5.*
- **Pas de mode replay** — le fichier `.pcap` n'est pas encore importable.
- **Performance** — Scapy décode en Python pur. Sur un réseau domestique c'est sans
  conséquence ; sur un lien chargé, des paquets sont perdus par le pilote, sans que
  l'analyseur puisse le savoir.
- **Un avertissement de bibliothèque** — FastAPI signale que `httpx` avec son client de
  test est déprécié au profit de `httpx2`. Cela ne concerne que les tests, aucune
  bibliothèque n'étant installée pour la production.
- **Une limite de fond, qui vaut d'être dite** : l'analyseur ne voit que ce que sa carte
  réseau reçoit. En mode normal, cela exclut le trafic des autres machines. Ici, la carte
  reçoit aussi des trames d'autres appareils du Wi-Fi — ce qui est utile pour la
  démonstration, mais ne constitue pas une surveillance fiable et complète du réseau.

## Licence et avertissement

Exercice de formation. Les données affichées par le tableau de bord sont réelles :
adresses IP, ports et noms de domaines d'un réseau local. Aucun contenu de message n'est
conservé.

Ne capturez que sur un réseau que vous administrez, ou pour lequel vous disposez d'une
autorisation écrite.

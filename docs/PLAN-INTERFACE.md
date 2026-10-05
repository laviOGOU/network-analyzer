# Intelligent Network Packet Analyzer — Plan de reprise de l'interface

**Document de travail — à valider avant toute modification du code**

---

## 1. Le constat

L'interface actuelle a été construite **par accumulation** : chaque section a été ajoutée et
justifiée séparément, aucune n'a été jugée par rapport à l'ensemble. La page présente donc
**ce que l'outil a calculé**, dans l'ordre où il a été construit — et non dans l'ordre où
l'exercice demande de s'en servir.

**Le sujet nomme lui-même la structure attendue.** Au §9, il écrit :

> Vue générale — NETWORK ANALYZER | Traffic | Connections | Protocols | Alerts

puis une **vue des paquets**, puis une **vue détaillée** contenant *Technical information +
Analysis + Human explanation + Risk / status*.

La page actuelle affiche ces quatre entrées, **plus** Packets, Sessions, Répartitions et débit,
Expert Info et Profils — soit **neuf blocs au même niveau**. Rien n'indique par où commencer,
ni ce qui est principal.

**Et le §20 donne l'ordre de la démonstration**, qui est la véritable colonne vertébrale du
projet :

| # | Étape de la démonstration | Réalisable aujourd'hui |
|---|---|---|
| 1 | le démarrage de l'application | ✅ |
| 2 | une capture réelle | ❌ **pas depuis l'interface** |
| 3 | les paquets observés | ✅ |
| 4 | l'analyse d'une communication | ⚠️ éclatée en trois endroits |
| 5 | l'explication produite | ✅ |
| 6 | une détection ou un événement intéressant | ✅ |
| 7 | l'enrichissement via l'API | ❌ **codé, jamais affiché** |
| 8 | les données enregistrées dans Supabase | ❌ |
| 9 | le repository GitHub | ❌ rien n'est poussé |
| 10 | l'application accessible en ligne | ❌ |

**Trois des dix points de la démonstration ne sont pas réalisables** (8, 9, 10), et deux
autres le sont mal (2, 4, 7). C'est ce que le ressenti « on ne comprend rien » traduit
exactement : la page ne raconte pas la même histoire que le sujet.

---

## 2. Ce qui est acquis et ne sera pas refait

Le **moteur** répond déjà à sept sections sur onze, et il a été éprouvé sur du trafic réel
(captures réelles, fichiers `.pcap` rejoués, 375 tests automatisés).

| § | Exigence du sujet | État | Preuve |
|---|---|---|---|
| 2 | source, destination, protocole, ports, taille, horodatage | ✅ | `agent/parser.py` |
| 2 | informations relatives aux couches réseau | ✅ | vue par couche, Ethernet → application |
| 2 | informations relatives aux communications | ✅ | `agent/flows.py` |
| 2 | gérer les paquets à informations manquantes | ✅ | `analyse_partielle` + motif écrit |
| 3 | qui communique avec qui, depuis combien de temps, protocole, port | ✅ | §3 du sujet, mot pour mot |
| 3 | combien de paquets, combien de données, communication encore active ? | ✅ | vue Connections |
| 4 | explication en langage humain | ✅ | `backend/explain/rules.py`, 60 services |
| 4 | distinguer FAIT OBSERVÉ de INTERPRÉTATION | ✅ | les deux sont séparés et étiquetés |
| 4 | ne pas présenter une hypothèse comme une certitude | ✅ | `etat_certain`, notes explicatives |
| 5 | reconnaître plusieurs protocoles et expliquer leur rôle | ✅ | TCP, UDP, DNS, ICMP, ICMPv6, ARP, TLS, HTTP |
| 6 | début, en cours, fermeture, échec d'une connexion | ✅ | machine à états + 4 anomalies TCP |
| 7 | OBSERVATION / HYPOTHÈSE / ALERTE | ✅ | les trois niveaux ; aucune règle isolée ne suffit |
| 7 | comportements inhabituels | ✅ | retransmissions, poignées incomplètes, RST, fenêtres nulles |
| 8 | au moins une API externe | ✅ | ipinfo.io + AbuseIPDB — **aucune IP privée n'est envoyée** |
| 10 | statistiques utiles | ✅ | pourcentages, top talkers, débit, ports fréquents |
| 11 | modèle de données conçu et expliqué | ✅ | `sql/schema.sql`, 7 tables, contraintes justifiées |

**Conclusion : le moteur reste.** C'est l'organisation de l'interface qui est reprise.

---

## 3. La structure proposée

### 3.1 Une barre d'état-capture, en tête de page, permanente

C'est le §1 et l'étape 2 de la démonstration. Elle porte :

- **le choix de la source** (la liste des interfaces réellement disponibles) ;
- **Démarrer** / **Arrêter** ;
- **l'état** : arrêté, capture en cours depuis N secondes, N paquets reçus ;
- le lien vers la page historique (§11).

### 3.2 Quatre vues principales, et rien d'autre au premier niveau

Exactement les quatre du §9 :

| Vue | Ce qu'elle porte | Sections actuelles déplacées dedans |
|---|---|---|
| **Traffic** | le trafic en un coup d'œil | cartes chiffrées, débit dans le temps, répartition par protocole |
| **Connections** | les communications observées | la table des communications, le récit d'une conversation |
| **Protocols** | les protocoles et leur rôle | la hiérarchie, les explications de protocole, la vue par couche |
| **Alerts** | ce qui mérite l'attention | les niveaux, l'Expert Info, les anomalies avec leurs critères |

**Les statistiques, l'Expert Info et les profils deviennent des contenus de vue** — plus des
sections concurrentes au même niveau que le reste.

### 3.3 Une vue détaillée unique

Quand un élément est sélectionné (§9), le détail réunit **les quatre blocs demandés, au même
endroit**, au lieu de les éparpiller :

1. **Technical information** — les faits mesurés : adresses, ports, protocole, volume, durée.
2. **Analysis** — l'état de la communication, ses étapes, ses anomalies.
3. **Human explanation** — l'explication en français, avec FAIT OBSERVÉ / INTERPRÉTATION.
4. **Risk / status** — OBSERVATION, HYPOTHÈSE ou ALERTE, avec la certitude associée.

Plus, ce que le projet a déjà et qui sert la démonstration : le **récit** de la conversation,
les **couches** avec leur rôle, les **octets** des en-têtes, et l'**enrichissement** externe.

### 3.4 Les deux vues techniques, accessibles depuis le détail

- **Vue des paquets** — la liste, avec ses trois zones (liste / détail du paquet / contenu).
- **Vue par couche** — la connaissance reste côté serveur.

---

## 4. L'ordre d'exécution

Je suivrai **l'ordre du §20**, parce que c'est celui que le jury suivra :

1. La barre d'état-capture (§1) — parce que la démonstration commence par là.
2. La restructuration en quatre vues (§9) — ce qui règle la lisibilité d'ensemble.
3. La vue détaillée unifiée (§9) — les quatre blocs au même endroit.
4. L'affichage de l'enrichissement (§8) — étape 7 de la démonstration.
5. Supabase (§11) et les données conservées — étape 8.
6. GitHub (§20.9) et la mise en ligne (§20.10) — étapes 9 et 10.

Chaque étape sera vérifiée **dans un vrai navigateur** avant d'être présentée, et la
documentation (`docs/DEFENSE.md`, `README.md`) sera mise à jour en même temps.

---

## 5. Ce dont j'ai besoin de ta part

Rien de bloquant, mais ces trois éléments conditionnent les étapes 5 et 6 :

1. **Supabase** — le projet existe-t-il déjà, ou faut-il en créer un ? La clé `service_role`
   et l'URL restent dans `.env`, jamais dans le dépôt.
2. **GitHub** — l'autorisation de pousser ce dépôt (rien n'a jamais été poussé). Rappel de ta
   règle : **aucun `.docx` ne va sur GitHub**.
3. **Vercel** — où l'application doit être accessible en ligne, et si le projet Vercel existe
   déjà.

---

## 6. Ce que je ne ferai pas

- Je ne toucherai à aucune ligne de code avant que tu aies validé ce plan.
- Je ne présenterai pas une étape comme terminée sans l'avoir éprouvée sur du trafic réel.
- Je ne pousserai rien sur GitHub ni ne publierai rien en ligne sans ton accord explicite.
- Je ne remplacerai pas un affichage honnête par un affichage plus flatteur : ce qui n'est pas
  extrait reste marqué comme tel, et une hypothèse ne deviendra jamais une certitude.

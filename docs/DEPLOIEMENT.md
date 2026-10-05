# Déploiement

Ce document décrit la mise en ligne du projet. Il suit l'architecture imposée : **deux
moitiés qui ne se déploient pas au même endroit**.

    l'agent   tourne sur la machine à surveiller, avec les privilèges de capture
    le backend tourne en ligne, dans un conteneur, et sert le tableau de bord public

Un serveur en ligne ne peut pas écouter votre réseau local. C'est la contrainte qui
structure tout le projet, et elle explique pourquoi cette page a deux parties.

---

## 1. La base de données — Supabase

Supabase est PostgreSQL. Il n'y a pas de code « Supabase » dans ce projet : il y a du code
PostgreSQL et une chaîne de connexion. C'est ce qui a permis d'éprouver la persistance sur
une base locale avant de la déployer.

1. Créer un projet sur [supabase.com](https://supabase.com) — l'offre gratuite suffit.
2. Ouvrir **SQL Editor**, coller le contenu de `sql/schema.sql`, exécuter.
   Le schéma crée son propre espace de noms, `analyzer` : il ne touche à rien d'autre.
3. Vérifier que tout est en place — la même commande peut être lancée depuis l'éditeur
   SQL de Supabase, elle s'auto-vérifie et s'arrête à la première anomalie :

   ```sql
   -- coller le contenu de sql/verifier-schema.sql
   ```

4. Relever la chaîne de connexion dans **Project Settings → Database → Connection
   string**. Prendre la version **pooler** (port 6543) : le backend ouvre plusieurs
   connexions, et la connexion directe les plafonne vite.

> **Les rôles de Supabase.** Le schéma retire les droits de lecture aux rôles `anon` et
> `authenticated`, et la sécurité au niveau des lignes est active **sans aucune
> politique** : seule la clé de service du backend peut lire. Le navigateur ne reçoit
> jamais de clé Supabase — il ne parle qu'à l'API du backend. Ces rôles n'existent pas
> sur un PostgreSQL ordinaire : le schéma le détecte et l'annonce, ce qui lui permet de
> fonctionner dans les deux cas.

---

## 2. Le backend — Render ou Railway

Le `Dockerfile` est à la racine : les deux plateformes le détectent seules.

| Variable | Valeur | Rôle |
|---|---|---|
| `ANALYZER_AGENT_TOKEN` | un secret long | **obligatoire** : authentifie l'agent |
| `ANALYZER_DATABASE_URL` | la chaîne Supabase | conserve l'historique |
| `ANALYZER_ENV` | `production` | active les contrôles de production |
| `ANALYZER_PORT` | `8000` | port d'écoute dans le conteneur |
| `ANALYZER_RETENTION_JOURS` | `30` | purge automatique |
| `ANALYZER_ORIGINES_CORS` | l'adresse publique du site | si un front séparé est ajouté |

Engendrer le jeton d'agent :

```bat
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

**En production, un jeton absent fait échouer le démarrage.** C'est délibéré : un backend
public dont n'importe qui pourrait écrire des paquets est un backend qui accepte des
données inventées. En développement, un jeton est engendré et affiché dans le journal.

Après le déploiement, vérifier :

```bat
curl https://<votre-adresse>/api/v1/health
```

La réponse dit l'état du service, celui de la couche IA et celui de l'enrichissement. Si
l'un des deux est inactif, c'est une information, pas une panne.

---

## 3. L'agent — sur la machine à surveiller

L'agent n'est **pas** déployé en ligne : il tourne là où le trafic circule.

```bat
python -m agent.main --interfaces
python -m agent.main --interface "Wi-Fi" --backend https://<votre-adresse> --jeton <jeton> --nom poste-ogou
```

Sur Windows, Npcap est nécessaire pour la capture. Sur Linux, lancer avec les droits de
capture (`CAP_NET_RAW` ou `sudo`) : sans eux, l'agent s'arrête en le disant clairement,
plutôt que de tourner en ne capturant rien.

**Pour un démarrage automatique**, un raccourci dans le dossier Démarrage suffit. Une
tâche planifiée serait plus propre, mais elle demande des droits d'administration que
cette machine n'a pas.

---

## 4. Le mode replay — démonstration sans capture

Le mode replay ne demande ni droits particuliers, ni réseau, ni interface. Il traverse
exactement la même chaîne que la capture : c'est ce qui en fait une vérification, et non
une démonstration à part.

```bat
python -m agent.main --pcap capture.pcap --inspecter
python -m agent.main --pcap capture.pcap --backend https://<votre-adresse> --jeton <jeton>
```

Un fichier `.pcap` s'obtient avec Wireshark, `tcpdump`, ou l'enregistreur de cet outil.
**Ne jamais versionner un fichier de capture réel** : il contient le trafic d'un réseau,
et révèle sa topologie.

---

## 5. L'entretien

**La purge est automatique.** Toutes les vingt-quatre heures, le backend supprime les
sessions de plus de `ANALYZER_RETENTION_JOURS` (trente par défaut), et la cascade emporte
leurs paquets, communications et détections. Elle tourne dans un fil séparé, attend un
intervalle complet avant sa première exécution, et ne retient jamais l'arrêt du service.
Une purge qui échoue est consignée et retentée au tour suivant : elle ne fait jamais
tomber le backend.

Sans persistance (aucune `ANALYZER_DATABASE_URL`), il n'y a rien à purger : tout disparaît
à l'arrêt.

**Ce qu'il faut surveiller** : `GET /api/v1/health` pour la disponibilité, et le journal du
service pour les refus d'authentification — un agent qui échoue en boucle se voit là avant
de se voir ailleurs.

---

## 6. Ce qui n'est pas fait

- **Pas de compte utilisateur.** Le tableau de bord est public, en lecture seule : c'est
  une décision prise au départ du projet. Ajouter une authentification supposerait des
  comptes, une gestion de session et une page de connexion — un projet à part entière.
- **Pas de HTTPS en local.** En ligne, la plateforme s'en charge. Sur un réseau local, la
  communication entre l'agent et le backend circule en clair : c'est acceptable quand les
  deux sont sur la même machine, beaucoup moins au-delà.
- **Le tableau de bord n'est pas paginé.** Il affiche les cent cinquante communications et
  les cinquante dernières détections. Au-delà, il faudrait de la pagination côté serveur.

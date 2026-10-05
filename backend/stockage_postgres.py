"""Stockage PostgreSQL — la même interface que le stockage en mémoire, mais durable.

POURQUOI CETTE CLASSE EXISTE
----------------------------
Le schéma (`sql/schema.sql`) était écrit et éprouvé depuis la phase 2 ; le backend, lui,
gardait tout en mémoire. Cette classe est la pièce qui les relie. Elle présente
**exactement les mêmes méthodes** que `Stockage` : les routes ne savent pas laquelle des
deux elles utilisent, et n'ont pas eu à changer d'une ligne. C'est ce que la couche de
dépendances promettait depuis le premier jour.

SUPABASE, POSTGRESQL, MÊME CHOSE
--------------------------------
Supabase est PostgreSQL. La seule différence tient dans la chaîne de connexion :
`ANALYZER_DATABASE_URL` pointe vers le serveur Supabase en production, et vers une base
locale pendant la mise au point. Il n'y a pas de code à changer, et c'est délibéré : cela
permet d'éprouver la persistance sans dépendre d'un service distant, et sans y écrire de
données de test.

CE QUI EST DIFFÉRENT DU STOCKAGE EN MÉMOIRE
-------------------------------------------
Trois choses, et il faut les connaître :

    - **la session est un identifiant**. En mémoire, une session était une chaîne
      quelconque ; dans le schéma, c'est une clé étrangère de type `uuid`. Un libellé
      comme « capture-du-matin » est donc converti en identifiant stable (même libellé,
      même identifiant). C'est ce qui permet aux tests et aux outils de vérification
      d'employer des noms lisibles sans casser le schéma.
    - **les écritures sont des `UPSERT`**. Une communication revue à chaque lot met à
      jour sa ligne au lieu d'en créer une seconde — c'est la contrainte d'unicité
      `(session_id, cle)` du schéma qui le garantit, et non la vigilance du code.
    - **les dates vides ne sont pas écrites**. Un `debut` absent deviendrait « maintenant »
      par défaut en base, ce qui inventerait une date. On écrit `NULL`, ou la date réelle.

CE QUI N'EST PAS FAIT, ET QUI EST ÉCRIT ICI POUR ÊTRE LU
--------------------------------------------------------
Les paquets ne sont pas rattachés à leur communication (`flow_id`). Le rattachement
demanderait, pour chaque paquet, de recalculer sa clé de communication puis de chercher la
ligne correspondante — un travail coûteux à chaque lot, pour une information que la table
des paquets permet déjà de retrouver par ses adresses et ses ports. Le champ existe dans
le schéma et reste `NULL` : c'est une optimisation possible, pas une lacune dissimulée.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
import uuid
from typing import Any

logger = logging.getLogger(__name__)

# La conversion vit dans son propre module : la traduction des filtres en a besoin, et
# elle serait sinon devenue un import circulaire. Elle est ré-exportée ici pour que les
# appelants existants n'aient pas à changer.
from backend import filtres_sql
from backend.identifiants import identifiant_session  # noqa: E402  (ré-export)


def _date(valeur: str | None) -> str | None:
    """Rend une date exploitable par PostgreSQL, ou `None` si elle est illisible.

    On ne remplace jamais une date absente par l'heure courante : ce serait inventer une
    observation. `None` devient `NULL` en base, et l'interface affiche un tiret.
    """
    if not valeur:
        return None
    texte = str(valeur).strip()
    if not texte:
        return None
    return texte.replace("Z", "+00:00")


def _entier(valeur: Any) -> int | None:
    try:
        return int(valeur)
    except (TypeError, ValueError):
        return None


def _adresse(valeur: Any) -> str | None:
    """Valide une adresse avant de l'envoyer à PostgreSQL.

    Le type `inet` refuserait une valeur malformée en levant une erreur — et une seule
    adresse abîmée ferait échouer tout un lot. On écarte donc les valeurs illisibles en
    amont, ce qui est aussi la façon dont le reste du projet traite les données du réseau.
    """
    if not valeur:
        return None
    try:
        ipaddress.ip_address(str(valeur))
    except ValueError:
        return None
    return str(valeur)


class StockagePostgres:
    """Persistance dans PostgreSQL. Mêmes méthodes que le stockage en mémoire."""

    def __init__(self, url: str, taille_max: int = 2000) -> None:
        if not url:
            raise ValueError("ANALYZER_DATABASE_URL est vide : aucun stockage PostgreSQL")
        self.url = url
        self.taille_max = taille_max
        self._verrou = threading.Lock()
        self._assurer_schema()

    # ------------------------------------------------------------------ connexion
    def _connexion(self):
        """Ouvre une connexion. Import local : l'outil doit rester utilisable sans base.

        `psycopg` n'est nécessaire que si l'on choisit PostgreSQL. L'importer au
        chargement du module obligerait à l'installer même pour une démonstration en
        mémoire — ce qui irait contre le principe du projet : chaque brique facultative
        doit pouvoir être absente.
        """
        import psycopg

        return psycopg.connect(self.url, autocommit=False)

    def _assurer_schema(self) -> None:
        """Vérifie que le schéma existe, et le dit clairement sinon.

        Le message compte plus que le contrôle : une erreur « relation analyzer.flows
        inexistante » au premier lot reçu ferait chercher longtemps. Ici, on dit quoi
        faire, et en quelle commande.
        """
        try:
            with self._connexion() as connexion, connexion.cursor() as curseur:
                curseur.execute("""
                    SELECT count(*) FROM information_schema.tables
                    WHERE table_schema = 'analyzer'
                """)
                presentes = curseur.fetchone()[0]
            if presentes == 0:
                logger.error(
                    "Le schéma « analyzer » est absent de la base.\n"
                    "  Appliquer le schéma, puis redémarrer :\n"
                    "    psql -v ON_ERROR_STOP=1 -f sql/schema.sql   "
                    "(avec la chaîne de connexion d'ANALYZER_DATABASE_URL)")
        except Exception as erreur:                                    # noqa: BLE001
            logger.error("Base injoignable (%s). Le backend démarrera, mais les lots "
                         "seront refusés jusqu'à ce que la connexion soit rétablie.",
                         type(erreur).__name__)

    # ------------------------------------------------------------------ ingestion
    @staticmethod
    def _assurer_session(curseur, identifiant: str, agent: str = "agent-local") -> None:
        """Crée la session si elle n'existe pas encore.

        Appelé avant chaque écriture, et pas seulement par l'ingestion des paquets. Un
        agent peut envoyer des communications ou des détections sans paquets — un lot
        partiel, une version antérieure de l'agent, un outil de vérification. Sans ce
        contrôle, la clé étrangère rejetterait l'écriture entière : le lot serait perdu
        pour une ligne manquante, alors que l'information, elle, était valide.
        """
        curseur.execute("""
            INSERT INTO analyzer.capture_sessions (id, agent)
            VALUES (%s, %s)
            ON CONFLICT (id) DO NOTHING
        """, (identifiant, (agent or "agent-local")[:120]))

    def enregistrer_lot(self, session: str, agent: str, paquets: list[dict[str, Any]]) -> int:
        """Écrit une session au besoin, puis les paquets qu'elle contient."""
        if not paquets:
            return 0
        identifiant = identifiant_session(session)
        with self._verrou, self._connexion() as connexion:
            with connexion.cursor() as curseur:
                self._assurer_session(curseur, identifiant, agent)

                lignes = []
                ecartes = 0
                for paquet in paquets:
                    # Une adresse identique des deux côtés ne décrit aucun échange — c'est
                    # le signe d'une capture abîmée ou d'une donnée forgée. Le schéma
                    # l'interdit par une contrainte, et il a raison. Mais laisser la
                    # contrainte faire échouer l'insertion ferait perdre **tout le lot**
                    # pour une ligne : on écarte donc la ligne avant l'insertion, et le
                    # schéma reste la dernière ligne de défense plutôt que la première.
                    source = _adresse(paquet.get("ip_source"))
                    destination = _adresse(paquet.get("ip_destination"))
                    if source and destination and source == destination:
                        ecartes += 1
                        continue
                    details = paquet.get("details") or {}
                    lignes.append((
                        identifiant,
                        _date(paquet.get("horodatage")) or "now()",
                        _entier(paquet.get("taille")),
                        _entier(paquet.get("taille_capturee")),
                        (paquet.get("protocole") or "inconnu")[:64],
                        _adresse(paquet.get("ip_source")),
                        _adresse(paquet.get("ip_destination")),
                        paquet.get("mac_source"),
                        paquet.get("mac_destination"),
                        _entier(paquet.get("version_ip")),
                        _entier(paquet.get("port_source")),
                        _entier(paquet.get("port_destination")),
                        paquet.get("flags_tcp"),
                        _entier(paquet.get("ttl")),
                        json.dumps(details, ensure_ascii=False),
                        bool(paquet.get("analyse_partielle")),
                        paquet.get("motif_partiel"),
                    ))

                # `executemany` envoie les lignes en un seul aller-retour : sur un lot de
                # mille paquets, la différence avec mille requêtes séparées se compte en
                # secondes, et l'écart grandit avec la latence du réseau.
                curseur.executemany("""
                    INSERT INTO analyzer.packets (
                        session_id, horodatage, taille, taille_capturee, protocole,
                        ip_source, ip_destination, mac_source, mac_destination,
                        version_ip, port_source, port_destination, flags_tcp, ttl,
                        details, analyse_partielle, motif_partiel
                    ) VALUES (%s, COALESCE(%s::timestamptz, now()), %s, %s, %s, %s, %s, %s, %s,
                              %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                """, lignes)

                curseur.execute("""
                    UPDATE analyzer.capture_sessions
                       SET dernier_paquet = GREATEST(COALESCE(dernier_paquet, now()), now()),
                           paquets_vus = paquets_vus + %s
                     WHERE id = %s
                """, (len(lignes), identifiant))
            connexion.commit()

        if ecartes:
            logger.warning("Lot %s : %d paquet(s) écarté(s) — adresse source et "
                           "destination identiques", session[:8], ecartes)
        # On rend le nombre réellement écrit : l'agent compare ce qu'il a envoyé à ce qui
        # a été conservé, et c'est ainsi qu'une perte se voit au lieu de se subir.
        return len(lignes)

    def enregistrer_communications(self, session: str,
                                   communications: list[dict[str, Any]]) -> int:
        """Écrit les communications, en mettant à jour celles déjà connues.

        L'unicité `(session_id, cle)` du schéma est ce qui rend l'envoi répété sans
        danger : l'agent renvoie une conversation à chaque lot, et c'est la base qui
        garantit qu'il n'en résulte pas deux lignes.
        """
        if not communications:
            return 0
        identifiant = identifiant_session(session)
        ecrites = 0
        with self._verrou, self._connexion() as connexion:
            with connexion.cursor() as curseur:
                self._assurer_session(curseur, identifiant)
                for communication in communications:
                    ip_a = _adresse(communication.get("ip_a"))
                    ip_b = _adresse(communication.get("ip_b"))
                    debut = _date(communication.get("debut"))
                    if not (ip_a and ip_b and debut and communication.get("cle")):
                        # Une communication sans extrémités ni date n'est pas une
                        # communication : on l'écarte plutôt que d'écrire une ligne
                        # inexploitable qui fausserait les comptages.
                        continue

                    curseur.execute("""
                        INSERT INTO analyzer.flows (
                            session_id, cle, protocole, ip_a, ip_b, port_a, port_b,
                            initiateur, debut, dernier_paquet, termine_le, duree_secondes,
                            paquets_a_vers_b, paquets_b_vers_a,
                            octets_a_vers_b, octets_b_vers_a,
                            indicateurs, etat, etat_certain, note_etat, vu_depuis_le_debut
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, COALESCE(%s::timestamptz, now()),
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                        )
                        ON CONFLICT (session_id, cle) DO UPDATE SET
                            dernier_paquet     = EXCLUDED.dernier_paquet,
                            termine_le         = EXCLUDED.termine_le,
                            duree_secondes     = EXCLUDED.duree_secondes,
                            paquets_a_vers_b   = EXCLUDED.paquets_a_vers_b,
                            paquets_b_vers_a   = EXCLUDED.paquets_b_vers_a,
                            octets_a_vers_b    = EXCLUDED.octets_a_vers_b,
                            octets_b_vers_a    = EXCLUDED.octets_b_vers_a,
                            indicateurs        = EXCLUDED.indicateurs,
                            etat               = EXCLUDED.etat,
                            etat_certain       = EXCLUDED.etat_certain,
                            note_etat          = EXCLUDED.note_etat,
                            vu_depuis_le_debut = EXCLUDED.vu_depuis_le_debut
                    """, (
                        identifiant, communication["cle"],
                        (communication.get("protocole") or "inconnu")[:32],
                        ip_a, ip_b,
                        _entier(communication.get("port_a")),
                        _entier(communication.get("port_b")),
                        _adresse(communication.get("initiateur")),
                        debut,
                        _date(communication.get("dernier_paquet")),
                        _date(communication.get("termine_le")),
                        float(communication.get("duree_secondes") or 0),
                        int(communication.get("paquets_a_vers_b") or 0),
                        int(communication.get("paquets_b_vers_a") or 0),
                        int(communication.get("octets_a_vers_b") or 0),
                        int(communication.get("octets_b_vers_a") or 0),
                        communication.get("indicateurs"),
                        communication.get("etat") or "inconnue",
                        bool(communication.get("etat_certain")),
                        communication.get("note_etat"),
                        bool(communication.get("vu_depuis_le_debut")),
                    ))
                    ecrites += 1
            connexion.commit()
        return ecrites

    def enregistrer_detections(self, session: str, detections: list[dict[str, Any]]) -> int:
        """Écrit les détections. L'unicité porte sur (session, règle, IP concernée).

        Une détection revue met à jour sa ligne et incrémente son compteur : c'est ce qui
        évite que le tableau de bord affiche cent fois la même phrase.
        """
        if not detections:
            return 0
        identifiant = identifiant_session(session)
        ecrites = 0
        with self._verrou, self._connexion() as connexion:
            with connexion.cursor() as curseur:
                self._assurer_session(curseur, identifiant)
                for detection in detections:
                    ip = _adresse(detection.get("cible"))
                    if not detection.get("regle") or not detection.get("titre"):
                        continue
                    # Le schéma distingue « hypothèse » (sans accent) du mot affiché. On
                    # traduit ici, en un seul endroit, plutôt que dans chaque appelant.
                    niveau = {"observation": "observation", "hypothèse": "hypothese",
                              "hypothese": "hypothese", "alerte": "alerte"}.get(
                        detection.get("niveau"), "observation")
                    severite = {"observation": "info", "hypothese": "low",
                                "alerte": "medium"}.get(niveau, "info")

                    curseur.execute("""
                        INSERT INTO analyzer.alerts (
                            session_id, niveau, severite, titre, constat,
                            interpretation, criteres, ip_concernee,
                            debut, dernier_vu, occurrences, regle
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s::jsonb, %s,
                            COALESCE(%s::timestamptz, now()), %s, %s, %s
                        )
                        ON CONFLICT (session_id, regle, ip_concernee) DO UPDATE SET
                            constat         = EXCLUDED.constat,
                            interpretation  = EXCLUDED.interpretation,
                            criteres        = EXCLUDED.criteres,
                            dernier_vu      = EXCLUDED.dernier_vu,
                            occurrences     = EXCLUDED.occurrences
                    """, (
                        identifiant, niveau, severite,
                        detection.get("titre")[:200],
                        detection.get("explication") or detection.get("titre"),
                        detection.get("explication"),
                        json.dumps({
                            "regle": detection.get("regle"),
                            "famille": detection.get("famille"),
                            "confiance": detection.get("confiance"),
                            "faits_observes": detection.get("faits_observes") or [],
                            "faux_positifs": detection.get("faux_positifs"),
                        }, ensure_ascii=False),
                        ip,
                        _date(detection.get("debut")) or _date(detection.get("dernier")),
                        _date(detection.get("dernier")),
                        max(1, int(detection.get("occurrences") or 1)),
                        detection.get("regle")[:64],
                    ))
                    ecrites += 1
            connexion.commit()
        return ecrites

    # ------------------------------------------------------------------ lecture
    def paquets(self, limite: int = 100, protocole: str | None = None,
                session: str | None = None, recherche: str | None = None,
                filtre: list | None = None) -> list[dict]:
        conditions, valeurs = [], []
        if protocole:
            conditions.append("protocole = %s")
            valeurs.append(protocole)
        if session:
            conditions.append("session_id = %s")
            valeurs.append(identifiant_session(session))
        if recherche:
            conditions.append("""(
                host(ip_source) ILIKE %s OR host(ip_destination) ILIKE %s
                OR COALESCE(port_source::text, '') = %s
                OR COALESCE(port_destination::text, '') = %s
                OR COALESCE(details->>'domaine', '') ILIKE %s)""")
            motif = f"%{recherche}%"
            valeurs.extend([motif, motif, recherche, recherche, motif])

        # Le filtre d'affichage arrive ici sous forme de critères déjà validés. Ses
        # conditions sont ajoutées aux précédentes, dans le même ordre que ses paramètres :
        # c'est cette correspondance qui garantit qu'aucune valeur ne se perd.
        if filtre:
            fragment, parametres = filtres_sql.conditions(filtre, "paquets")
            if fragment:
                conditions.append(fragment)
                valeurs.extend(parametres)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        valeurs.append(min(limite, 1000))
        with self._connexion() as connexion, connexion.cursor() as curseur:
            curseur.execute(f"""
                SELECT horodatage, taille, taille_capturee, protocole,
                       host(ip_source), host(ip_destination), mac_source, mac_destination,
                       version_ip, port_source, port_destination, flags_tcp, ttl,
                       details, analyse_partielle, motif_partiel
                  FROM analyzer.packets {where}
                 ORDER BY horodatage DESC
                 LIMIT %s
            """, valeurs)
            lignes = curseur.fetchall()
        return [{
            "horodatage": ligne[0].isoformat() if ligne[0] else None,
            "taille": ligne[1], "taille_capturee": ligne[2], "protocole": ligne[3],
            "ip_source": ligne[4], "ip_destination": ligne[5],
            "mac_source": ligne[6], "mac_destination": ligne[7],
            "version_ip": ligne[8], "port_source": ligne[9], "port_destination": ligne[10],
            "flags_tcp": ligne[11], "ttl": ligne[12], "details": ligne[13] or {},
            "analyse_partielle": ligne[14], "motif_partiel": ligne[15],
        } for ligne in lignes]

    def communication(self, cle: str, session: str | None = None) -> dict | None:
        conditions = ["cle = %s"]
        valeurs: list[Any] = [cle]
        if session:
            conditions.append("session_id = %s")
            valeurs.append(identifiant_session(session))
        with self._connexion() as connexion, connexion.cursor() as curseur:
            curseur.execute(f"""
                SELECT {_COLONNES_COMMUNICATION}
                  FROM analyzer.flows
                 WHERE {' AND '.join(conditions)}
                 ORDER BY dernier_paquet DESC
                 LIMIT 1
            """, valeurs)
            ligne = curseur.fetchone()
        return _ligne_vers_communication(ligne) if ligne else None

    def communications(self, limite: int = 100, etat: str | None = None,
                       protocole: str | None = None, session: str | None = None,
                       recherche: str | None = None, filtre: list | None = None) -> list[dict]:
        conditions, valeurs = [], []
        if session:
            conditions.append("session_id = %s")
            valeurs.append(identifiant_session(session))
        if etat:
            conditions.append("etat = %s")
            valeurs.append(etat)
        if protocole:
            conditions.append("protocole = %s")
            valeurs.append(protocole)
        if recherche:
            conditions.append("""(
                host(ip_a) ILIKE %s OR host(ip_b) ILIKE %s
                OR COALESCE(port_a::text, '') = %s OR COALESCE(port_b::text, '') = %s
                OR etat ILIKE %s)""")
            motif = f"%{recherche}%"
            valeurs.extend([motif, motif, recherche, recherche, motif])

        if filtre:
            fragment, parametres = filtres_sql.conditions(filtre, "communications")
            if fragment:
                conditions.append(fragment)
                valeurs.extend(parametres)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        valeurs.append(min(limite, 2000))
        with self._connexion() as connexion, connexion.cursor() as curseur:
            curseur.execute(f"""
                SELECT {_COLONNES_COMMUNICATION}, session_id
                  FROM analyzer.flows {where}
                 ORDER BY dernier_paquet DESC
                 LIMIT %s
            """, valeurs)
            lignes = curseur.fetchall()
        resultats = []
        for ligne in lignes:
            communication = _ligne_vers_communication(ligne)
            communication["session"] = str(ligne[-1])
            resultats.append(communication)
        return resultats

    def detections(self, limite: int = 200, niveau: str | None = None,
                   session: str | None = None, filtre: list | None = None) -> list[dict]:
        conditions, valeurs = [], []
        if session:
            conditions.append("session_id = %s")
            valeurs.append(identifiant_session(session))
        if niveau:
            conditions.append("niveau = %s")
            valeurs.append({"observation": "observation", "hypothèse": "hypothese",
                            "hypothese": "hypothese", "alerte": "alerte"}.get(niveau, niveau))

        if filtre:
            fragment, parametres = filtres_sql.conditions(filtre, "detections")
            if fragment:
                conditions.append(fragment)
                valeurs.extend(parametres)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        valeurs.append(min(limite, 500))
        with self._connexion() as connexion, connexion.cursor() as curseur:
            curseur.execute(f"""
                SELECT niveau, titre, constat, interpretation, criteres,
                       host(ip_concernee), debut, dernier_vu, occurrences, session_id, regle
                  FROM analyzer.alerts {where}
                 ORDER BY COALESCE(dernier_vu, debut) DESC
                 LIMIT %s
            """, valeurs)
            lignes = curseur.fetchall()

        resultats = []
        for ligne in lignes:
            criteres = ligne[4] or {}
            resultats.append({
                # La règle vient de sa colonne : elle est la clé de l'unicité, elle ne
                # peut donc pas manquer, contrairement à sa copie dans `criteres`.
                "regle": ligne[10] or "inconnue",
                "famille": criteres.get("famille") or "",
                "niveau": {"hypothese": "hypothèse"}.get(ligne[0], ligne[0]),
                "titre": ligne[1],
                "faits_observes": criteres.get("faits_observes") or [],
                "explication": ligne[3] or ligne[2],
                "confiance": criteres.get("confiance") or "moyenne",
                "faux_positifs": criteres.get("faux_positifs") or "",
                "cible": ligne[5], "debut": ligne[6].isoformat() if ligne[6] else "",
                "dernier": ligne[7].isoformat() if ligne[7] else "",
                "occurrences": ligne[8], "session": str(ligne[9]),
            })
        return resultats

    def statistiques(self) -> dict[str, Any]:
        """Chiffres du tableau de bord, calculés par la base et non par le navigateur.

        Les comptages sont faits en SQL pour la même raison qu'en mémoire : une page de
        tableau de bord ne doit pas rapatrier des milliers de lignes pour en compter
        quelques nombres.
        """
        with self._connexion() as connexion, connexion.cursor() as curseur:
            curseur.execute("""
                SELECT count(*), COALESCE(sum(taille), 0),
                       COALESCE(sum(CASE WHEN analyse_partielle THEN 1 ELSE 0 END), 0),
                       min(horodatage), max(horodatage)
                  FROM analyzer.packets
            """)
            total, octets, partielles, premier, dernier = curseur.fetchone()

            curseur.execute("""SELECT protocole, count(*) FROM analyzer.packets
                                GROUP BY protocole ORDER BY count(*) DESC""")
            par_protocole = dict(curseur.fetchall())

            def classement(colonne: str) -> list[dict]:
                curseur.execute(f"""
                    SELECT host({colonne}) AS valeur, count(*) AS nombre
                      FROM analyzer.packets WHERE {colonne} IS NOT NULL
                     GROUP BY 1 ORDER BY nombre DESC LIMIT 5
                """)
                return [{"valeur": ligne[0], "nombre": ligne[1]} for ligne in curseur.fetchall()]

            sources = classement("ip_source")
            destinations = classement("ip_destination")

            curseur.execute("""SELECT COALESCE(port_destination, port_source) AS port,
                                      count(*) AS nombre
                                 FROM analyzer.packets
                                WHERE COALESCE(port_destination, port_source) IS NOT NULL
                                GROUP BY 1 ORDER BY nombre DESC LIMIT 8""")
            ports = [{"valeur": ligne[0], "nombre": ligne[1]} for ligne in curseur.fetchall()]

            curseur.execute("""SELECT etat, count(*) FROM analyzer.flows
                                GROUP BY etat ORDER BY count(*) DESC""")
            par_etat = dict(curseur.fetchall())

            curseur.execute("SELECT count(*), COALESCE(sum(CASE WHEN NOT etat_certain "
                            "THEN 1 ELSE 0 END), 0) FROM analyzer.flows")
            communications, incertaines = curseur.fetchone()

            curseur.execute("SELECT niveau, count(*) FROM analyzer.alerts GROUP BY niveau")
            par_niveau = dict(curseur.fetchall())

            curseur.execute("SELECT count(*) FROM analyzer.alerts")
            detections = curseur.fetchone()[0]

            curseur.execute("SELECT count(*) FROM analyzer.capture_sessions")
            sessions = curseur.fetchone()[0]

        return {
            "paquets_total": total, "paquets_conserves": total, "octets_total": octets,
            "par_protocole": par_protocole, "top_sources": sources,
            "top_destinations": destinations, "ports_frequents": ports,
            "premier_paquet": premier.isoformat() if premier else None,
            "dernier_paquet": dernier.isoformat() if dernier else None,
            "analyses_partielles": partielles,
            "sessions": sessions,
            "communications_total": communications,
            "communications_conservees": communications,
            "communications_par_etat": par_etat,
            "communications_incertaines": incertaines,
            "detections_total": detections, "detections_conservees": detections,
            "detections_par_niveau": {
                {"hypothese": "hypothèse"}.get(cle, cle): valeur
                for cle, valeur in par_niveau.items()},
            "stockage": "postgresql",
        }

    def session(self, identifiant: str) -> dict[str, Any] | None:
        with self._connexion() as connexion, connexion.cursor() as curseur:
            curseur.execute("""
                SELECT id, agent, debut, dernier_paquet, paquets_vus, octets_vus
                  FROM analyzer.capture_sessions WHERE id = %s
            """, (identifiant_session(identifiant),))
            ligne = curseur.fetchone()
        if not ligne:
            return None
        return {
            "id": str(ligne[0]), "agent": ligne[1],
            "debut": ligne[2].isoformat() if ligne[2] else None,
            "dernier_paquet": ligne[3].isoformat() if ligne[3] else None,
            "paquets": ligne[4], "octets": ligne[5],
        }

    def sessions(self) -> list[dict[str, Any]]:
        with self._connexion() as connexion, connexion.cursor() as curseur:
            curseur.execute("""
                SELECT id, agent, debut, dernier_paquet, paquets_vus
                  FROM analyzer.capture_sessions ORDER BY debut DESC LIMIT 50
            """)
            lignes = curseur.fetchall()
        return [{
            "id": str(ligne[0]), "agent": ligne[1],
            "debut": ligne[2].isoformat() if ligne[2] else None,
            "dernier_paquet": ligne[3].isoformat() if ligne[3] else None,
            "paquets": ligne[4],
        } for ligne in lignes]

    # ------------------------------------------------------------------ entretien
    def vider(self) -> None:
        """Vide toutes les tables. Les cascades emportent le reste.

        Réservé aux outils de vérification : un tableau de bord public ne doit jamais
        pouvoir vider sa base.
        """
        with self._verrou, self._connexion() as connexion:
            with connexion.cursor() as curseur:
                curseur.execute("TRUNCATE analyzer.capture_sessions CASCADE")
            connexion.commit()

    def purger(self, jours: int = 30) -> int:
        """Supprime les sessions plus anciennes que la durée de conservation.

        La cascade emporte leurs paquets, communications et détections. Le compte rendu
        est celui des sessions supprimées : c'est la seule mesure qui dit si la purge a
        réellement fait quelque chose — un « 0 » est une information, pas un échec.
        """
        if jours <= 0:
            raise ValueError("La durée de conservation doit être positive")
        with self._verrou, self._connexion() as connexion:
            with connexion.cursor() as curseur:
                curseur.execute("""
                    DELETE FROM analyzer.capture_sessions
                     WHERE debut < now() - make_interval(days => %s)
                """, (jours,))
                supprimees = curseur.rowcount
            connexion.commit()
        if supprimees:
            logger.info("Purge : %d session(s) de plus de %d jours supprimée(s)",
                        supprimees, jours)
        return supprimees


#: Colonnes d'une communication, dans l'ordre attendu par `_ligne_vers_communication`.
_COLONNES_COMMUNICATION = """
    cle, protocole, host(ip_a), host(ip_b), port_a, port_b, host(initiateur),
    debut, dernier_paquet, termine_le, duree_secondes,
    paquets_a_vers_b, paquets_b_vers_a, octets_a_vers_b, octets_b_vers_a,
    indicateurs, etat, etat_certain, note_etat, vu_depuis_le_debut
"""


def _ligne_vers_communication(ligne) -> dict[str, Any]:
    """Traduit une ligne de `flows` dans la forme attendue par l'interface.

    La traduction existe parce que le vocabulaire de la base et celui de l'API diffèrent
    volontairement : la base dit `flows`, l'énoncé dit « communications » ; la base dit
    `alerts`, l'interface dit « détections ». Quelque chose doit faire le pont, et il vaut
    mieux que ce soit un seul endroit qu'une convention implicite partout.
    """
    return {
        "cle": ligne[0], "protocole": ligne[1], "ip_a": ligne[2], "ip_b": ligne[3],
        "port_a": ligne[4], "port_b": ligne[5], "initiateur": ligne[6],
        "debut": ligne[7].isoformat() if ligne[7] else "",
        "dernier_paquet": ligne[8].isoformat() if ligne[8] else "",
        "termine_le": ligne[9].isoformat() if ligne[9] else None,
        "duree_secondes": float(ligne[10] or 0),
        "paquets_a_vers_b": ligne[11], "paquets_b_vers_a": ligne[12],
        "paquets_total": ligne[11] + ligne[12],
        "octets_a_vers_b": ligne[13], "octets_b_vers_a": ligne[14],
        "octets_total": ligne[13] + ligne[14],
        "indicateurs": ligne[15], "etat": ligne[16], "etat_certain": ligne[17],
        "note_etat": ligne[18], "vu_depuis_le_debut": ligne[19],
    }

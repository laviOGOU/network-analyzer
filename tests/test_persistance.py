"""Tests de la persistance PostgreSQL (phase 5).

CES TESTS SONT D'UNE AUTRE NATURE QUE LES PRÉCÉDENTS
----------------------------------------------------
Tous les autres tests du projet tournent sans rien installer : c'est un choix, et il est
tenu. Ceux-ci ont besoin d'un PostgreSQL joignable — ils sont donc **ignorés** quand la
variable `ANALYZER_DATABASE_URL_TEST` n'est pas définie, et la suite reste verte sur une
machine sans base de données.

C'est délibéré : un projet qui ne se teste que sur la machine de son auteur n'est pas
testable. La variable indique une base **de test**, distincte de toute base de production,
et le préfixe du nom est vérifié — une purge ou un vidage ne doit jamais pouvoir tomber
sur des données réelles.

    ANALYZER_DATABASE_URL_TEST=postgresql://...@127.0.0.1:5432/analyzer_pytest

CE QUI EST ÉPROUVÉ ICI, ET QUI NE PEUT PAS L'ÊTRE EN MÉMOIRE
------------------------------------------------------------
L'`UPSERT`. Une communication revue met à jour sa ligne au lieu d'en créer une seconde ;
c'est la contrainte d'unicité du schéma qui le garantit, pas le code Python. Une
implémentation en mémoire vérifie qu'un dictionnaire ne double pas ; celle-ci vérifie que
**la base** ne double pas — ce qui est la seule garantie qui compte en production.

La purge et la cascade : supprimer une session doit emporter ses paquets, ses
communications et ses détections. Un `DELETE` qui laisserait des lignes orphelines
grossirait la base en silence pendant des mois.
"""

from __future__ import annotations

import os
import uuid

import pytest

URL = os.environ.get("ANALYZER_DATABASE_URL_TEST", "")

pytestmark = pytest.mark.skipif(
    not URL, reason="ANALYZER_DATABASE_URL_TEST absent : tests PostgreSQL ignorés")


@pytest.fixture(scope="module", autouse=True)
def base_de_test():
    """Refuse de tourner sur une base dont le nom ne dit pas qu'elle est de test.

    Ce garde-fou vaut mieux qu'une consigne : une variable mal recopiée pointerait sur la
    base de production, et le premier test appellerait `vider()`.
    """
    if "test" not in URL:
        pytest.fail(
            "ANALYZER_DATABASE_URL_TEST ne désigne pas une base de test : le nom doit "
            "contenir « test ». Ces tests vident les tables."
        )
    return URL


@pytest.fixture
def stockage(base_de_test):
    from backend.stockage_postgres import StockagePostgres

    moteur = StockagePostgres(base_de_test)
    moteur.vider()
    return moteur


def paquet(source="192.168.1.5", destination="93.184.216.34", port=443,
           horodatage="2026-10-05T10:00:00+00:00"):
    return {
        "horodatage": horodatage, "taille": 74, "protocole": "TCP",
        "ip_source": source, "ip_destination": destination,
        "port_source": 51000, "port_destination": port, "flags_tcp": "PA",
        "ttl": 64, "version_ip": 4, "details": {"domaine": "example.com"},
        "analyse_partielle": False,
    }


def communication(session, cle="TCP|a|b", etat="fermée", **remplacements):
    base = {
        "cle": cle, "protocole": "TCP", "ip_a": "93.184.216.34", "ip_b": "192.168.1.5",
        "port_a": 443, "port_b": 51000, "initiateur": "192.168.1.5",
        "debut": "2026-10-05T10:00:00+00:00", "dernier_paquet": "2026-10-05T10:00:05+00:00",
        "termine_le": None, "duree_secondes": 5.0,
        "paquets_a_vers_b": 6, "paquets_b_vers_a": 5,
        "octets_a_vers_b": 4000, "octets_b_vers_a": 900,
        "indicateurs": "SYN, SYN-ACK, ACK", "etat": etat, "etat_certain": True,
        "note_etat": "", "vu_depuis_le_debut": True,
    }
    base.update(remplacements)
    return base


def detection(niveau="observation", regle="scan_ports", cible="192.168.1.5", **remplacements):
    base = {
        "regle": regle, "famille": "balayage", "niveau": niveau,
        "titre": "20 ports contactés", "faits_observes": ["20 ports en 20 secondes"],
        "explication": "Une machine a tenté d'ouvrir des connexions sur de nombreux ports.",
        "confiance": "moyenne",
        "faux_positifs": "Un scanner volontaire, un logiciel qui cherche son serveur.",
        "cible": cible, "debut": "2026-10-05T10:00:00+00:00",
        "dernier": "2026-10-05T10:00:20+00:00", "occurrences": 1,
    }
    base.update(remplacements)
    return base


# --------------------------------------------------------------------------- #
#  L'écriture, et la relecture
# --------------------------------------------------------------------------- #
def test_un_lot_est_conserve(stockage):
    """Ce que la phase 1 gardait en mémoire doit survivre à l'écriture en base."""
    assert stockage.enregistrer_lot("session-1", "poste-ogou", [paquet(), paquet(port=80)]) == 2
    paquets = stockage.paquets(limite=10)
    assert len(paquets) == 2
    assert {p["port_destination"] for p in paquets} == {443, 80}
    assert paquets[0]["details"]["domaine"] == "example.com"


def test_les_statistiques_refletent_la_base(stockage):
    stockage.enregistrer_lot("session-1", "poste-ogou", [paquet(), paquet(), paquet(port=80)])
    statistiques = stockage.statistiques()
    assert statistiques["paquets_total"] == 3
    assert statistiques["par_protocole"] == {"TCP": 3}
    assert statistiques["stockage"] == "postgresql"


def test_une_session_est_creee_automatiquement(stockage):
    stockage.enregistrer_lot("session-du-matin", "poste-ogou", [paquet()])
    session = stockage.session("session-du-matin")
    assert session is not None
    assert session["agent"] == "poste-ogou"
    assert session["paquets"] == 1


def test_le_meme_libelle_designe_la_meme_session(stockage):
    """Un libellé doit se traduire en identifiant de façon stable.

    Sans cette stabilité, « capture-du-matin » créerait une session différente à chaque
    exécution, et l'historique deviendrait illisible.
    """
    from backend.stockage_postgres import identifiant_session

    assert identifiant_session("capture-du-matin") == identifiant_session("capture-du-matin")
    assert identifiant_session("capture-du-matin") != identifiant_session("capture-du-soir")
    # Un véritable identifiant est conservé tel quel, aux minuscules près.
    vrai = str(uuid.uuid4())
    assert identifiant_session(vrai) == vrai


# --------------------------------------------------------------------------- #
#  L'UPSERT : ce que la mémoire ne peut pas prouver
# --------------------------------------------------------------------------- #
def test_une_communication_revue_ne_se_duplique_pas(stockage):
    """C'est la contrainte d'unicité du schéma qui l'empêche, pas le code Python."""
    stockage.enregistrer_lot("s", "poste", [paquet()])
    stockage.enregistrer_communications("s", [communication("s", paquets_a_vers_b=6)])
    stockage.enregistrer_communications("s", [communication("s", paquets_a_vers_b=40,
                                                            paquets_b_vers_a=12)])
    liste = stockage.communications(limite=10)
    assert len(liste) == 1, "la même communication a produit deux lignes"
    assert liste[0]["paquets_a_vers_b"] == 40      # la dernière version fait foi


def test_deux_sessions_ne_se_melangent_pas(stockage):
    """Même clé, sessions différentes : deux lignes distinctes."""
    stockage.enregistrer_communications("capture-1", [communication("capture-1")])
    stockage.enregistrer_communications("capture-2", [communication("capture-2")])
    assert len(stockage.communications(limite=10)) == 2
    assert len(stockage.communications(limite=10, session="capture-1")) == 1


def test_une_detection_revue_met_a_jour_son_compteur(stockage):
    stockage.enregistrer_detections("s", [detection(occurrences=1)])
    stockage.enregistrer_detections("s", [detection(occurrences=7)])
    liste = stockage.detections(limite=10)
    assert len(liste) == 1
    assert liste[0]["occurrences"] == 7


def test_les_detections_conservent_leurs_faux_positifs(stockage):
    """Le champ qui rend une détection utilisable ne doit pas se perdre en base."""
    stockage.enregistrer_detections("s", [detection()])
    liste = stockage.detections(limite=10)
    assert "scanner volontaire" in liste[0]["faux_positifs"]
    assert liste[0]["faits_observes"]
    assert liste[0]["regle"] == "scan_ports"


def test_les_trois_niveaux_sont_conserves(stockage):
    for niveau in ("observation", "hypothèse", "alerte"):
        stockage.enregistrer_detections("s", [detection(niveau=niveau, regle=f"r_{niveau}",
                                                        titre=f"titre {niveau}")])
    niveaux = {d["niveau"] for d in stockage.detections(limite=20)}
    assert niveaux == {"observation", "hypothèse", "alerte"}
    assert len(stockage.detections(limite=20, niveau="alerte")) == 1


# --------------------------------------------------------------------------- #
#  La purge et la cascade
# --------------------------------------------------------------------------- #
def test_la_purge_emporte_tout_ce_qui_depend(stockage):
    """Supprimer une session ancienne doit emporter ses paquets, communications et
    détections : une cascade incomplète grossirait la base en silence pendant des mois."""
    with stockage._connexion() as connexion, connexion.cursor() as curseur:
        curseur.execute("""
            INSERT INTO analyzer.capture_sessions (id, agent, debut)
            VALUES (gen_random_uuid(), 'poste-ancien', now() - interval '60 days')
        """)
        curseur.execute("SELECT id FROM analyzer.capture_sessions "
                        "WHERE agent = 'poste-ancien'")
        ancienne = curseur.fetchone()[0]
        curseur.execute("""
            INSERT INTO analyzer.packets (session_id, horodatage, protocole)
            VALUES (%s, now() - interval '60 days', 'TCP')
        """, (ancienne,))
        connexion.commit()

    stockage.enregistrer_lot("session-recente", "poste-ogou", [paquet()])

    supprimees = stockage.purger(jours=30)
    assert supprimees == 1
    assert stockage.session("session-recente") is not None
    with stockage._connexion() as connexion, connexion.cursor() as curseur:
        curseur.execute("SELECT count(*) FROM analyzer.packets WHERE session_id = %s",
                        (ancienne,))
        assert curseur.fetchone()[0] == 0, "des paquets orphelins subsistent"


def test_la_purge_refuse_une_duree_nulle(stockage):
    """Une durée nulle supprimerait tout : mieux vaut refuser que faire une bêtise."""
    with pytest.raises(ValueError):
        stockage.purger(jours=0)


def test_la_purge_ne_touche_pas_les_donnees_recentes(stockage):
    stockage.enregistrer_lot("recente", "poste", [paquet()])
    assert stockage.purger(jours=30) == 0
    assert stockage.statistiques()["paquets_total"] == 1


# --------------------------------------------------------------------------- #
#  Ce que la base doit refuser
# --------------------------------------------------------------------------- #
def test_une_adresse_illisible_est_ecartee_sans_faire_echouer_le_lot(stockage):
    """Une seule adresse abîmée ne doit pas faire perdre les cent autres du lot.

    Le type `inet` de PostgreSQL refuse une adresse malformée en levant une erreur : sans
    filtrage en amont, un paquet abîmé ferait échouer tout un lot.
    """
    abimes = [paquet(), {**paquet(), "ip_source": "pas une adresse"}, paquet(port=80)]
    assert stockage.enregistrer_lot("s", "poste", abimes) == 3
    paquets = stockage.paquets(limite=10)
    assert len(paquets) == 3
    assert sum(1 for p in paquets if p["ip_source"] is None) == 1


def test_une_communication_sans_cle_est_ecartee(stockage):
    stockage.enregistrer_lot("s", "poste", [paquet()])
    assert stockage.enregistrer_communications("s", [{**communication("s"), "cle": ""}]) == 0


def test_les_filtres_de_lecture_fonctionnent(stockage):
    stockage.enregistrer_lot("s", "poste", [paquet(port=443), paquet(port=80)])
    assert len(stockage.paquets(limite=10, protocole="TCP")) == 2
    assert len(stockage.paquets(limite=10, protocole="UDP")) == 0
    assert len(stockage.paquets(limite=10, recherche="443")) == 1
    assert len(stockage.paquets(limite=10, recherche="example.com")) == 2


def test_un_filtre_hostile_ne_touche_pas_la_base(stockage):
    """La question de l'injection, posée à une vraie base au lieu d'être supposée.

    Les critères sont des données : les valeurs deviennent des paramètres liés, jamais du
    SQL. Le test le vérifie de la seule façon qui compte — en exécutant la tentative contre
    PostgreSQL, et en constatant que la base est intacte et la réponse vide.
    """
    from backend import filtres

    stockage.enregistrer_lot("s", "poste", [paquet()])
    avant = stockage.statistiques()["paquets_total"]

    tentatives = [
        "texte:\"'; DROP TABLE analyzer.packets; --\"",
        "texte:\"tcp' OR 1=1 --\"",
        "ip:\"1.1.1.1' UNION SELECT * FROM analyzer.alerts --\"",
        "proto:\"tcp'; DELETE FROM analyzer.flows; --\"",
        "texte:\"%' OR '1'='1\"",
    ]

    refusees = 0
    for tentative in tentatives:
        try:
            criteres = filtres.analyser(tentative)
        except filtres.ErreurFiltre:
            # Premier niveau : le parseur a refusé la valeur. Une adresse qui contient
            # « UNION SELECT » n'est pas une adresse, et elle est rejetée comme telle.
            refusees += 1
            continue
        # Second niveau : le critère est passé, mais la valeur devient un paramètre lié.
        # La requête s'exécute, ne trouve rien, et ne modifie rien.
        resultats = stockage.paquets(limite=10, filtre=criteres)
        assert resultats == [], f"« {tentative} » a ramené des lignes"

    # Les deux niveaux de défense doivent jouer : au moins une tentative bloquée par la
    # validation, et aucune n'atteint la base sous forme de SQL.
    assert refusees >= 1, "aucune tentative n'a été refusée par la validation"

    # Les tables sont intactes : la base répond toujours, et les données sont là.
    assert stockage.statistiques()["paquets_total"] == avant
    assert len(stockage.paquets(limite=10)) == 1
    assert stockage.session("s") is not None


def test_le_filtre_de_la_base_donne_les_memes_lignes_qu_en_memoire(stockage):
    """Le même filtre, appliqué par SQL et par Python, doit donner le même résultat.

    Les deux chemins sont écrits séparément — une comparaison SQL d'un côté, une fonction
    Python de l'autre. Rien ne garantit qu'ils restent d'accord, sinon ce test : sans lui,
    une installation en mémoire et une installation PostgreSQL afficheraient des listes
    différentes pour le même filtre, et personne ne saurait laquelle croire.
    """
    from backend import filtres
    from backend.storage import Stockage

    paquets = [paquet(port=443), paquet(port=80), paquet(port=443, source="10.0.0.9")]
    stockage.enregistrer_lot("s", "poste", paquets)

    memoire = Stockage(taille_max=100)
    memoire.enregistrer_lot("s", "poste", paquets)

    for expression in ("proto:tcp", "port:443", "ip:10.0.0.9", "taille:>10"):
        criteres = filtres.analyser(expression)
        par_sql = stockage.paquets(limite=10, filtre=criteres)
        par_python = memoire.paquets(limite=10, filtre=criteres)
        assert len(par_sql) == len(par_python), \
            f"« {expression} » : {len(par_sql)} lignes en base, {len(par_python)} en mémoire"


def test_le_stockage_se_vide(stockage):
    stockage.enregistrer_lot("s", "poste", [paquet()])
    stockage.enregistrer_communications("s", [communication("s")])
    stockage.enregistrer_detections("s", [detection()])
    stockage.vider()
    assert stockage.statistiques()["paquets_total"] == 0
    assert stockage.communications(limite=10) == []
    assert stockage.detections(limite=10) == []

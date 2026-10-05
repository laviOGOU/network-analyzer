"""Tests des communications vues par l'API (phase 2).

Ce qui est vérifié ici : les communications arrivent jusqu'au backend, y sont refondues
par clé (et non dupliquées), ressortent filtrables, et une donnée incohérente est refusée
à l'entrée.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.config import configuration
from backend.dependances import obtenir_stockage
from backend.main import application
from backend.storage import Stockage

JETON = configuration.jeton_agent


def communication(**remplacements) -> dict:
    """Communication valide minimale, à modifier selon le test."""
    base = {
        "cle": "TCP|10.0.0.5:49703|93.184.216.34:443",
        "protocole": "TCP",
        "ip_a": "10.0.0.5", "ip_b": "93.184.216.34",
        "port_a": 49703, "port_b": 443,
        "initiateur": "10.0.0.5",
        "vu_depuis_le_debut": True,
        "debut": "2026-10-05T12:00:00+00:00",
        "dernier_paquet": "2026-10-05T12:00:02+00:00",
        "duree_secondes": 2.0,
        "paquets_a_vers_b": 2, "paquets_b_vers_a": 1, "paquets_total": 3,
        "octets_a_vers_b": 172, "octets_b_vers_a": 86, "octets_total": 258,
        "indicateurs": "SYN, ACK",
        "etat": "établie",
        "etat_certain": True,
        "note_etat": "Ouverture complète observée (SYN, SYN-ACK, ACK).",
    }
    base.update(remplacements)
    return base


def paquet(**remplacements) -> dict:
    base = {"horodatage": "2026-10-05T12:00:00+00:00", "taille": 74, "protocole": "TCP",
            "ip_source": "10.0.0.5", "ip_destination": "93.184.216.34",
            "port_destination": 443}
    base.update(remplacements)
    return base


def envoyer(client: TestClient, communications=None, paquets=None) -> object:
    return client.post("/api/v1/ingest", headers={"X-Agent-Token": JETON},
                       json={"session": "session-flux", "agent": "poste",
                             "paquets": paquets if paquets is not None else [paquet()],
                             "communications": communications or []})


import pytest  # noqa: E402  (placé après les fabriques, pour la lisibilité du fichier)


@pytest.fixture
def stockage() -> Stockage:
    return Stockage(taille_max=50)


@pytest.fixture
def client(stockage):
    application.dependency_overrides[obtenir_stockage] = lambda: stockage
    with TestClient(application) as client_test:
        yield client_test
    application.dependency_overrides.clear()


# --------------------------------------------------------------------------- #
#  Ingestion des communications
# --------------------------------------------------------------------------- #
def test_communication_transmise(client):
    reponse = envoyer(client, communications=[communication()])

    assert reponse.status_code == 200
    assert reponse.json()["communications"] == 1


def test_communication_relue(client):
    envoyer(client, communications=[communication()])

    donnees = client.get("/api/v1/flows").json()

    assert donnees["affichees"] == 1
    flux = donnees["communications"][0]
    assert flux["etat"] == "établie"
    assert flux["etat_certain"] is True
    assert flux["paquets_total"] == 3
    assert flux["octets_total"] == 258
    assert "Ouverture complète" in flux["note_etat"]


def test_une_communication_est_refondue_et_non_dupliquee(client):
    """L'agent revoit la même conversation évoluer : la dernière version fait foi.

    Sans cette règle, chaque lot créerait une nouvelle communication et le tableau de
    bord afficherait la même conversation des dizaines de fois.
    """
    envoyer(client, communications=[communication()])
    envoyer(client, communications=[communication(paquets_a_vers_b=5, paquets_total=6,
                                                 octets_a_vers_b=900, octets_total=986,
                                                 etat="fermée", etat_certain=True,
                                                 note_etat="Fermeture ordonnée observée.")])

    donnees = client.get("/api/v1/flows").json()

    assert donnees["affichees"] == 1
    assert donnees["communications"][0]["etat"] == "fermée"
    assert donnees["communications"][0]["paquets_total"] == 6
    # Le total cumulé des communications vues ne compte pas les mises à jour.
    assert donnees["statistiques"]["communications_total"] == 1


def test_communications_separees_par_cle(client):
    envoyer(client, communications=[
        communication(),
        communication(cle="TCP|10.0.0.5:49704|93.184.216.34:443",
                      port_a=49704, etat="tentative", etat_certain=True),
    ])

    assert client.get("/api/v1/flows").json()["affichees"] == 2


# --------------------------------------------------------------------------- #
#  Filtres
# --------------------------------------------------------------------------- #
def test_deux_sessions_ne_se_melangent_pas(client):
    """Deux captures observant la même conversation doivent rester distinctes.

    Indexer sur la seule clé ferait écraser la première par la seconde : le tableau de
    bord attribuerait à une capture les chiffres d'une autre.
    """
    commun = dict(cle="TCP|a|b", protocole="TCP", ip_a="10.0.0.5", ip_b="93.184.216.34",
                  port_a=49703, port_b=443, initiateur="10.0.0.5")
    client.post("/api/v1/ingest", headers={"X-Agent-Token": JETON},
                json={"session": "capture-du-matin", "agent": "poste", "paquets": [paquet()],
                      "communications": [communication(**commun)]})
    client.post("/api/v1/ingest", headers={"X-Agent-Token": JETON},
                json={"session": "capture-du-soir", "agent": "poste", "paquets": [paquet()],
                      "communications": [communication(paquets_a_vers_b=9, paquets_b_vers_a=4,
                                                      paquets_total=13, octets_a_vers_b=900,
                                                      octets_b_vers_a=400, octets_total=1300,
                                                      **commun)]})

    toutes = client.get("/api/v1/flows").json()
    matin = client.get("/api/v1/flows?session=capture-du-matin").json()

    # Deux lignes, et non une seule écrasée par la seconde capture.
    assert toutes["affichees"] == 2
    assert matin["affichees"] == 1
    assert matin["communications"][0]["paquets_total"] == 3
    assert matin["communications"][0]["session"] == "capture-du-matin"


def test_le_filtre_du_journal_est_precis():
    """Le filtre doit taire une erreur de Windows sans masquer les vraies pannes.

    Un filtre trop large serait plus dangereux que le bruit qu'il supprime : il cacherait
    une panne réelle au moment précis où on la cherche.
    """
    import logging
    from backend.main import FiltreFermeturesBrutales

    filtre = FiltreFermeturesBrutales()

    def enregistrement(message, erreur=None, *arguments):
        """Reproduit fidèlement ce qu'asyncio écrit : le type d'erreur est dans exc_info,
        et le message ne contient que le nom de la fonction de rappel."""
        return logging.LogRecord(
            "asyncio", logging.ERROR, __file__, 1, message, arguments,
            exc_info=(type(erreur), erreur, None) if erreur else None)

    # Celle-là doit être tue : fermeture brutale, pendant le nettoyage de la connexion.
    assert filtre.filter(enregistrement(
        "Exception in callback _ProactorBasePipeTransport._call_connection_lost(None)",
        ConnectionResetError(10054, "Connexion fermée par l'hôte distant"))) is False

    # Les autres doivent passer : c'est ce qui distingue un filtre d'un bandeau.
    assert filtre.filter(enregistrement(
        "Exception in callback _ProactorBasePipeTransport._call_connection_lost(None)",
        ValueError("autre problème"))) is True
    assert filtre.filter(enregistrement(
        "Exception in callback Application.__call__", ValueError("vraie panne"))) is True
    assert filtre.filter(enregistrement(
        "Une erreur quelconque sans contexte", ConnectionResetError(10054, "ailleurs"))) is True


def test_filtre_par_etat(client):
    envoyer(client, communications=[
        communication(),
        communication(cle="TCP|a|b", ip_a="10.0.0.9", ip_b="10.0.0.10",
                      etat="tentative", etat_certain=False),
    ])

    etablies = client.get("/api/v1/flows?etat=établie").json()

    assert etablies["affichees"] == 1
    assert etablies["communications"][0]["etat"] == "établie"


def test_filtre_par_protocole(client):
    envoyer(client, communications=[
        communication(),
        communication(cle="UDP|a|b", protocole="UDP", ip_a="10.0.0.9", ip_b="10.0.0.10",
                      port_a=53000, port_b=53, etat="en cours"),
    ])

    udp = client.get("/api/v1/flows?protocole=UDP").json()

    assert udp["affichees"] == 1
    assert udp["communications"][0]["protocole"] == "UDP"


def test_recherche_par_adresse(client):
    envoyer(client, communications=[communication()])

    assert client.get("/api/v1/flows?recherche=93.184").json()["affichees"] == 1
    assert client.get("/api/v1/flows?recherche=introuvable").json()["affichees"] == 0


def test_limite_borne(client):
    assert client.get("/api/v1/flows?limite=99999").status_code == 422


# --------------------------------------------------------------------------- #
#  Validation
# --------------------------------------------------------------------------- #
def test_totaux_incoherents_refuses(client):
    """Un total qui ne correspond pas à la somme des deux sens signalerait un défaut de
    calcul côté agent : mieux vaut le refuser que d'afficher un chiffre faux."""
    reponse = envoyer(client, communications=[communication(paquets_total=99)])

    assert reponse.status_code == 422
    assert "somme des deux sens" in reponse.text


def test_adresse_invalide_refusee(client):
    reponse = envoyer(client, communications=[communication(ip_b="999.1.1.1")])

    assert reponse.status_code == 422
    assert "adresse IP invalide" in reponse.text


def test_champ_inconnu_refuse(client):
    reponse = envoyer(client, communications=[communication(champ_invente=1)])

    assert reponse.status_code == 422


def test_statistiques_par_etat(client):
    envoyer(client, communications=[
        communication(),
        communication(cle="TCP|x|y", ip_a="10.0.0.9", ip_b="10.0.0.10",
                      etat="tentative", etat_certain=False),
    ])

    stats = client.get("/api/v1/stats").json()

    assert stats["communications_total"] == 2
    assert stats["communications_par_etat"]["établie"] == 1
    assert stats["communications_incertaines"] == 1


def test_lot_sans_communication_reste_valide(client):
    """Les paquets seuls restent acceptés : les communications sont un complément."""
    reponse = envoyer(client, communications=[])

    assert reponse.status_code == 200
    assert reponse.json()["communications"] == 0
    assert client.get("/api/v1/flows").json()["affichees"] == 0

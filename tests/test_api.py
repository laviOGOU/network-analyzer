"""Tests de l'API : droits d'écriture, validation, lecture, limitation de débit.

On utilise le client de test de FastAPI, qui exerce les vraies routes et les vraies
dépendances — pas un serveur lancé à côté. Le stockage est remplacé par un neuf pour
chaque test : sans cela, un test laisserait des paquets qui fausseraient le suivant.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from backend.config import configuration
from backend.dependances import obtenir_stockage
from backend.main import application
from backend.storage import Stockage

JETON = configuration.jeton_agent


def fiche(**remplacements) -> dict:
    base = {"horodatage": datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc).isoformat(),
            "taille": 74, "protocole": "TCP", "ip_source": "192.168.1.5",
            "ip_destination": "93.184.216.34", "port_destination": 443}
    base.update(remplacements)
    return base


@pytest.fixture
def stockage() -> Stockage:
    return Stockage(taille_max=50)


@pytest.fixture
def client(stockage):
    """Client de test avec un stockage isolé, retiré après le test."""
    application.dependency_overrides[obtenir_stockage] = lambda: stockage
    with TestClient(application) as client_test:
        yield client_test
    application.dependency_overrides.clear()


# --------------------------------------------------------------------------- #
#  Lecture : publique
# --------------------------------------------------------------------------- #
def test_sante_sans_jeton(client):
    """Le contrôle de disponibilité doit répondre sans authentification."""
    reponse = client.get("/api/v1/health")

    assert reponse.status_code == 200
    assert reponse.json()["etat"] == "ok"


def test_page_principale(client):
    """La page est servie, et elle porte l'identité du site.

    Ce test a fait son travail : le site a été renommé sans lui, et il a échoué. On en profite
    pour vérifier aussi les repères de la page — la bannière d'accueil et les vues — plutôt
    qu'une seule chaîne. Une page qui se servirait vide passerait le contrôle du nom si le nom
    figurait dans un coin.
    """
    reponse = client.get("/")

    assert reponse.status_code == 200
    assert "FlowScope" in reponse.text
    assert "Bienvenue sur FlowScope" in reponse.text
    assert 'class="vue-onglet"' in reponse.text


def test_paquets_vides(client):
    reponse = client.get("/api/v1/packets")

    assert reponse.status_code == 200
    assert reponse.json()["paquets"] == []
    assert reponse.json()["statistiques"]["paquets_total"] == 0


def test_limite_hors_bornes_refusee(client):
    """`?limite=99999` demanderait une réponse énorme : la borne est là pour ça."""
    assert client.get("/api/v1/packets?limite=99999").status_code == 422
    assert client.get("/api/v1/packets?limite=0").status_code == 422


def test_adresse_inconnue_rend_du_json_pour_une_api(client):
    reponse = client.get("/api/v1/route-qui-nexiste-pas", headers={"Accept": "application/json"})

    assert reponse.status_code in (404, 405)
    assert reponse.headers["content-type"].startswith("application/json")


# --------------------------------------------------------------------------- #
#  Écriture : protégée
# --------------------------------------------------------------------------- #
def test_ingestion_sans_jeton_refusee(client):
    reponse = client.post("/api/v1/ingest",
                          json={"session": "s", "agent": "a", "paquets": [fiche()]})

    assert reponse.status_code == 401
    assert "jeton" in reponse.json()["detail"].lower()


def test_ingestion_jeton_faux_refuse(client):
    reponse = client.post("/api/v1/ingest", headers={"X-Agent-Token": "mauvais-jeton"},
                          json={"session": "s", "agent": "a", "paquets": [fiche()]})

    assert reponse.status_code == 401


def test_ingestion_jeton_valide_acceptee(client, stockage):
    reponse = client.post("/api/v1/ingest", headers={"X-Agent-Token": JETON},
                          json={"session": "session-1", "agent": "poste",
                                "paquets": [fiche(), fiche(protocole="UDP",
                                                           port_destination=53)]})

    assert reponse.status_code == 200
    corps = reponse.json()
    assert corps["acceptes"] == 2
    assert corps["session"] == "session-1"
    assert corps["total_session"] == 2
    # On relit dans le stockage, pas dans la réponse : c'est la donnée écrite qui compte.
    assert stockage.statistiques()["paquets_total"] == 2


def test_ingestion_compte_les_paquets_par_lot(client, stockage):
    for indice in range(3):
        client.post("/api/v1/ingest", headers={"X-Agent-Token": JETON},
                    json={"session": "s", "agent": "a", "paquets": [fiche()]})

    assert stockage.statistiques()["paquets_total"] == 3
    assert stockage.session("s")["paquets"] == 3


def test_ingestion_refuse_un_paquet_invalide(client, stockage):
    """Une adresse impossible fait échouer le lot, et rien n'est écrit."""
    reponse = client.post("/api/v1/ingest", headers={"X-Agent-Token": JETON},
                          json={"session": "s", "agent": "a",
                                "paquets": [fiche(ip_source="999.1.1.1")]})

    assert reponse.status_code == 422
    assert "adresse IP invalide" in reponse.text
    assert stockage.statistiques()["paquets_total"] == 0


def test_ingestion_refuse_un_lot_vide(client):
    reponse = client.post("/api/v1/ingest", headers={"X-Agent-Token": JETON},
                          json={"session": "s", "agent": "a", "paquets": []})

    assert reponse.status_code == 422


# --------------------------------------------------------------------------- #
#  Statistiques et sessions
# --------------------------------------------------------------------------- #
def test_statistiques_apres_ingestion(client):
    client.post("/api/v1/ingest", headers={"X-Agent-Token": JETON},
                json={"session": "s", "agent": "a",
                      "paquets": [fiche(protocole="TCP"), fiche(protocole="TCP"),
                                  fiche(protocole="DNS", port_destination=53)]})

    stats = client.get("/api/v1/stats").json()

    assert stats["paquets_total"] == 3
    assert stats["par_protocole"]["TCP"] == 2
    assert stats["par_protocole"]["DNS"] == 1
    # Les ports sont comptés côté destination : 443 deux fois, 53 une fois.
    ports = {entree["valeur"]: entree["nombre"] for entree in stats["ports_frequents"]}
    assert ports[443] == 2 and ports[53] == 1


def test_filtre_par_protocole(client):
    client.post("/api/v1/ingest", headers={"X-Agent-Token": JETON},
                json={"session": "s", "agent": "a",
                      "paquets": [fiche(protocole="TCP"), fiche(protocole="DNS")]})

    reponse = client.get("/api/v1/packets?protocole=DNS").json()

    assert reponse["affiches"] == 1
    assert reponse["paquets"][0]["protocole"] == "DNS"


def test_recherche_libre(client):
    client.post("/api/v1/ingest", headers={"X-Agent-Token": JETON},
                json={"session": "s", "agent": "a",
                      "paquets": [fiche(details={"dns_question": "exemple.ci"}),
                                  fiche()]})

    assert client.get("/api/v1/packets?recherche=exemple").json()["affiches"] == 1
    assert client.get("/api/v1/packets?recherche=inexistant").json()["affiches"] == 0


def test_sessions_listees(client):
    client.post("/api/v1/ingest", headers={"X-Agent-Token": JETON},
                json={"session": "session-a", "agent": "poste-1", "paquets": [fiche()]})

    reponse = client.get("/api/v1/sessions").json()

    assert reponse["total"] == 1
    assert reponse["sessions"][0]["session"] == "session-a"
    assert reponse["sessions"][0]["agent"] == "poste-1"


# --------------------------------------------------------------------------- #
#  Limitation de débit
# --------------------------------------------------------------------------- #
def test_limitation_de_debit(client, monkeypatch):
    """Au-delà de la limite, l'ingestion répond 429 au lieu d'accepter sans fin."""
    from backend import securite

    monkeypatch.setattr(securite.limiteur, "limite", 3)
    securite.limiteur._historique.clear()

    codes = [client.post("/api/v1/ingest", headers={"X-Agent-Token": JETON},
                         json={"session": "s", "agent": "a", "paquets": [fiche()]}
                         ).status_code for _ in range(5)]

    assert codes[:3] == [200, 200, 200]
    assert codes[3] == 429
    assert codes[4] == 429
    securite.limiteur._historique.clear()

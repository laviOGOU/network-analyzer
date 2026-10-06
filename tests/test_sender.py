"""Tests de la file d'attente et de l'envoi.

Ces tests portent sur le comportement en cas de panne — c'est-à-dire sur ce qui se passe
quand le backend est injoignable, lent ou saturé. C'est la partie de l'agent qui décide si
l'outil tient ou s'écroule, et la seule qu'on ne peut pas vérifier à l'œil pendant une
démonstration.
"""

from __future__ import annotations

import time

import pytest

from agent import sender


def fiche(indice: int = 0) -> dict:
    return {"horodatage": "2026-10-05T12:00:00+00:00", "taille": 74,
            "protocole": "TCP", "port_destination": 443, "id": indice}


def attendre(condition, delai: float = 3.0) -> bool:
    """Attend qu'une condition devienne vraie, sans dormir un temps fixe."""
    limite = time.monotonic() + delai
    while time.monotonic() < limite:
        if condition():
            return True
        time.sleep(0.02)
    return condition()


# --------------------------------------------------------------------------- #
#  File d'attente
# --------------------------------------------------------------------------- #
def test_les_paquets_arrivent_par_lots():
    """Les paquets sont regroupés : une requête pour deux cents paquets, pas deux cents."""
    memoire = sender.EnvoyeurMemoire()
    envoyeur = sender.Envoyeur(memoire)
    envoyeur.demarrer()
    try:
        for indice in range(sender.LOT_MAX + 5):
            envoyeur.ajouter(fiche(indice))
        assert attendre(lambda: envoyeur.stats.envoyes >= sender.LOT_MAX)
    finally:
        envoyeur.arreter()

    assert len(memoire.paquets) == sender.LOT_MAX + 5
    assert len(memoire.lots) >= 2          # au moins un lot plein, puis le reste


def test_un_petit_nombre_part_apres_le_delai():
    """Trois paquets isolés ne doivent pas rester en attente indéfiniment."""
    memoire = sender.EnvoyeurMemoire()
    envoyeur = sender.Envoyeur(memoire)
    envoyeur.demarrer()
    try:
        for indice in range(3):
            envoyeur.ajouter(fiche(indice))
        assert attendre(lambda: len(memoire.paquets) == 3, delai=5)
    finally:
        envoyeur.arreter()


def test_l_arret_vide_la_file():
    """À l'arrêt, ce qui reste en attente est transmis : on ne perd pas la fin."""
    memoire = sender.EnvoyeurMemoire()
    envoyeur = sender.Envoyeur(memoire)
    for indice in range(7):
        envoyeur.ajouter(fiche(indice))     # sans démarrer le fil : rien n'est parti

    envoyeur.arreter(vider=True)

    assert len(memoire.paquets) == 7


def test_la_file_ne_grandit_pas_sans_fin(monkeypatch):
    """Au-delà de la taille maximale, les plus anciens sont abandonnés et comptés.

    On préfère perdre les paquets les plus vieux : un outil de surveillance doit montrer
    ce qui se passe maintenant. Et l'abandon est chiffré, jamais passé sous silence.
    """
    monkeypatch.setattr(sender, "TAILLE_FILE", 10)
    envoyeur = sender.Envoyeur(sender.EnvoyeurMemoire())     # jamais démarré : rien ne part

    for indice in range(25):
        envoyeur.ajouter(fiche(indice))

    assert envoyeur.stats.abandonnes == 15
    assert envoyeur.stats.file <= 10


def test_un_ajout_ne_leve_jamais(monkeypatch):
    """La capture ne doit pas s'arrêter parce que la file est pleine.

    Si `ajouter` levait une exception, elle remonterait dans le fil de capture de Scapy et
    arrêterait tout l'agent : un backend saturé ferait taire la surveillance.
    """
    monkeypatch.setattr(sender, "TAILLE_FILE", 3)
    envoyeur = sender.Envoyeur(sender.EnvoyeurMemoire())

    for indice in range(10):
        envoyeur.ajouter(fiche(indice))      # aucune exception attendue
    assert envoyeur.stats.recus == 10


# --------------------------------------------------------------------------- #
#  Panne du backend
# --------------------------------------------------------------------------- #
def test_un_echec_est_compte_et_ne_fait_pas_tomber_l_agent():
    """Backend injoignable : l'échec est compté, l'agent continue de fonctionner."""
    appels = {"nombre": 0}

    def destination_qui_echoue(lot):
        appels["nombre"] += 1
        raise ConnectionError("backend injoignable")

    envoyeur = sender.Envoyeur(destination_qui_echoue)
    envoyeur.demarrer()
    try:
        for indice in range(5):
            envoyeur.ajouter(fiche(indice))
        assert attendre(lambda: envoyeur.stats.echecs >= 1, delai=5)
    finally:
        envoyeur.arreter()

    assert envoyeur.stats.echecs >= 1
    assert "ConnectionError" in envoyeur.stats.dernier_echec
    assert envoyeur.stats.envoyes == 0


def test_le_dernier_echec_est_conserve_pour_l_interface():
    """Le motif du dernier échec est lisible : il finit affiché, pas seulement journalisé."""
    envoyeur = sender.Envoyeur(lambda lot: (_ for _ in ()).throw(TimeoutError("délai dépassé")))
    envoyeur._transmettre([fiche()])

    assert "délai dépassé" in envoyeur.stats.dernier_echec


# --------------------------------------------------------------------------- #
#  Client HTTP
# --------------------------------------------------------------------------- #
def test_charge_utile_envoyee(monkeypatch):
    """Le client construit la charge attendue, avec le jeton dans l'en-tête."""
    capture = {}

    class FausseReponse:
        status_code = 200
        def raise_for_status(self):
            return None

    def faux_post(url, json=None, headers=None, timeout=None):
        capture.update({"url": url, "json": json, "headers": headers, "timeout": timeout})
        return FausseReponse()

    monkeypatch.setattr(sender.httpx, "post", faux_post)
    client = sender.ClientBackend("http://exemple.test", "jeton-secret",
                                  nom_agent="poste", session="session-1")
    client.envoyer([fiche(1)])

    assert capture["url"] == "http://exemple.test/api/v1/ingest"
    assert capture["headers"]["X-Agent-Token"] == "jeton-secret"
    assert capture["json"]["session"] == "session-1"
    assert capture["json"]["agent"] == "poste"
    assert len(capture["json"]["paquets"]) == 1
    # Le delai a change (5 s ne suffisaient pas face a une base distante, voir sender.py).
    # Ce controle ne fixe donc plus de valeur : il verifie que le client transmet BIEN
    # SON delai. Un test qui epingle un nombre casse au premier reglage et n'apprend rien.
    assert capture["timeout"] == client.delai            # un délai est toujours posé


def test_une_reponse_erreur_leve(monkeypatch):
    """Un 401 ne doit pas passer pour un succès : les paquets disparaîtraient en silence."""
    class ReponseRefusee:
        status_code = 401
        def raise_for_status(self):
            raise sender.httpx.HTTPStatusError("401", request=None, response=None)

    monkeypatch.setattr(sender.httpx, "post", lambda *a, **k: ReponseRefusee())
    client = sender.ClientBackend("http://exemple.test", "mauvais-jeton")

    with pytest.raises(sender.httpx.HTTPStatusError):
        client.envoyer([fiche()])

    # La file doit avoir compté l'échec plutôt que d'avoir cru à un envoi
    envoyeur = sender.Envoyeur(client.envoyer)
    envoyeur._transmettre([fiche()])
    assert envoyeur.stats.echecs == 1
    assert envoyeur.stats.envoyes == 0


def test_adresse_sans_barre_finale():
    """Une adresse terminée par « / » ne doit pas produire un « // » dans l'URL."""
    client = sender.ClientBackend("http://exemple.test/", "jeton")

    assert client.url == "http://exemple.test"

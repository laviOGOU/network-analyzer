"""Tests de l'association DNS → connexion (Lot B).

DEUX PROPRIÉTÉS COMPTENT
------------------------
1. **Le nom vient du réseau observé, jamais d'un annuaire.** Aucune requête externe n'est
   émise : les noms sont relus dans les réponses DNS déjà conservées. Un test fabrique ces
   réponses et vérifie que l'index en sort.
2. **L'adresse n'est jamais remplacée.** Le nom s'ajoute à côté. Un affichage qui
   remplacerait l'adresse rendrait impossible la vérification de ce qui a réellement été
   observé — et un outil d'analyse dont on ne peut pas vérifier les dires ne sert à rien.
"""

from __future__ import annotations

import time

from backend import noms


def paquet_dns(adresse, nom, horodatage="2026-10-05T10:00:00+00:00", reponse=True):
    details = {"dns_adresse": adresse}
    if reponse:
        details["dns_reponse_nom"] = nom
        details["dns_question"] = nom
    else:
        details["dns_question"] = nom
    return {"horodatage": horodatage, "protocole": "DNS", "details": details}


# --------------------------------------------------------------------------- #
#  L'index
# --------------------------------------------------------------------------- #
def test_un_nom_est_associe_a_son_adresse():
    index = noms.indexer([paquet_dns("93.184.216.34", "example.com")])
    assert index["93.184.216.34"]["nom"] == "example.com"
    assert index["93.184.216.34"]["source"] == "DNS observé"


def test_le_nom_le_plus_recent_gagne():
    """Une adresse partagée change de nom : c'est le dernier vu qui compte.

    Les hébergeurs et les fermes de serveurs portent des dizaines de noms sur une même
    adresse. Le plus récent est celui qui a le plus de chances de correspondre au trafic
    en cours.
    """
    index = noms.indexer([
        paquet_dns("1.2.3.4", "ancien.example.com", "2026-10-05T10:00:00+00:00"),
        paquet_dns("1.2.3.4", "recent.example.com", "2026-10-05T10:05:00+00:00"),
    ])
    assert index["1.2.3.4"]["nom"] == "recent.example.com"


def test_un_paquet_sans_adresse_ou_sans_nom_est_ignore():
    index = noms.indexer([
        paquet_dns(None, "example.com"),
        {"details": {"dns_adresse": "1.2.3.4"}},
        {"details": {}},
        {},
    ])
    assert index == {}


def test_les_noms_invraisemblables_sont_ecartes():
    """Ces valeurs viennent du réseau : elles sont filtrées avant d'être affichées.

    Un nom sans point n'est pas un nom de domaine ; une chaîne de mille caractères est un
    enregistrement détourné ou une donnée malformée. Les afficher dans une colonne serait
    au mieux illisible, au pire trompeur.
    """
    index = noms.indexer([
        paquet_dns("1.1.1.1", "sanspoint"),
        paquet_dns("2.2.2.2", "a" * 200 + ".com"),
        paquet_dns("3.3.3.3", "mauvais\x00nom.com"),
        paquet_dns("4.4.4.4", "espaces dans le nom.com"),
        paquet_dns("5.5.5.5", "espace.example.com"),          # celui-ci est valide
    ])
    assert "1.1.1.1" not in index
    assert "2.2.2.2" not in index
    assert "3.3.3.3" not in index
    assert "4.4.4.4" not in index
    assert index["5.5.5.5"]["nom"] == "espace.example.com"


def test_un_nom_est_normalise_en_minuscules_et_sans_point_final():
    index = noms.indexer([paquet_dns("1.2.3.4", "Example.COM.")])
    assert index["1.2.3.4"]["nom"] == "example.com"


# --------------------------------------------------------------------------- #
#  L'application à une communication
# --------------------------------------------------------------------------- #
def test_le_nom_s_ajoute_sans_retirer_l_adresse():
    """La propriété la plus importante du module."""
    communication = {"protocole": "TCP", "ip_a": "192.168.1.5", "ip_b": "93.184.216.34"}
    index = {"93.184.216.34": {"nom": "example.com", "vu_le": "2026-10-05T10:00:00+00:00"}}
    resultat = noms.nommer(communication, index)

    assert resultat["nom_b"] == "example.com"
    assert resultat["ip_b"] == "93.184.216.34", "l'adresse a été retirée"
    assert resultat["ip_a"] == "192.168.1.5"
    assert "nom_a" not in resultat


def test_une_adresse_inconnue_reste_sans_nom():
    """On ne devine pas : pas de nom connu, pas de nom affiché."""
    communication = {"ip_a": "192.168.1.5", "ip_b": "8.8.8.8"}
    resultat = noms.nommer(communication, {"93.184.216.34": {"nom": "example.com"}})
    assert "nom_b" not in resultat
    assert resultat["ip_b"] == "8.8.8.8"


def test_sans_index_la_fiche_est_inchangee():
    communication = {"ip_a": "192.168.1.5", "ip_b": "8.8.8.8"}
    assert noms.nommer(communication, {}) == communication


# --------------------------------------------------------------------------- #
#  Le cache
# --------------------------------------------------------------------------- #
def test_le_cache_evite_de_relire_les_paquets():
    """Sans lui, chaque rafraîchissement relirait des milliers de paquets pour rien."""
    appels = {"nombre": 0}

    def construire():
        appels["nombre"] += 1
        return [paquet_dns("93.184.216.34", "example.com")]

    cache = noms.CacheNoms(validite=60)
    cache.obtenir(construire)
    cache.obtenir(construire)
    cache.obtenir(construire)
    assert appels["nombre"] == 1
    assert cache.obtenir(construire)["93.184.216.34"]["nom"] == "example.com"


def test_le_cache_se_reconstruit_apres_expiration():
    """Il doit rester court : un nom nouveau doit apparaître vite, pas dans une heure."""
    appels = {"nombre": 0}

    def construire():
        appels["nombre"] += 1
        return []

    cache = noms.CacheNoms(validite=0.01)
    cache.obtenir(construire)
    time.sleep(0.02)
    cache.obtenir(construire)
    assert appels["nombre"] == 2

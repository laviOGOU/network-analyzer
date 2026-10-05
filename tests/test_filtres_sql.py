"""Tests de la traduction des filtres en SQL (Lot A).

LA PROPRIÉTÉ QUI COMPTE
-----------------------
Une valeur écrite par l'utilisateur doit apparaître dans les **paramètres**, et jamais
dans le **fragment SQL**. C'est vérifiable sans base de données, et c'est ce qui rend la
vérification utilisable partout — y compris sur une machine sans PostgreSQL.

Le test d'injection ne cherche pas à savoir si la base résisterait : il vérifie que la
question ne se pose pas, parce que le texte hostile n'a jamais la forme de SQL.
"""

from __future__ import annotations

import pytest

from backend import filtres
from backend import filtres_sql


def critere(champ, valeur, comparateur="="):
    return filtres.Critere(champ, valeur, comparateur)


# --------------------------------------------------------------------------- #
#  Le fragment produit
# --------------------------------------------------------------------------- #
def test_sans_critere_aucune_condition():
    assert filtres_sql.conditions([], "paquets") == ("", [])


def test_condition_sur_le_protocole():
    fragment, parametres = filtres_sql.conditions([critere("proto", "tcp")], "paquets")
    assert fragment == "(lower(protocole) = %s)"
    assert parametres == ["tcp"]


def test_condition_sur_un_port_des_deux_cotes():
    """Un port se cherche à la source comme à la destination."""
    fragment, parametres = filtres_sql.conditions([critere("port", "443")], "paquets")
    assert fragment == "(port_source = %s OR port_destination = %s)"
    assert parametres == ["443", "443"]


def test_adresse_complete_comparee_en_texte():
    """`host()` rend l'adresse sans masque : la comparaison est fiable."""
    fragment, parametres = filtres_sql.conditions([critere("ip", "192.168.1.5")], "paquets")
    assert fragment == "(host(ip_source) = %s OR host(ip_destination) = %s)"
    assert parametres == ["192.168.1.5", "192.168.1.5"]


def test_prefixe_d_adresse_utilise_like():
    fragment, parametres = filtres_sql.conditions([critere("ip", "192.168.1.")], "paquets")
    assert "LIKE" in fragment
    assert parametres == ["192.168.1.%", "192.168.1.%"]


def test_comparaison_de_taille():
    fragment, parametres = filtres_sql.conditions(
        [critere("taille", "1000", ">")], "paquets")
    assert fragment == "(taille > %s)"
    assert parametres == [1000]


def test_le_niveau_accentue_est_traduit():
    """Le schéma écrit « hypothese » sans accent ; l'interface écrit « hypothèse ».

    La traduction se fait en un seul endroit : sans elle, aucun filtre sur ce niveau ne
    trouverait jamais rien, et personne ne comprendrait pourquoi.
    """
    fragment, parametres = filtres_sql.conditions([critere("niveau", "hypothèse")],
                                                  "detections")
    assert parametres == ["hypothese"]


def test_plusieurs_criteres_sont_lies_par_et():
    fragment, parametres = filtres_sql.conditions(
        [critere("proto", "tcp"), critere("port", "443")], "paquets")
    assert fragment.count(" AND ") == 1
    assert parametres == ["tcp", "443", "443"]


def test_recherche_libre_sur_plusieurs_colonnes():
    fragment, parametres = filtres_sql.conditions([critere("texte", "example.com")],
                                                  "paquets")
    assert fragment.count(" OR ") == 2          # trois colonnes explorées
    assert all("%example.com%" in parametre or parametre == "%example.com%"
               for parametre in parametres)


# --------------------------------------------------------------------------- #
#  Ce qui doit être refusé
# --------------------------------------------------------------------------- #
def test_un_champ_qui_ne_s_applique_pas_a_la_vue_est_refuse():
    """Un état n'a pas de sens pour un paquet, un niveau n'en a pas pour une communication.

    Le refus est explicite, et la liste des champs utilisables est donnée.
    """
    with pytest.raises(filtres_sql.ErreurFiltreSQL) as erreur:
        filtres_sql.conditions([critere("etat", "fermée")], "paquets")
    assert "etat" in str(erreur.value)


def test_une_table_inconnue_est_refusee():
    with pytest.raises(filtres_sql.ErreurFiltreSQL):
        filtres_sql.conditions([critere("proto", "tcp")], "n_existe_pas")


def test_un_operateur_inconnu_est_refuse():
    """Rien ne doit pouvoir se glisser à la place d'un opérateur."""
    with pytest.raises(filtres_sql.ErreurFiltreSQL):
        filtres_sql.conditions([critere("taille", "1000", "; DROP TABLE x --")], "paquets")


# --------------------------------------------------------------------------- #
#  La propriété qui compte : les valeurs ne sont jamais du SQL
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("valeur", [
    "'; DROP TABLE analyzer.packets; --",
    "tcp' OR 1=1 --",
    "%",
    "a' UNION SELECT * FROM analyzer.alerts --",
])
def test_une_valeur_hostile_reste_un_parametre(valeur):
    """La valeur est dans les paramètres, entière, et le fragment n'en contient rien.

    C'est la seule chose à vérifier pour être tranquille : si la valeur n'est pas dans la
    requête, elle ne peut pas en changer le sens.
    """
    fragment, parametres = filtres_sql.conditions([critere("texte", valeur)], "paquets")
    # On retire les marqueurs avant de chercher : « %s » contient un « % », et une valeur
    # réduite à ce seul caractère produirait une alerte fausse. Ce qui reste doit être du
    # SQL écrit par le code, et rien d'autre.
    assert valeur not in fragment.replace("%s", ""), \
        "le texte de l'utilisateur a atteint la requête"
    # La recherche libre met la valeur en minuscules (comparaison insensible à la casse) :
    # on compare donc de la même façon, sinon le test échouerait sur des majuscules.
    assert any(valeur.lower() in str(parametre).lower() for parametre in parametres)
    # Le fragment ne contient que des marqueurs, des colonnes et des mots-clés.
    assert fragment.count("%s") == len(parametres)


def test_le_nombre_de_marqueurs_egale_le_nombre_de_parametres():
    """Vérification générale : un marqueur de trop ferait échouer la requête à l'exécution.

    Le défaut ne se verrait qu'au moment de la requête, en production, sur le filtre
    précis qui a le décalage — c'est-à-dire jamais pendant les tests manuels.
    """
    # Chaque table a ses champs : `taille` n'existe pas pour une communication, `etat`
    # n'existe pas pour un paquet. Les jeux sont donc écrits par table.
    jeux = {
        "paquets": [
            [critere("proto", "tcp")],
            [critere("ip", "192.168.1.5")],
            [critere("ip", "192.168.1.")],
            [critere("port", "443"), critere("taille", "100", ">")],
            [critere("texte", "abc"), critere("proto", "udp")],
        ],
        "communications": [
            [critere("proto", "tcp")],
            [critere("ip", "192.168.1.5")],
            [critere("port", "443")],
            [critere("etat", "fermée"), critere("proto", "tcp")],
            [critere("texte", "abc")],
        ],
        "detections": [
            [critere("niveau", "alerte")],
            [critere("ip", "192.168.1.5")],
            [critere("texte", "ports"), critere("niveau", "hypothèse")],
        ],
    }
    for table, liste in jeux.items():
        for jeu in liste:
            fragment, parametres = filtres_sql.conditions(jeu, table)
            assert fragment.count("%s") == len(parametres), f"{table} {jeu}"
            assert parametres, f"{table} {jeu} : aucun paramètre"


def test_le_compte_de_conditions():
    assert filtres_sql.compte_conditions([], "paquets") == 0
    assert filtres_sql.compte_conditions([critere("proto", "tcp")], "paquets") == 1
    assert filtres_sql.compte_conditions(
        [critere("proto", "tcp"), critere("port", "443")], "paquets") == 2

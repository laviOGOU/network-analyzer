"""Tests des statistiques (Lot C).

CE QUI EST ÉPROUVÉ, ET POURQUOI CES POINTS-LÀ
---------------------------------------------
1. **Les pourcentages retombent sur 100.** Un lecteur qui additionne une colonne et trouve
   99 ou 101 cesse de croire au tableau — et il a raison. Le reste de la division est donc
   absorbé par la part la plus grande, jamais perdu.
2. **Les paquets d'analyse partielle ne sont pas classés.** Leur donner un protocole serait
   inventer ce que le parseur n'a pas su lire : c'est la règle d'honnêteté du projet,
   appliquée à un chiffre.
3. **Le débit part du premier paquet vu, pas de l'horloge.** C'est ce qui permet à un
   fichier `.pcap` rejoué de produire le même graphique que la capture d'origine.

Les structures employées sont celles de vrais paquets, relevées sur une réponse de l'API.
"""

from __future__ import annotations

from backend import statistiques


def paquet(protocole="TCP", taille=100, source="192.168.1.5", destination="93.184.216.34",
           horodatage="2026-10-05T10:00:00+00:00", partiel=False):
    return {
        "horodatage": horodatage, "protocole": protocole, "taille": taille,
        "ip_source": source, "ip_destination": destination,
        "analyse_partielle": partiel,
    }


# --------------------------------------------------------------------------- #
#  Pourcentages
# --------------------------------------------------------------------------- #
def test_les_pourcentages_retombent_sur_cent():
    """Un total qui ne retombe pas sur 100 fait perdre confiance au tableau entier."""
    for comptes in ({"a": 1, "b": 2}, {"a": 1, "b": 1, "c": 1}, {"a": 7, "b": 11},
                    {"a": 1, "b": 1, "c": 1, "d": 1, "e": 1, "f": 1, "g": 1}):
        parts = statistiques._pourcentages(comptes)
        assert round(sum(p["pourcent"] for p in parts), 1) == 100.0, comptes


def test_les_pourcentages_vont_du_plus_frequenta_au_plus_rare():
    parts = statistiques._pourcentages({"rare": 1, "frequent": 9})
    assert [p["nom"] for p in parts] == ["frequent", "rare"]
    assert parts[0]["pourcent"] == 90.0


def test_aucun_compte_ne_donne_aucune_part():
    assert statistiques._pourcentages({}) == []


# --------------------------------------------------------------------------- #
#  Hiérarchie
# --------------------------------------------------------------------------- #
def test_la_hierarchie_compte_chaque_protocole():
    resultat = statistiques.hierarchie([paquet("TCP"), paquet("TCP"), paquet("UDP")])
    assert resultat["total"] == 3
    noms = {p["nom"]: p for p in resultat["protocoles"]}
    assert noms["TCP"]["paquets"] == 2
    assert noms["TCP"]["pourcent"] == 66.7
    assert round(sum(p["pourcent"] for p in resultat["protocoles"]), 1) == 100.0


def test_un_paquet_partiel_est_compte_a_part_jamais_classe():
    """Lui donner un protocole serait inventer ce que le parseur n'a pas su lire."""
    resultat = statistiques.hierarchie([paquet("TCP"), paquet("TCP", partiel=True)])
    noms = {p["nom"] for p in resultat["protocoles"]}
    assert "analyse partielle" in noms
    assert noms == {"TCP", "analyse partielle"}
    assert resultat["total"] == 2


def test_une_capture_vide_ne_produit_pas_de_pourcentage():
    resultat = statistiques.hierarchie([])
    assert resultat["total"] == 0
    assert resultat["protocoles"] == []


# --------------------------------------------------------------------------- #
#  Extrémités
# --------------------------------------------------------------------------- #
def test_emis_et_recus_sont_distingues():
    """Un serveur qui répond beaucoup et une machine qui interroge beaucoup n'ont pas le
    même profil : un classement sur le seul volume total les confondrait."""
    resultat = statistiques.extremites([
        paquet(source="192.168.1.5", destination="93.184.216.34"),
        paquet(source="192.168.1.5", destination="93.184.216.34"),
    ])
    fiches = {f["adresse"]: f for f in resultat["extremites"]}
    assert fiches["192.168.1.5"]["emis"] == 2
    assert fiches["192.168.1.5"]["recus"] == 0
    assert fiches["93.184.216.34"]["emis"] == 0
    assert fiches["93.184.216.34"]["recus"] == 2


def test_les_extremites_sont_classees_par_activite():
    resultat = statistiques.extremites([
        paquet(source="bavarde", destination="muette"),
        paquet(source="bavarde", destination="muette"),
        paquet(source="bavarde", destination="muette"),
    ])
    assert resultat["extremites"][0]["adresse"] == "bavarde"
    assert resultat["extremites"][0]["total"] == 3


def test_une_adresse_absente_ne_produit_pas_d_entree():
    resultat = statistiques.extremites([paquet(source=None, destination=None)])
    assert resultat["extremites"] == []


# --------------------------------------------------------------------------- #
#  Débit
# --------------------------------------------------------------------------- #
def test_le_debit_part_du_premier_paquet_vu():
    """C'est ce qui rend un fichier rejoué fidèle à la capture d'origine."""
    resultat = statistiques.debit([
        paquet(horodatage="2030-01-01T00:00:00+00:00", taille=100),
        paquet(horodatage="2030-01-01T00:00:02+00:00", taille=300),
    ])
    assert [p["offset_s"] for p in resultat["points"]] == [0.0, 2.0]
    assert resultat["points"][0]["octets"] == 100
    assert resultat["maximum_octets"] == 300


def test_deux_paquets_du_meme_seau_sont_regroupes():
    resultat = statistiques.debit([
        paquet(horodatage="2030-01-01T00:00:00+00:00", taille=100),
        paquet(horodatage="2030-01-01T00:00:00+00:00", taille=200),
    ])
    assert len(resultat["points"]) == 1
    assert resultat["points"][0]["octets"] == 300
    assert resultat["points"][0]["paquets"] == 2


def test_le_debit_ne_depend_pas_de_l_ordre_recu():
    """Comme partout : un ordre non garanti n'est pas un ordre."""
    desordre = [
        paquet(horodatage="2030-01-01T00:00:02+00:00"),
        paquet(horodatage="2030-01-01T00:00:00+00:00"),
    ]
    resultat = statistiques.debit(desordre)
    assert [p["offset_s"] for p in resultat["points"]] == [0.0, 2.0]


def test_une_capture_sans_horodatage_ne_produit_pas_de_graphique():
    resultat = statistiques.debit([paquet(horodatage=None)])
    assert resultat["points"] == []


# --------------------------------------------------------------------------- #
#  Vue d'ensemble
# --------------------------------------------------------------------------- #
def test_l_ensemble_porte_toujours_le_nombre_de_paquets_examines():
    """Sans lui, un tableau vide ne distingue pas « rien » de « rien à analyser »."""
    resultat = statistiques.ensemble([paquet(), paquet("UDP")])
    assert resultat["paquets_examines"] == 2
    assert set(resultat) == {"paquets_examines", "hierarchie", "extremites", "debit"}

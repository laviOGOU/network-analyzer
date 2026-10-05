"""Tests des filtres d'affichage (Lot A).

DEUX PROPRIÉTÉS PORTENT CE MODULE
---------------------------------
1. **Un filtre incompris est refusé, jamais ignoré.** Ignorer un critère donnerait des
   résultats incomplets sans le dire : l'utilisateur verrait moins de lignes, croirait son
   filtre appliqué, et conclurait quelque chose de faux sur son réseau. C'est le genre
   d'erreur silencieuse qu'un outil d'analyse ne peut pas se permettre.

2. **Les critères sont des données, pas du texte.** Rien de ce que l'utilisateur écrit ne
   devient une chaîne exécutée : le stockage reçoit des couples (champ, valeur) et les
   traduit lui-même. Les tests le vérifient de deux façons : la forme des critères ici, et
   l'innocuité d'une tentative d'injection dans `test_persistance.py`.

Le reste éprouve la syntaxe, y compris ses cas désagréables — guillemets mal fermés,
comparateur sans nombre, préfixe d'adresse.
"""

from __future__ import annotations

import pytest

from backend import filtres


# --------------------------------------------------------------------------- #
#  La lecture d'une expression
# --------------------------------------------------------------------------- #
def test_expression_vide_ne_filtre_rien():
    """« Pas de filtre » n'est pas une erreur : c'est le cas le plus courant."""
    assert filtres.analyser("") == []
    assert filtres.analyser(None) == []
    assert filtres.analyser("   ") == []


def test_criteres_simples():
    criteres = filtres.analyser("proto:tcp port:443")
    assert len(criteres) == 2
    assert criteres[0] == filtres.Critere("proto", "tcp", "=")
    assert criteres[1] == filtres.Critere("port", "443", "=")


def test_les_valeurs_ecrites_sont_conservees_telles_quelles():
    """Les critères portent la valeur brute : rien n'est transformé en code."""
    # La valeur contient des espaces : elle s'écrit entre guillemets. Sans eux, elle
    # serait découpée en plusieurs morceaux et le second n'aurait pas de « champ: » —
    # donc refusée, à juste titre.
    criteres = filtres.analyser('texte:"\'; DROP TABLE analyzer.packets; --"')
    assert len(criteres) == 1
    assert criteres[0].champ == "texte"
    # La valeur est là, entière, en tant que donnée — jamais exécutée.
    assert "DROP TABLE" in criteres[0].valeur
    assert isinstance(criteres[0].vers_dict(), dict)


def test_guillemets_pour_une_valeur_avec_espace():
    """« échec probable » contient une espace : les guillemets la protègent."""
    criteres = filtres.analyser('etat:"échec probable"')
    assert criteres == [filtres.Critere("etat", "échec probable", "=")]


def test_guillemets_mal_fermes_sont_refuses():
    with pytest.raises(filtres.ErreurFiltre) as erreur:
        filtres.analyser('etat:"échec probable')
    assert "guillemet" in str(erreur.value).lower()


def test_la_casse_n_importe_pas_pour_les_valeurs_enumerees():
    assert filtres.analyser("PROTO:TCP")[0].valeur == "tcp"
    assert filtres.analyser("Niveau:Alerte")[0].valeur == "alerte"


# --------------------------------------------------------------------------- #
#  Ce qui doit être refusé — et pourquoi
# --------------------------------------------------------------------------- #
def test_un_champ_inconnu_est_refuse_avec_la_liste_des_champs():
    """Le message doit permettre de corriger sans consulter la documentation."""
    with pytest.raises(filtres.ErreurFiltre) as erreur:
        filtres.analyser("couleur:rouge")
    message = str(erreur.value)
    assert "couleur" in message
    for champ in filtres.CHAMPS:
        assert champ in message, f"le champ {champ} n'est pas proposé dans le message"


def test_un_morceau_sans_deux_points_est_refuse():
    with pytest.raises(filtres.ErreurFiltre) as erreur:
        filtres.analyser("tcp")
    assert "champ:valeur" in str(erreur.value)


def test_un_champ_sans_valeur_est_refuse():
    with pytest.raises(filtres.ErreurFiltre):
        filtres.analyser("proto:")


def test_comparateur_sans_nombre_est_refuse():
    with pytest.raises(filtres.ErreurFiltre) as erreur:
        filtres.analyser("taille:>beaucoup")
    assert "nombre" in str(erreur.value)


def test_port_non_numerique_est_refuse():
    with pytest.raises(filtres.ErreurFiltre):
        filtres.analyser("port:https")


def test_adresse_invalide_est_refusee():
    with pytest.raises(filtres.ErreurFiltre):
        filtres.analyser("ip:999.999.999.999")


def test_trop_de_criteres_sont_refuses():
    """Huit critères suffisent à décrire une intention ; au-delà, c'est une erreur."""
    expression = " ".join(f"port:{p}" for p in range(filtres.CRITERES_MAX + 2))
    with pytest.raises(filtres.ErreurFiltre):
        filtres.analyser(expression)


def test_une_expression_trop_longue_est_refusee():
    with pytest.raises(filtres.ErreurFiltre) as erreur:
        filtres.analyser("texte:" + "a" * (filtres.LONGUEUR_MAX + 10))
    assert "longue" in str(erreur.value)


# --------------------------------------------------------------------------- #
#  Les comparateurs
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("expression,comparateur,nombre", [
    ("taille:>1000", ">", "1000"),
    ("taille:<100", "<", "100"),
    ("taille:>=500", ">=", "500"),
    ("taille:<=500", "<=", "500"),
    ("taille:64", "=", "64"),
])
def test_les_comparateurs_sont_reconnus(expression, comparateur, nombre):
    critere = filtres.analyser(expression)[0]
    assert critere.comparateur == comparateur
    assert critere.valeur == nombre


# --------------------------------------------------------------------------- #
#  L'application à des enregistrements
# --------------------------------------------------------------------------- #
def paquet(source="192.168.1.5", destination="93.184.216.34", port_source=51000,
           port=443, protocole="TCP", taille=74, domaine=None):
    details = {"dns_question": domaine} if domaine else {}
    return {
        "ip_source": source, "ip_destination": destination,
        "port_source": port_source, "port_destination": port,
        "protocole": protocole, "taille": taille, "details": details,
        "resume": f"{source} > {destination}",
    }


def test_filtre_par_protocole():
    criteres = filtres.analyser("proto:udp")
    assert filtres.filtrer(criteres, [paquet(), paquet(protocole="UDP")]) == \
        [paquet(protocole="UDP")]


def test_filtre_par_port_des_deux_cotes():
    """Un filtre sur le port doit trouver la source comme la destination.

    Filtrer « port:443 » et manquer les paquets où 443 est le port source serait
    contre-intuitif : l'utilisateur cherche un port, pas un rôle.
    """
    criteres = filtres.analyser("port:51000")
    assert len(filtres.filtrer(criteres, [paquet()])) == 1
    criteres = filtres.analyser("port:443")
    assert len(filtres.filtrer(criteres, [paquet()])) == 1
    criteres = filtres.analyser("port:8080")
    assert filtres.filtrer(criteres, [paquet()]) == []


def test_filtre_par_adresse_des_deux_cotes():
    assert len(filtres.filtrer(filtres.analyser("ip:192.168.1.5"), [paquet()])) == 1
    assert len(filtres.filtrer(filtres.analyser("ip:93.184.216.34"), [paquet()])) == 1


def test_filtre_par_prefixe_de_sous_reseau():
    """« ip:192.168.1. » sélectionne tout le réseau local."""
    criteres = filtres.analyser("ip:192.168.1.")
    assert len(filtres.filtrer(criteres, [paquet()])) == 1
    assert filtres.filtrer(criteres, [paquet(source="10.0.0.1")]) == []


def test_filtre_par_taille():
    criteres = filtres.analyser("taille:>1000")
    assert filtres.filtrer(criteres, [paquet(taille=74)]) == []
    assert len(filtres.filtrer(criteres, [paquet(taille=1500)])) == 1


def test_plusieurs_criteres_se_cumulent():
    """Deux critères sont un ET, pas un OU.

    Un OU donnerait plus de résultats que chaque critère pris seul : l'utilisateur
    croirait avoir restreint, et aurait élargi.
    """
    criteres = filtres.analyser("proto:tcp port:443")
    assert len(filtres.filtrer(criteres, [paquet()])) == 1
    assert filtres.filtrer(criteres, [paquet(protocole="UDP")]) == []
    assert filtres.filtrer(criteres, [paquet(port=8080)]) == []


def test_filtre_sur_l_etat_d_une_communication():
    communication = {"etat": "échec probable", "protocole": "TCP"}
    criteres = filtres.analyser('etat:"échec probable"')
    assert len(filtres.filtrer(criteres, [communication])) == 1
    assert filtres.filtrer(filtres.analyser("etat:établie"), [communication]) == []


def test_filtre_sur_le_niveau_d_une_detection():
    detection = {"niveau": "hypothèse", "titre": "Beaucoup de ports"}
    assert len(filtres.filtrer(filtres.analyser("niveau:hypothèse"), [detection])) == 1
    assert filtres.filtrer(filtres.analyser("niveau:alerte"), [detection]) == []


def test_recherche_libre_dans_les_details():
    """La recherche libre regarde aussi les détails : un nom de domaine se retrouve."""
    criteres = filtres.analyser("texte:example.com")
    assert len(filtres.filtrer(criteres, [paquet(domaine="example.com")])) == 1
    assert filtres.filtrer(criteres, [paquet(domaine="autre.org")]) == []


def test_une_valeur_absente_ne_fait_pas_echouer_le_filtre():
    """Un enregistrement incomplet est simplement écarté, sans exception.

    Les paquets arrivent du réseau : certains n'ont ni adresse ni port. Un filtre qui
    lèverait sur ces cas rendrait l'interface inutilisable dès qu'un paquet tronqué passe.
    """
    incomplet = {"protocole": "TCP", "ip_source": None, "ip_destination": None}
    for expression in ("ip:192.168.1.5", "port:443", "taille:>10", "texte:abc"):
        assert filtres.filtrer(filtres.analyser(expression), [incomplet]) == []


def test_sans_critere_tout_passe():
    fiches = [paquet(), paquet(protocole="UDP")]
    assert filtres.filtrer([], fiches) == fiches


# --------------------------------------------------------------------------- #
#  Le retour à l'écrit
# --------------------------------------------------------------------------- #
def test_l_expression_est_restituee_telle_qu_elle_a_ete_comprise():
    """L'interface réaffiche le filtre interprété : une faute de frappe se voit."""
    assert filtres.criteres_vers_texte(filtres.analyser("proto:tcp port:443")) == \
        "proto:tcp port:443"
    # Les guillemets reviennent autour des valeurs qui en ont besoin.
    assert filtres.criteres_vers_texte(
        filtres.analyser('etat:"échec probable"')) == 'etat:"échec probable"'
    assert filtres.criteres_vers_texte(filtres.analyser("taille:>1000")) == "taille:>1000"

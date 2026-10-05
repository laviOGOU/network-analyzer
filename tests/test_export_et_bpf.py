"""Tests de l'export et de la validation du filtre de capture (Lot A)."""

from __future__ import annotations

import json

import pytest

from agent import bpf
from backend import export

# --------------------------------------------------------------------------- #
#  L'export
# --------------------------------------------------------------------------- #
PAQUET = {
    "horodatage": "2026-10-05T10:00:00+00:00", "protocole": "TCP",
    "ip_source": "192.168.1.5", "ip_destination": "93.184.216.34",
    "port_source": 51000, "port_destination": 443, "taille": 74, "ttl": 64,
    "flags_tcp": "PA", "analyse_partielle": False,
    # Un champ qui n'est pas dans la liste des colonnes exportées : il ne doit pas sortir.
    "details": {"dns_question": "secret.example.com"},
}


def test_le_csv_commence_par_la_marque_d_encodage():
    """Sans elle, Excel affiche « Ã© » à la place de « é ».

    C'est le détail qui fait qu'un export correct « ne marche pas » pour celui qui
    l'ouvre — et il ne pense pas à le signaler, il conclut que l'outil est cassé.
    """
    contenu = export.vers_csv([PAQUET], "paquets")
    assert contenu.startswith("\ufeff")


def test_le_csv_utilise_le_point_virgule():
    """Un tableur configuré en français attend le point-virgule."""
    contenu = export.vers_csv([PAQUET], "paquets")
    entete = contenu.lstrip("\ufeff").split("\r\n")[0]
    assert ";" in entete
    assert "," not in entete


def test_une_valeur_contenant_le_separateur_est_protegee():
    """Un texte qui contient le séparateur casserait le fichier s'il n'était pas protégé."""
    detection = {"niveau": "alerte", "titre": "Ports ; beaucoup", "regle": "scan_ports",
                 "cible": "10.0.0.1", "explication": "ligne 1\nligne 2",
                 "faux_positifs": "a;b", "faits_observes": ["x", "y"]}
    contenu = export.vers_csv([detection], "detections")
    ligne = contenu.lstrip("\ufeff").split("\r\n")[1]
    # Le champ est entouré de guillemets : le tableur ne le coupera pas en deux colonnes.
    assert '"Ports ; beaucoup"' in ligne
    assert "x | y" in ligne               # une liste devient du texte lisible


def test_les_booleens_sont_ecrits_en_francais():
    contenu = export.vers_csv([PAQUET], "paquets")
    assert "non" in contenu.split("\r\n")[1]


def test_le_csv_n_exporte_que_les_colonnes_declarees():
    """Ce qui n'est pas déclaré ne sort pas.

    La liste des colonnes est écrite à la main : c'est elle qui décide de ce qui quitte
    l'outil. Un export qui recopierait tous les champs ferait sortir un jour, sans
    prévenir, une donnée qu'on avait décidé de ne pas conserver.
    """
    contenu = export.vers_csv([PAQUET], "paquets")
    assert "secret.example.com" not in contenu
    assert "details" not in contenu


def test_le_json_garde_la_structure():
    """Le JSON est là pour ce que le CSV aplatit : les listes et les objets."""
    contenu = export.vers_json([PAQUET], "paquets")
    donnees = json.loads(contenu)
    assert donnees["vue"] == "paquets"
    assert donnees["lignes"] == 1
    assert donnees["tronque"] is False
    assert donnees["donnees"][0]["details"]["dns_question"] == "secret.example.com"


def test_le_csv_aplatit_la_structure_que_le_json_conserve():
    """Les deux formats servent à deux choses : c'est ce qui justifie de les avoir deux."""
    paquet = {"analyse_partielle": True, "protocole": "TCP", "taille": 74}
    assert "oui" in export.vers_csv([paquet], "paquets")
    assert json.loads(export.vers_json([paquet], "paquets"))["donnees"][0][
        "analyse_partielle"] is True


def test_une_vue_inconnue_est_refusee():
    with pytest.raises(ValueError):
        export.vers_csv([], "n_existe_pas")


def test_l_export_est_borne():
    """Un export n'est pas une copie de la base : au-delà, le fichier ne s'ouvre plus."""
    lignes = [dict(PAQUET) for _ in range(export.LIGNES_MAX + 100)]
    contenu = export.vers_json(lignes, "paquets")
    donnees = json.loads(contenu)
    assert donnees["lignes"] == export.LIGNES_MAX
    assert donnees["tronque"] is True


def test_le_nom_de_fichier_porte_la_date():
    """Sans date, deux exports du même jour s'écrasent dans les téléchargements."""
    nom = export.nom_de_fichier("paquets", "csv", "2026-10-05T14:30:22+00:00")
    assert nom == "network-analyzer_paquets_20261005143022.csv"


# --------------------------------------------------------------------------- #
#  Le filtre de capture
# --------------------------------------------------------------------------- #
def test_un_filtre_vide_est_valide():
    """Le cas le plus courant : tout capturer."""
    assert bpf.valider("") == ""
    assert bpf.valider(None) == ""
    assert bpf.valider("   ") == ""


def test_un_filtre_trop_long_est_refuse():
    with pytest.raises(bpf.ErreurFiltreBPF) as erreur:
        bpf.valider("tcp " * (bpf.LONGUEUR_MAX // 4 + 10))
    assert "trop long" in str(erreur.value)


def test_un_caractere_de_controle_est_refuse():
    with pytest.raises(bpf.ErreurFiltreBPF):
        bpf.valider("tcp\x00port 443")


def test_le_message_d_erreur_donne_la_syntaxe_attendue():
    """Un message qui dit seulement « invalide » oblige à chercher la syntaxe ailleurs.

    Et la confusion la plus probable est celle du filtre d'affichage : les deux
    s'écrivent différemment, dans deux champs différents de l'interface.
    """
    try:
        from scapy.arch.common import compile_filter           # noqa: F401
    except ImportError:                                        # pragma: no cover
        pytest.skip("libpcap absent : la validation par compilation n'est pas possible")

    with pytest.raises(bpf.ErreurFiltreBPF) as erreur:
        bpf.valider("proto:tcp")            # syntaxe du filtre d'affichage, pas du BPF
    message = str(erreur.value)
    assert "tcp port 443" in message, "le message ne montre pas la bonne syntaxe"


def test_un_filtre_valide_est_accepte():
    """La validation s'appuie sur la bibliothèque qui filtrera réellement."""
    try:
        from scapy.arch.common import compile_filter           # noqa: F401
    except ImportError:                                        # pragma: no cover
        pytest.skip("libpcap absent")

    assert bpf.valider("tcp port 443") == "tcp port 443"
    assert bpf.valider("udp and port 53") == "udp and port 53"
    assert bpf.valider("  not port 53  ") == "not port 53"      # espaces retirés

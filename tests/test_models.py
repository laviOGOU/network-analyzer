"""Tests de validation des données reçues.

Ces tests défendent l'endpoint d'ingestion. Sans eux, un agent peut écrire n'importe quoi :
une adresse IP inventée se retrouverait affichée comme une machine, un port à 99 999
fausserait le classement des ports fréquentés, et un champ texte non borné remplirait la
base.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from backend.models import FichePaquet, LotPaquets


def fiche(**remplacements) -> dict:
    """Fiche minimale valide, à modifier selon le test."""
    base = {"horodatage": datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc).isoformat(),
            "taille": 74, "protocole": "TCP"}
    base.update(remplacements)
    return base


def test_fiche_minimale_acceptee():
    """Seuls l'horodatage, la taille et le protocole sont nécessaires."""
    paquet = FichePaquet(**fiche())

    assert paquet.protocole == "TCP"
    assert paquet.ip_source is None          # absent, et non inventé


def test_adresse_ipv4_valide():
    paquet = FichePaquet(**fiche(ip_source="192.168.1.5", ip_destination="8.8.8.8"))

    assert paquet.ip_source == "192.168.1.5"


def test_adresse_ipv6_normalisee():
    """Une adresse IPv6 compressée est conservée telle quelle, reconnue comme valide."""
    paquet = FichePaquet(**fiche(ip_source="2001:db8::1"))

    assert paquet.ip_source == "2001:db8::1"


def test_adresse_invalide_refusee():
    """999.1.1.1 n'est pas une adresse : l'ingestion doit refuser, avec un motif clair."""
    with pytest.raises(ValidationError) as erreur:
        FichePaquet(**fiche(ip_source="999.1.1.1"))

    assert "adresse IP invalide" in str(erreur.value)


def test_port_hors_bornes_refuse():
    with pytest.raises(ValidationError):
        FichePaquet(**fiche(port_destination=70000))


def test_port_negatif_refuse():
    with pytest.raises(ValidationError):
        FichePaquet(**fiche(port_source=-1))


def test_taille_negative_refusee():
    with pytest.raises(ValidationError):
        FichePaquet(**fiche(taille=-5))


def test_ttl_hors_bornes_refuse():
    """Le TTL tient sur un octet : 300 ne peut pas venir d'un vrai paquet."""
    with pytest.raises(ValidationError):
        FichePaquet(**fiche(ttl=300))


def test_champ_inconnu_refuse():
    """`extra="forbid"` : une divergence entre l'agent et le backend doit être bruyante.

    Un champ silencieusement ignoré donnerait l'illusion que tout va bien, alors qu'une
    donnée serait perdue à chaque envoi.
    """
    with pytest.raises(ValidationError):
        FichePaquet(**fiche(champ_qui_n_existe_pas="valeur"))


def test_texte_trop_long_refuse():
    with pytest.raises(ValidationError):
        FichePaquet(**fiche(protocole="P" * 200))


def test_details_bornes():
    """Le dictionnaire de détails est limité : il vient du réseau, donc de nulle part."""
    with pytest.raises(ValidationError):
        FichePaquet(**fiche(details={f"cle{indice}": "valeur" for indice in range(20)}))


def test_detail_trop_long_refuse():
    with pytest.raises(ValidationError):
        FichePaquet(**fiche(details={"dns_question": "a" * 400}))


def test_lot_valide():
    lot = LotPaquets(session="session-1", agent="poste", paquets=[fiche()])

    assert len(lot.paquets) == 1
    assert lot.agent == "poste"


def test_lot_vide_refuse():
    """Un lot sans paquet est un agent qui va mal : mieux vaut le lui dire."""
    with pytest.raises(ValidationError):
        LotPaquets(session="s", agent="a", paquets=[])


def test_lot_trop_gros_refuse():
    with pytest.raises(ValidationError):
        LotPaquets(session="s", agent="a", paquets=[fiche() for _ in range(1001)])


def test_lot_sans_session_refuse():
    with pytest.raises(ValidationError):
        LotPaquets(session="", agent="a", paquets=[fiche()])


def test_fiche_produite_par_le_parseur_est_acceptee():
    """Test de contrat : ce que l'agent produit, le backend doit l'accepter.

    C'est le test le plus utile de ce fichier. Si une clé est renommée d'un côté sans
    l'autre, l'ingestion refuserait tous les lots en production — et l'erreur
    n'apparaîtrait qu'au moment de la démonstration.
    """
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    from agent import parser

    paquet = Ether() / IP(src="192.168.1.5", dst="93.184.216.34") / TCP(sport=49703, dport=443, flags="S")
    produit = parser.analyser(paquet)

    valide = FichePaquet(**produit)
    assert valide.port_destination == 443
    assert valide.flags_tcp == "SYN"

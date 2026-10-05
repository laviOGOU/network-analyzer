"""Tests de la description des couches (Lot A)."""

from __future__ import annotations

from backend.explain import couches


def test_chaque_couche_explique_a_quoi_elle_sert():
    """La question d'un débutant devant une liste d'en-têtes : « ça sert à quoi ? ».

    Chaque couche doit y répondre en une phrase compréhensible, sans jargon, et sans
    supposer qu'on connaît déjà la réponse.
    """
    for couche in couches.description()["couches"]:
        assert couche["nom"]
        assert len(couche["role"]) > 60, f"{couche['cle']} : rôle trop court pour expliquer"
        assert couche["champs"], f"{couche['cle']} : aucun champ décrit"


def test_les_couches_sont_dans_l_ordre_d_encapsulation():
    """Ethernet, puis IP, puis le transport, puis l'application : c'est l'ordre réel."""
    cles = [couche["cle"] for couche in couches.description()["couches"]]
    assert cles == ["ethernet", "ip", "transport", "application"]


def test_ce_que_l_outil_ne_sait_pas_est_marque_comme_tel():
    """Les octets non extraits portent `source: None` : la vue affichera « ?? ».

    Les combler par des zéros donnerait un affichage plus complet et faux. Ce test
    verrouille l'honnêteté de la vue : ce qui n'est pas analysé doit rester visible comme
    non analysé.
    """
    champs = [champ for couche in couches.COUCHES for champ in couche["champs"]]
    inconnus = [champ for champ in champs if champ["source"] is None]
    assert len(inconnus) >= 4, "le numéro de séquence, la fenêtre et les sommes manquent"
    libelles = " ".join(champ["libelle"].lower() for champ in inconnus)
    assert "séquence" in libelles
    assert "fenêtre" in libelles


def test_le_numero_de_sequence_est_declare_non_extrait():
    """Tant qu'il n'est pas analysé, il doit rester marqué non extrait.

    Le jour où l'analyseur l'extraira (prérequis de la détection des retransmissions),
    ce test échouera — et c'est exactement ce qu'on veut : il faudra alors changer
    `source: None` en `"seq"`, et la vue hexadécimale se complétera d'elle-même.
    """
    transport = next(c for c in couches.COUCHES if c["cle"] == "transport")
    sequence = next(champ for champ in transport["champs"]
                    if "séquence" in champ["libelle"].lower())
    assert sequence["source"] is None


def test_l_avertissement_explique_la_reconstruction():
    """L'utilisateur doit savoir que la vue est reconstruite, pas recopiée."""
    avertissement = couches.AVERTISSEMENT_HEX
    assert "reconstruite" in avertissement
    assert "??" in avertissement
    assert "aucun octet brut" in avertissement.lower()


def test_la_charge_utile_est_declaree_non_conservee():
    """La règle du projet, écrite là où elle se voit."""
    application = next(c for c in couches.COUCHES if c["cle"] == "application")
    assert "ne la conserve pas" in application["role"]
    charge = [champ for champ in application["champs"] if "charge" in champ["libelle"].lower()]
    assert charge and charge[0]["source"] is None

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


def test_ce_que_l_outil_ne_sait_pas_reconstituer_dit_pourquoi():
    """Un champ non reconstituable doit DIRE POURQUOI, jamais afficher « ?? ».

    Règle changée le 06/10/2026, à la demande de l'auteur du projet. L'honnêteté du test
    précédent est conservée — rien n'est comblé par des zéros — mais sous sa nouvelle forme :
    ce qui n'est pas reconstituable porte une raison écrite, pas un point d'interrogation muet.
    Un « ?? » occupe la place d'une information sans en donner aucune.
    """
    champs = [champ for couche in couches.COUCHES for champ in couche["champs"]]
    inconnus = [champ for champ in champs if champ["source"] is None]
    assert inconnus, "les sommes de contrôle restent non reconstituables"
    sans_raison = [champ["libelle"] for champ in inconnus if not champ.get("raison")]
    assert not sans_raison, f"ni source ni raison pour : {sans_raison}"


def test_le_numero_de_sequence_est_desormais_declare():
    """Ce test avait prévu sa propre fin, et il avait prévu juste.

    Il s'appelait « est_declare_non_extrait » et portait ce commentaire : « Le jour où
    l'analyseur l'extraira, ce test échouera — et c'est exactement ce qu'on veut : il faudra
    alors changer source: None en "seq". » Ce jour est arrivé : le parseur extrait la séquence
    et l'acquittement, la vue se complète d'elle-même, et le test a échoué en le disant.

    Il vérifie maintenant l'inverse, et garde son utilité : il empêche que cette déclaration
    disparaisse par inadvertance.
    """
    transport = next(c for c in couches.COUCHES if c["cle"] == "transport")
    sequence = next(champ for champ in transport["champs"]
                    if "séquence" in champ["libelle"].lower())
    assert sequence["source"] == "seq"


def test_l_avertissement_explique_la_reconstruction():
    """L'utilisateur doit savoir que la vue est reconstruite, pas recopiée."""
    avertissement = couches.AVERTISSEMENT_HEX
    assert "reconstruite" in avertissement
    assert "??" in avertissement
    assert "aucun octet brut" in avertissement.lower()


def test_la_charge_utile_n_est_toujours_pas_conservee():
    """La règle du projet n'a pas bougé ; seule sa déclaration s'est précisée.

    La TAILLE de la charge utile est désormais publiée — elle est dans les métadonnées, et
    FlowScope la montre. Le CONTENU, lui, n'est toujours pas conservé, et le champ doit le dire
    en toutes lettres plutôt que de laisser croire à une donnée manquante.
    """
    application = next(c for c in couches.COUCHES if c["cle"] == "application")
    assert "ne la conserve pas" in application["role"]
    charge = [champ for champ in application["champs"] if "charge" in champ["libelle"].lower()]
    assert charge and charge[0]["source"] == "charge_utile"
    assert "jamais conservé" in charge[0].get("raison", "")



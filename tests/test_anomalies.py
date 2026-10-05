"""Tests des anomalies TCP — Expert Info (Lot C).

CE QUI EST ÉPROUVÉ ICI
----------------------
1. **Les faux positifs sont traqués autant que les vrais.** Une retransmission se confond
   facilement avec un accusé de réception : un ACK pur partage souvent son numéro de
   séquence avec le paquet précédent. Compter celui-ci comme une retransmission remplirait
   la liste de bruit, et une liste bruitée ne se lit plus.
2. **Aucune anomalie ne devient une alerte.** Une retransmission est un fait ; l'accuser
   serait une conclusion. La règle du projet — trois indices convergents, familles
   différentes — reste entière, et c'est `detection.py` qui en décide.

Les structures employées sont celles de vrais paquets, relevées sur une réponse de l'API :
`flags_tcp` en **chaîne** au premier niveau, `seq`/`ack`/`fenetre`/`charge_utile` dans
`details`. Trois fois de suite au lot B, un test qui forgeait la mauvaise forme a validé un
code incapable de fonctionner sur les données réelles.
"""

from __future__ import annotations

from agent import anomalies


def paquet(seq=1000, ack=2000, fenetre=64240, charge=100, drapeaux="PSH, ACK",
           source="192.168.1.5", sport=51000, destination="93.184.216.34", dport=443,
           horodatage="2026-10-05T10:00:00+00:00"):
    return {
        "horodatage": horodatage,
        "protocole": "TCP",
        "ip_source": source, "port_source": sport,
        "ip_destination": destination, "port_destination": dport,
        "flags_tcp": drapeaux,
        "details": {"seq": seq, "ack": ack, "fenetre": fenetre, "charge_utile": charge},
    }


# --------------------------------------------------------------------------- #
#  Retransmissions — et le faux positif à éviter
# --------------------------------------------------------------------------- #
def test_deux_fois_la_meme_donnee_est_une_retransmission():
    resultats = anomalies.retransmissions([
        paquet(seq=500, horodatage="2026-10-05T10:00:00+00:00"),
        paquet(seq=500, horodatage="2026-10-05T10:00:01+00:00"),
    ])
    assert len(resultats) == 1
    assert resultats[0]["occurrences"] == 2
    assert resultats[0]["seq"] == 500
    assert any("charge utile non nulle" in critere for critere in resultats[0]["criteres"])


def test_un_accuse_de_reception_ne_compte_pas_comme_une_retransmission():
    """Le piège classique : un ACK pur reprend le numéro de séquence du paquet précédent.

    Sans la condition sur la charge utile, la liste se remplirait de faux positifs — et une
    liste qu'on ne peut pas croire ne sert à rien.
    """
    resultats = anomalies.retransmissions([
        paquet(seq=500, charge=200, horodatage="2026-10-05T10:00:00+00:00"),
        paquet(seq=500, charge=0, drapeaux="ACK", horodatage="2026-10-05T10:00:01+00:00"),
    ])
    assert resultats == []


def test_le_meme_numero_dans_l_autre_sens_n_est_pas_une_retransmission():
    """Les deux sens numérotent leurs séquences indépendamment."""
    resultats = anomalies.retransmissions([
        paquet(seq=500, horodatage="2026-10-05T10:00:00+00:00"),
        paquet(seq=500, source="93.184.216.34", sport=443,
               destination="192.168.1.5", dport=51000,
               horodatage="2026-10-05T10:00:01+00:00"),
    ])
    assert resultats == []


def test_une_seule_occurrence_n_est_pas_une_retransmission():
    assert anomalies.retransmissions([paquet(seq=500)]) == []


# --------------------------------------------------------------------------- #
#  Fenêtre nulle
# --------------------------------------------------------------------------- #
def test_une_fenetre_nulle_est_signalee_et_qualifiee_de_normale():
    resultats = anomalies.fenetres_nulles([paquet(fenetre=0)])
    assert len(resultats) == 1
    assert any("régulation normal" in critere for critere in resultats[0]["criteres"])


def test_une_fenetre_normale_n_est_pas_signalee():
    assert anomalies.fenetres_nulles([paquet(fenetre=64240)]) == []


# --------------------------------------------------------------------------- #
#  RST inattendu
# --------------------------------------------------------------------------- #
def test_un_reset_en_premier_paquet_est_signale():
    resultats = anomalies.resets_inattendus([paquet(drapeaux="RST", horodatage="2026-10-05T10:00:00+00:00")])
    assert len(resultats) == 1
    assert any("PREMIER" in critere for critere in resultats[0]["criteres"])


def test_un_reset_apres_echange_n_est_pas_inattendu():
    """Une fermeture brutale après une conversation établie est banale."""
    resultats = anomalies.resets_inattendus([
        paquet(drapeaux="SYN", horodatage="2026-10-05T10:00:00+00:00"),
        paquet(drapeaux="SYN, ACK", horodatage="2026-10-05T10:00:01+00:00"),
        paquet(drapeaux="RST", horodatage="2026-10-05T10:00:02+00:00"),
    ])
    assert resultats == []


# --------------------------------------------------------------------------- #
#  Poignée de main incomplète
# --------------------------------------------------------------------------- #
def test_un_syn_sans_reponse_est_une_poignee_incomplete():
    resultats = anomalies.poignees_incompletes([
        paquet(drapeaux="SYN", seq=0, charge=0),
        paquet(drapeaux="SYN", seq=0, charge=0, horodatage="2026-10-05T10:00:03+00:00"),
    ])
    assert len(resultats) == 1
    assert any("trois explications possibles" in critere for critere in resultats[0]["criteres"])


def test_une_poignee_de_main_complete_n_est_pas_signalee():
    """Un SYN-ACK porte SYN **et** ACK : sa présence innocente la conversation."""
    resultats = anomalies.poignees_incompletes([
        paquet(drapeaux="SYN", seq=0, charge=0, horodatage="2026-10-05T10:00:00+00:00"),
        paquet(drapeaux="SYN, ACK", seq=0, charge=0, source="93.184.216.34", sport=443,
               destination="192.168.1.5", dport=51000, horodatage="2026-10-05T10:00:01+00:00"),
        paquet(drapeaux="ACK", charge=0, horodatage="2026-10-05T10:00:02+00:00"),
    ])
    assert resultats == []


def test_un_ack_seul_ne_prouve_pas_une_reponse():
    """Un ACK apparaît sur presque tous les paquets : il ne remplace pas un SYN-ACK."""
    resultats = anomalies.poignees_incompletes([
        paquet(drapeaux="SYN", seq=0, charge=0, horodatage="2026-10-05T10:00:00+00:00"),
        paquet(drapeaux="ACK", charge=0, horodatage="2026-10-05T10:00:01+00:00"),
    ])
    assert len(resultats) == 1


# --------------------------------------------------------------------------- #
#  Vue d'ensemble
# --------------------------------------------------------------------------- #
def test_l_ensemble_ne_produit_jamais_d_alerte():
    """La règle du projet : aucune règle isolée ne produit une alerte."""
    resultat = anomalies.analyser([
        paquet(seq=500, fenetre=0, drapeaux="R", horodatage="2026-10-05T10:00:00+00:00"),
        paquet(seq=500, fenetre=0, drapeaux="R", horodatage="2026-10-05T10:00:01+00:00"),
    ])
    assert resultat["niveau"] == "observation"
    assert "aucune" in resultat["note"]
    assert resultat["total"] > 0


def test_l_ensemble_dit_combien_de_paquets_il_a_examines():
    """Sans ce chiffre, une liste vide ne distingue pas « rien d'anormal » de « rien lu »."""
    vide = anomalies.analyser([])
    assert vide["paquets_examines"] == 0
    assert vide["total"] == 0
    assert anomalies.analyser([paquet(), paquet(seq=2000)])["paquets_examines"] == 2


def test_un_ensemble_vide_ne_provoque_aucune_erreur():
    resultat = anomalies.analyser([])
    assert resultat["comptes"] == {
        "retransmission": 0, "poignee_incomplete": 0,
        "reset_inattendu": 0, "fenetre_nulle": 0,
    }

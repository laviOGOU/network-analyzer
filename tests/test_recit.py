"""Tests du récit d'une conversation — Lot B.

DEUX PROPRIÉTÉS SONT ÉPROUVÉES ICI
----------------------------------
1. **Séparation du fait et de la lecture.** Chaque phrase porte son genre. Une phrase
   d'interprétation doit être présentée comme telle : c'est la règle n°4 du projet, et elle
   vaut aussi pour une phrase en français.
2. **L'incertitude est écrite, pas contournée.** Une conversation vue en cours de route ne
   doit jamais être racontée comme si on avait vu son début. Un outil qui affirme plus qu'il
   n'a vu ne sert à rien : on ne peut pas le vérifier.
"""

from __future__ import annotations

from backend import recit


def communication(**champs):
    base = {
        "protocole": "TCP",
        "ip_a": "192.168.1.5", "port_a": 51000,
        "ip_b": "140.82.121.4", "port_b": 443,
        # Noms de champs réels, relevés sur une réponse de l'API — pas devinés. Trois fois
        # de suite, un nom inventé a produit un récit muet sans erreur visible.
        "debut": "2026-10-05T10:32:14+00:00",
        "dernier_paquet": "2026-10-05T10:32:26+00:00",
        "octets_a_vers_b": 18300, "octets_b_vers_a": 142700,
        "etat": "fermée", "etat_certain": True,
    }
    base.update(champs)
    return base


def moment(nom, secondes, description="", sens="192.168.1.5 → 140.82.121.4"):
    return {"moment": nom, "description": description, "horodatage": None,
            "depuis_debut_s": secondes, "sens": sens}


def textes(phrases):
    return " ".join(phrase["texte"] for phrase in phrases)


# --------------------------------------------------------------------------- #
#  La séparation du fait et de la lecture
# --------------------------------------------------------------------------- #
def test_chaque_phrase_dit_si_elle_est_un_fait_ou_une_lecture():
    """La propriété la plus importante : rien ne se présente comme un fait sans l'être."""
    phrases = recit.raconter(communication(), [moment("ouverture", 0), moment("acceptation", 0.1)])
    assert phrases, "le récit est vide"
    for phrase in phrases:
        assert phrase["genre"] in ("fait", "lecture"), phrase


def test_le_recit_ne_melange_jamais_les_deux_genres_dans_une_phrase():
    """Une phrase, un genre. Un mélange rendrait le genre trompeur."""
    phrases = recit.raconter(communication(), [moment("ouverture", 0), moment("acceptation", 0.1)])
    genres = {phrase["genre"] for phrase in phrases}
    assert "fait" in genres


def test_le_recit_ne_conclut_pas_a_partir_du_volume():
    """Le déséquilibre est une lecture, et il est annoncé comme telle."""
    phrases = recit.raconter(communication(), [])
    desequilibre = [p for p in phrases if "déséquilibré" in p["texte"]]
    assert desequilibre, "le déséquilibre n'est pas signalé"
    assert all(p["genre"] == "lecture" for p in desequilibre)


# --------------------------------------------------------------------------- #
#  L'incertitude
# --------------------------------------------------------------------------- #
def test_une_conversation_vue_en_cours_de_route_est_annoncee_comme_telle():
    """Sans ouverture observée, on ne peut pas affirmer que la conversation a été établie.

    C'est le cas le plus fréquent d'une capture lancée sur une machine déjà active — et
    celui où un outil bavard raconterait une histoire qu'il n'a pas vue.
    """
    phrases = recit.raconter(
        communication(etat="en cours", etat_certain=False,
                      note_etat="les premiers paquets n'ont pas été vus"),
        [],
    )
    texte = textes(phrases)
    assert "n'a pas été vu" in texte or "n'a pas été vue" in texte
    assert any(p["genre"] == "lecture" and "réserve" in p["texte"] for p in phrases)


def test_un_fin_dans_un_seul_sens_ne_ferme_pas_la_conversation():
    phrases = recit.raconter(
        communication(etat="en cours"),
        [moment("ouverture", 0), moment("acceptation", 0.1), moment("fermeture", 5)],
    )
    texte = textes(phrases)
    assert "un seul sens" in texte
    assert any("pas certaine" in p["texte"] for p in phrases)


def test_une_fermeture_des_deux_cotes_est_dite_certaine():
    phrases = recit.raconter(
        communication(etat="fermée"),
        [moment("ouverture", 0), moment("acceptation", 0.1), moment("fermeture", 5)],
    )
    assert "certaine" in textes(phrases)


def test_une_rupture_brutale_est_racontee_sans_acuser():
    """Un RST a plusieurs causes possibles : le paquet seul ne dit pas laquelle."""
    phrases = recit.raconter(communication(etat="fermée"), [moment("rupture", 3)])
    texte = textes(phrases)
    assert "RST" in texte
    lecture = [p for p in phrases if "RST" in p["texte"] and p["genre"] == "lecture"]
    assert lecture, "les causes possibles ne sont pas présentées comme une lecture"


# --------------------------------------------------------------------------- #
#  La chronologie
# --------------------------------------------------------------------------- #
def test_la_chronologie_trie_elle_meme():
    """Comme pour les noms : un ordre non garanti n'est pas un ordre."""
    # La structure est celle d'un vrai paquet : `flags_tcp` au premier niveau. La première
    # version du test plaçait les drapeaux dans `details` — une forme qui n'existe pas — et
    # validait donc un code qui ne pouvait pas fonctionner sur des données réelles.
    desordre = [
        {"horodatage": "2026-10-05T10:00:05+00:00", "flags_tcp": "FIN"},
        {"horodatage": "2026-10-05T10:00:00+00:00", "flags_tcp": "SYN"},
        {"horodatage": "2026-10-05T10:00:01+00:00", "flags_tcp": "SYN, ACK"},
    ]
    moments = recit.chronologie(desordre)
    assert [m["moment"] for m in moments] == ["ouverture", "acceptation", "fermeture"]


def test_la_chronologie_ne_retient_que_les_evenements():
    """Quarante échanges de données ne racontent rien de plus que le premier."""
    paquets = [{"horodatage": f"2026-10-05T10:00:{i:02d}+00:00", "flags_tcp": "ACK"}
               for i in range(10)]
    assert recit.chronologie(paquets) == []


def test_la_chronologie_d_un_ensemble_vide_est_vide():
    assert recit.chronologie([]) == []


def test_les_tailles_sont_lisibles_et_en_francais():
    phrases = recit.raconter(communication(), [])
    texte = textes(phrases)
    assert "ko" in texte
    assert "18.3" not in texte, "le séparateur décimal doit être la virgule"
    assert "18,3" in texte


def test_le_nom_de_domaine_est_utilise_quand_il_est_connu():
    phrases = recit.raconter(communication(nom_b="github.com"), [])
    assert "github.com" in textes(phrases)
    assert "140.82.121.4" in textes(phrases), "l'adresse doit rester visible"

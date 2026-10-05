"""Tests des profils d'analyse (Lot C).

CE QUI EST ÉPROUVÉ ICI
----------------------
1. **Un profil ne peut pas être enregistré avec un filtre invalide.** La validation se fait
   au moment de l'enregistrement, par le même parseur que celui qui appliquera le filtre :
   l'erreur est refusée quand celui qui la commet est encore devant l'écran, pas découverte
   en pleine analyse.
2. **Un fichier abîmé ne met pas l'application en panne.** Un tableau de bord qui refuse de
   s'ouvrir parce qu'un fichier de configuration est illisible serait une panne pour rien.

Chaque test écrit dans un fichier temporaire : aucun ne touche la configuration réelle du
poste qui l'exécute.
"""

from __future__ import annotations

import json

import pytest

from backend import profils


@pytest.fixture()
def fichier_profils(tmp_path, monkeypatch):
    """Redirige les profils vers un fichier temporaire, propre à chaque test."""
    chemin = tmp_path / "profils.json"
    monkeypatch.setattr(profils, "CHEMIN_PROFILS", str(chemin))
    return chemin


# --------------------------------------------------------------------------- #
#  Les profils proposés
# --------------------------------------------------------------------------- #
def test_sans_fichier_les_profils_proposes_sont_rendus(fichier_profils):
    proposes = profils.charger()
    assert [p["nom"] for p in proposes][0] == "Tout"
    assert len(proposes) == len(profils.PROFILS_INCLUS)


def test_tous_les_profils_proposes_ont_un_filtre_valide():
    """Un profil livré avec un filtre que l'application refuse serait une promesse en l'air."""
    for propose in profils.PROFILS_INCLUS:
        propre = profils.valider(propose)
        assert propre["nom"]
        assert propre["description"], propose["nom"]


def test_chaque_profil_propose_dit_a_quoi_il_sert():
    for propose in profils.PROFILS_INCLUS:
        assert len(propose["description"]) > 15, propose["nom"]


# --------------------------------------------------------------------------- #
#  La validation — au moment de l'enregistrement, pas de l'application
# --------------------------------------------------------------------------- #
def test_un_profil_sans_nom_est_refuse():
    with pytest.raises(profils.ProfilInvalide, match="nom"):
        profils.valider({"nom": "   ", "filtre": ""})


def test_un_filtre_de_syntaxe_invalide_est_refuse_a_l_enregistrement(fichier_profils):
    """Le refus doit arriver maintenant, pas au moment où l'on croira filtrer."""
    with pytest.raises(profils.ProfilInvalide):
        profils.enregistrer({"nom": "Cassé", "filtre": "champ_qui_n_existe_pas:valeur"})


def test_un_filtre_valide_est_accepte(fichier_profils):
    profils.enregistrer({"nom": "Web", "filtre": "proto:tcp port:443"})
    assert "Web" in [p["nom"] for p in profils.charger()]


def test_un_profil_sans_filtre_est_valide(fichier_profils):
    """« Tout » est un profil légitime : ne rien filtrer est un choix."""
    profils.enregistrer({"nom": "Tout voir", "filtre": ""})
    enregistre = next(p for p in profils.charger() if p["nom"] == "Tout voir")
    assert enregistre["filtre"] == ""


def test_un_nom_trop_long_est_borne(fichier_profils):
    """Ce qui vient d'un formulaire ne doit pas pouvoir grossir le fichier sans limite."""
    profils.enregistrer({"nom": "a" * 500, "filtre": ""})
    assert len(profils.charger()[-1]["nom"]) <= profils.LONGUEUR_NOM


def test_les_caracteres_de_controle_sont_retires(fichier_profils):
    profils.enregistrer({"nom": "Web\x00\x01", "filtre": ""})
    assert "\x00" not in profils.charger()[-1]["nom"]


# --------------------------------------------------------------------------- #
#  Enregistrement et suppression
# --------------------------------------------------------------------------- #
def test_un_meme_nom_remplace_au_lieu_de_doubler(fichier_profils):
    profils.enregistrer({"nom": "Web", "filtre": "proto:tcp"})
    profils.enregistrer({"nom": "Web", "filtre": "proto:udp"})
    occurrences = [p for p in profils.charger() if p["nom"] == "Web"]
    assert len(occurrences) == 1
    assert occurrences[0]["filtre"] == "proto:udp"


def test_le_remplacement_ignore_la_casse_du_nom(fichier_profils):
    profils.enregistrer({"nom": "Web", "filtre": "proto:tcp"})
    profils.enregistrer({"nom": "WEB", "filtre": "proto:udp"})
    assert len([p for p in profils.charger() if p["nom"].lower() == "web"]) == 1


def test_supprimer_un_profil_le_retire(fichier_profils):
    profils.enregistrer({"nom": "À jeter", "filtre": ""})
    profils.supprimer("À jeter")
    assert "À jeter" not in [p["nom"] for p in profils.charger()]


def test_supprimer_un_nom_absent_n_est_pas_une_erreur(fichier_profils):
    """Le résultat voulu est atteint : refuser obligerait l'appelant à vérifier avant."""
    reste = profils.supprimer("n'existe pas")
    assert isinstance(reste, list)


def test_le_nombre_de_profils_est_borne(fichier_profils):
    """La limite porte sur la liste entière, profils proposés compris.

    Les profils proposés sont rendus tant que le fichier n'existe pas, puis enregistrés avec
    les autres : ils occupent donc des places. Le test en tient compte — le borner au nombre
    de profils enregistrés aurait échoué à l'intérieur même de sa boucle.
    """
    # On remplit jusqu'au refus, plutôt que de calculer le nombre exact de places : les
    # profils proposés sont rendus tant que le fichier n'existe pas, puis enregistrés avec
    # les autres, et compter sur cette bascule rendrait le test fragile sans rien prouver de
    # plus. Ce qui compte est qu'un refus finisse par arriver, et qu'il soit explicite.
    with pytest.raises(profils.ProfilInvalide, match="Trop de profils"):
        for index in range(profils.MAX_PROFILS + 5):
            profils.enregistrer({"nom": f"Profil {index}", "filtre": ""})

    assert len(profils.charger()) <= profils.MAX_PROFILS


# --------------------------------------------------------------------------- #
#  Robustesse du fichier
# --------------------------------------------------------------------------- #
def test_un_fichier_illisible_ne_met_pas_l_application_en_panne(fichier_profils):
    fichier_profils.write_text("{ceci n'est pas du json", encoding="utf-8")
    assert len(profils.charger()) == len(profils.PROFILS_INCLUS)


def test_une_entree_abimee_est_ecartee_sans_perdre_les_autres(fichier_profils):
    fichier_profils.write_text(json.dumps([
        {"nom": "Bon", "filtre": "proto:tcp", "description": "valide"},
        {"nom": "", "filtre": ""},
    ]), encoding="utf-8")
    noms = [p["nom"] for p in profils.charger()]
    assert noms == ["Bon"]


def test_aucun_secret_n_est_ecrit_dans_le_fichier(fichier_profils):
    """Un profil décrit une façon de regarder, rien d'autre."""
    profils.enregistrer({"nom": "Web", "filtre": "proto:tcp",
                         "jeton": "secret-qui-ne-doit-pas-etre-ecrit"})
    contenu = fichier_profils.read_text(encoding="utf-8")
    assert "secret-qui-ne-doit-pas-etre-ecrit" not in contenu
    assert set(json.loads(contenu)[0]) == {"nom", "filtre", "description"}

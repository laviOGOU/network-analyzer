"""Supprimer une capture.

L'effacement touche des données définitives : il doit être juste, et refuser proprement ce
qu'il ne peut pas traiter. Ces tests portent sur le stockage, là où la décision est prise.
"""

from __future__ import annotations

import pytest

from backend.storage import Stockage


def test_supprimer_une_capture_inconnue_rend_zero() -> None:
    """Un identifiant qui n'existe pas n'est pas une erreur : c'est un compte rendu.

    Un « 0 » dit honnêtement que rien n'a été supprimé. Lever une exception ferait croire à
    une panne là où il n'y a qu'une capture déjà effacée — le cas se produit dès qu'un
    navigateur garde une page ouverte après une suppression.
    """
    assert Stockage().supprimer_session("00000000-0000-0000-0000-000000000000") == 0


def test_supprimer_deux_fois_la_meme_capture() -> None:
    """La seconde suppression rend 0, sans rien casser."""
    stockage = Stockage()
    identifiant = "11111111-1111-1111-1111-111111111111"
    stockage._sessions[identifiant] = {"identifiant": identifiant, "dernier": "2026-10-07T10:00:00"}
    assert stockage.supprimer_session(identifiant) == 1
    assert stockage.supprimer_session(identifiant) == 0
    assert stockage.session(identifiant) is None

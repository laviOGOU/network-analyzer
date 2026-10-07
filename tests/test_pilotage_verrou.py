"""Arreter une capture ne doit jamais figer le serveur.

`Pilote.arreter()` prend un verrou, et appelait `self.etat()` EN LE TENANT. Or `etat()` reprend
ce meme verrou au debut. Un `threading.Lock` n'etant pas reentrant, le thread se bloquait sur son
propre verrou, pour toujours - et comme il le gardait, TOUTE route touchant ce verrou restait
pendue. Le tableau de bord devenait muet, sans le moindre message d'erreur.

Le cas declencheur est le plus banal qui soit : arreter une capture deja arretee.
"""

from __future__ import annotations

import threading

from backend.pilotage import Pilote


def test_arreter_sans_capture_ne_bloque_pas() -> None:
    """Le cas qui figeait le serveur : aucune capture en cours, et on demande l'arret.

    Le test echoue en se bloquant si le defaut revient, d'ou le delai maximal : sans lui, une
    regression ferait pendre la suite de tests au lieu de la faire echouer.
    """
    pilote = Pilote()
    resultat = []

    fil = threading.Thread(target=lambda: resultat.append(pilote.arreter()), daemon=True)
    fil.start()
    fil.join(timeout=5)

    assert not fil.is_alive(), "arreter() s'est bloque : le verrou est repris depuis lui-meme"
    assert resultat, "arreter() doit rendre l'etat courant"
    assert resultat[0]["en_cours"] is False


def test_arreter_deux_fois_de_suite_ne_bloque_pas() -> None:
    """Deux arrets consecutifs : le second suit exactement le meme chemin que dans le defaut."""
    pilote = Pilote()
    for _ in range(2):
        fil = threading.Thread(target=pilote.arreter, daemon=True)
        fil.start()
        fil.join(timeout=5)
        assert not fil.is_alive(), "le second arret s'est bloque"

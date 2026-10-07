"""Arguments de l'agent : le piege du tiret dans le jeton.

Le jeton d'agent est une chaine aleatoire qui peut commencer par un tiret. Ecrit
« --jeton -abc123 », argparse prend « -abc123 » pour une AUTRE OPTION et refuse l'appel
entier :

    agent: error: argument --jeton: expected one argument

L'agent n'est alors jamais lance, la capture ne demarre pas, et rien ne le dit dans
l'interface : le bouton semble simplement ne rien faire. Ce test verrouille la forme
correcte de l'appel, ou la valeur est collee a son option par un signe egal.
"""

from __future__ import annotations

import pytest

from agent.main import construire_analyseur


def test_jeton_commencant_par_un_tiret_est_accepte() -> None:
    """Le jeton colle a son option par « = » traverse argparse intact."""
    analyseur = construire_analyseur()
    arguments = analyseur.parse_args([
        "--interface=X",
        "--backend=http://127.0.0.1:8000",
        "--jeton=-abc123def456",
    ])
    assert arguments.jeton == "-abc123def456"


def test_jeton_separe_par_un_espace_est_refuse() -> None:
    """La forme fautive est bien refusee : si argparse l'acceptait un jour, ce test le dirait.

    Il documente la raison d'etre du signe egal. Sans lui, quelqu'un pourrait revenir a la
    forme « --jeton VALEUR » en la croyant equivalente.
    """
    analyseur = construire_analyseur()
    with pytest.raises(SystemExit):
        analyseur.parse_args([
            "--interface=X",
            "--backend=http://127.0.0.1:8000",
            "--jeton", "-abc123def456",
        ])


def test_toutes_les_valeurs_sont_collees_par_un_signe_egal() -> None:
    """Le pilotage ne doit pas revenir a la forme separee, pour AUCUNE option.

    Un nom de session ou un filtre peut commencer par un tiret tout autant qu'un jeton.
    """
    import io as _io
    source = _io.open("backend/pilotage.py", encoding="utf-8").read()
    for option in ("interface", "backend", "jeton", "nom", "duree", "filtre"):
        assert f'f"--{option}=' in source, (
            f"l'option --{option} doit etre collee a sa valeur par un signe egal"
        )

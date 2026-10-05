"""Identifiants de session — une seule conversion, partagée.

Un agent envoie un identifiant unique ; un outil de vérification envoie souvent un nom
lisible (« capture-du-matin »). Les deux doivent fonctionner, et le même libellé doit
désigner la même session d'une exécution à l'autre.

Ce module existe pour une raison précise : la conversion est utilisée par le stockage
PostgreSQL **et** par la traduction des filtres. Placée dans le stockage, elle aurait
obligé la traduction à l'importer — et le stockage importe déjà la traduction. La mettre
dans un module qui ne dépend de rien coupe le cycle au lieu de le contourner.
"""

from __future__ import annotations

import uuid

#: Espace de noms fictif, utilisé uniquement pour dériver un identifiant stable à partir
#: d'un libellé. `uuid5` est déterministe : le même libellé donne toujours le même
#: identifiant, sur n'importe quelle machine — ce qui rend les tests reproductibles.
ESPACE_SESSIONS = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")


def identifiant_session(libelle: str) -> str:
    """Convertit un libellé de session en identifiant stable."""
    try:
        return str(uuid.UUID(libelle))
    except (ValueError, AttributeError, TypeError):
        return str(uuid.uuid5(ESPACE_SESSIONS, str(libelle)))

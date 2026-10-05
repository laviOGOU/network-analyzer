"""Route d'ingestion : l'agent y dépose les paquets qu'il a analysés.

La route ne contient aucune logique métier : elle valide (par les types Pydantic),
vérifie le droit d'écrire (dépendances), délègue au stockage, et rend un compte rendu.
C'est ce qui la rend lisible et testable — et ce qui permettra de remplacer le stockage
en mémoire par Supabase sans la rouvrir.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from backend.dependances import obtenir_stockage
from backend.models import AccuseReception, LotPaquets
from backend.securite import verifier_debit, verifier_jeton
from backend.storage import Stockage, details_reduits

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ingestion"])


@router.post("/ingest", response_model=AccuseReception, summary="Recevoir un lot de paquets")
def ingerer(
    lot: LotPaquets,
    request: Request,
    _jeton: Annotated[None, Depends(verifier_jeton)],
    _debit: Annotated[None, Depends(verifier_debit)],
    stockage: Annotated[Stockage, Depends(obtenir_stockage)],
) -> AccuseReception:
    """Enregistre un lot de paquets analysés.

    Le nombre de paquets acceptés est renvoyé à l'agent : il peut ainsi comparer ce qu'il
    a envoyé à ce qui a été conservé, et signaler une perte plutôt que de la subir en
    silence.
    """
    # On ne conserve pas le dictionnaire de détails tel quel : il est filtré pour ne
    # garder que ce qui sera affiché, ce qui borne aussi la taille en mémoire.
    propres = [paquet.model_dump() for paquet in lot.paquets]
    for paquet in propres:
        paquet["details"] = details_reduits(paquet.get("details") or {})

    acceptes = stockage.enregistrer_lot(lot.session, lot.agent, propres)
    communications = stockage.enregistrer_communications(
        lot.session, [communication.model_dump() for communication in lot.communications])
    origine = request.client.host if request.client else "inconnue"
    logger.info("Lot reçu : %d paquets de %s (agent %s, origine %s)",
                acceptes, lot.session, lot.agent, origine)

    return AccuseReception(acceptes=acceptes, session=lot.session,
                           total_session=stockage.session(lot.session)["paquets"],
                           communications=communications)

"""Schémas Pydantic : le contrat entre l'agent et le backend.

Pourquoi valider à l'entrée plutôt que faire confiance à l'agent
----------------------------------------------------------------
L'endpoint d'ingestion est joignable par le réseau. Même protégé par un jeton, il reçoit
des données qu'il n'a pas produites. Trois raisons de les valider :

1. **Sécurité** — un champ texte non borné peut faire grossir la base jusqu'à la saturer.
   Chaque chaîne a donc une longueur maximale, chaque nombre un intervalle.
2. **Cohérence** — un port à 99 999 ou une taille négative produiraient des statistiques
   fausses, impossibles à repérer ensuite. Ils sont refusés à l'entrée.
3. **Diagnostic** — si l'agent et le backend divergent, la divergence doit être bruyante.
   `extra="forbid"` fait échouer un champ inconnu au lieu de l'ignorer en silence.

Ce que ce module n'est pas : un modèle de base de données. Les tables viennent en phase
suivante ; ici on décrit seulement ce qui circule.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

#: Longueurs maximales. Elles ne sont pas décoratives : sans elles, un agent (ou un
#: imposteur muni d'un jeton) pourrait envoyer un champ de plusieurs mégaoctets, répété
#: mille fois par lot.
MAX_TEXTE_COURT = 64
MAX_TEXTE = 255
MAX_RESUME = 200

Port = Annotated[int, Field(ge=0, le=65535)]
Taille = Annotated[int, Field(ge=0, le=10_000_000)]


class FichePaquet(BaseModel):
    """Un paquet tel qu'il est transmis : des métadonnées, jamais de contenu.

    Tous les champs sont facultatifs sauf l'horodatage et la taille : un paquet peut être
    tronqué, d'un protocole inconnu, ou capturé sans son début. Un modèle qui exigerait
    une adresse IP refuserait ces cas pourtant normaux.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    horodatage: datetime
    taille: Taille | None = None
    taille_capturee: Taille | None = None

    protocole: Annotated[str, Field(max_length=MAX_TEXTE_COURT)] = "inconnu"
    couches: Annotated[list[str], Field(max_length=16)] = Field(default_factory=list)

    ip_source: Annotated[str, Field(max_length=45)] | None = None
    ip_destination: Annotated[str, Field(max_length=45)] | None = None
    mac_source: Annotated[str, Field(max_length=17)] | None = None
    mac_destination: Annotated[str, Field(max_length=17)] | None = None
    version_ip: Annotated[int, Field(ge=4, le=6)] | None = None

    port_source: Port | None = None
    port_destination: Port | None = None
    flags_tcp: Annotated[str, Field(max_length=64)] | None = None
    ttl: Annotated[int, Field(ge=0, le=255)] | None = None
    longueur_transport: Taille | None = None

    resume: Annotated[str, Field(max_length=MAX_RESUME)] = ""
    analyse_partielle: bool = False
    motif_partiel: Annotated[str, Field(max_length=MAX_RESUME)] | None = None

    #: Informations applicatives dérivées (nom DNS demandé, type de requête…). Le
    #: dictionnaire est libre, mais borné : 16 clés au plus, chacune courte.
    details: dict[Annotated[str, Field(max_length=40)], Any] = Field(default_factory=dict)

    @field_validator("ip_source", "ip_destination", mode="after")
    @classmethod
    def _adresse_valide(cls, valeur: str | None) -> str | None:
        """Refuse une adresse IP impossible.

        `ipaddress` connaît IPv4 et IPv6, y compris les formes compressées. Valider ici
        évite qu'une chaîne arbitraire (« 999.1.1.1 ») se retrouve affichée comme une
        adresse et fausse les regroupements par machine.
        """
        if valeur is None:
            return None
        try:
            return str(ipaddress.ip_address(valeur))
        except ValueError as erreur:
            raise ValueError(f"adresse IP invalide : {valeur!r}") from erreur

    @field_validator("details", mode="after")
    @classmethod
    def _details_bornes(cls, valeur: dict[str, Any]) -> dict[str, Any]:
        """Borne le dictionnaire de détails : au plus 16 entrées, valeurs courtes."""
        if len(valeur) > 16:
            raise ValueError("trop d'entrées dans « details » (16 au maximum)")
        for cle, contenu in valeur.items():
            if isinstance(contenu, str) and len(contenu) > MAX_TEXTE:
                raise ValueError(f"valeur trop longue pour « {cle} » "
                                 f"({len(contenu)} caractères, {MAX_TEXTE} au maximum)")
        return valeur


class LotPaquets(BaseModel):
    """Un lot transmis par l'agent : la session de capture, l'agent, et les paquets."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    session: Annotated[str, Field(min_length=1, max_length=MAX_TEXTE_COURT)]
    agent: Annotated[str, Field(min_length=1, max_length=120)] = "agent-local"
    paquets: Annotated[list[FichePaquet], Field(min_length=1, max_length=1000)]


class AccuseReception(BaseModel):
    """Réponse à un lot. Le compte renvoyé permet à l'agent de détecter une perte."""

    acceptes: int
    session: str
    total_session: int


class Statistiques(BaseModel):
    """Chiffres du tableau de bord. Calculés côté backend, jamais par le navigateur."""

    paquets_total: int = 0
    octets_total: int = 0
    par_protocole: dict[str, int] = Field(default_factory=dict)
    top_sources: list[dict[str, Any]] = Field(default_factory=list)
    top_destinations: list[dict[str, Any]] = Field(default_factory=list)
    ports_frequents: list[dict[str, Any]] = Field(default_factory=list)
    premier_paquet: datetime | None = None
    dernier_paquet: datetime | None = None
    analyses_partielles: int = 0

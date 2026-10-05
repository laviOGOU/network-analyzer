"""Export d'une session — CSV et JSON.

POURQUOI DEUX FORMATS, ET PAS UN SEUL
-------------------------------------
Le **CSV** s'ouvre dans un tableur : c'est le format qu'on demande quand on veut trier,
recouper, ou joindre une capture à un rapport. Le **JSON** garde la structure — les listes
imbriquées, les détails d'un paquet — que le CSV aplatit forcément.

Les deux sont proposés parce qu'ils ne servent pas à la même chose, et qu'un export qui
obligerait à choisir entre perdre la structure et perdre le tableur serait un demi-service.

CE QUI N'EST PAS EXPORTÉ, ET POURQUOI
-------------------------------------
Aucun contenu de message. L'outil ne conserve que des métadonnées — c'est l'une des règles
du projet, et elle vaut aussi pour l'export. Ce qui sort est exactement ce que le tableau
de bord affiche : adresses, ports, protocoles, volumes, états, explications.

Deux détails qui comptent pour un tableur français :

    - le fichier commence par une marque d'ordre des octets (BOM UTF-8), sans quoi Excel
      affiche « Ã© » à la place de « é » ;
    - le séparateur est le point-virgule, parce que c'est ce qu'attend un tableur configuré
      en français. Un CSV à virgules y arrive en une seule colonne.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

#: Nombre maximal de lignes exportées. Un export n'est pas une copie de la base : au-delà
#: de quelques milliers de lignes, le fichier ne s'ouvre plus, et personne ne le lit.
LIGNES_MAX = 5000

#: Colonnes exportées, par vue. Elles sont nommées en français, comme l'interface : un
#: export se lit à côté du tableau de bord, et deux vocabulaires côte à côte se lisent mal.
COLONNES: dict[str, list[tuple[str, str]]] = {
    "paquets": [
        ("horodatage", "horodatage"),
        ("protocole", "protocole"),
        ("ip_source", "ip_source"),
        ("ip_destination", "ip_destination"),
        ("port_source", "port_source"),
        ("port_destination", "port_destination"),
        ("taille", "taille"),
        ("ttl", "ttl"),
        ("flags_tcp", "flags_tcp"),
        ("analyse_partielle", "analyse partielle"),
    ],
    "communications": [
        ("debut", "début"),
        ("dernier_paquet", "dernier paquet"),
        ("protocole", "protocole"),
        ("ip_a", "extrémité A"),
        ("port_a", "port A"),
        ("ip_b", "extrémité B"),
        ("port_b", "port B"),
        ("etat", "état"),
        ("etat_certain", "état observé"),
        ("paquets_a_vers_b", "paquets A→B"),
        ("paquets_b_vers_a", "paquets B→A"),
        ("octets_a_vers_b", "octets A→B"),
        ("octets_b_vers_a", "octets B→A"),
        ("duree_secondes", "durée (s)"),
        ("note_etat", "ce qui manque"),
    ],
    "detections": [
        ("niveau", "niveau"),
        ("regle", "règle"),
        ("titre", "titre"),
        ("cible", "cible"),
        ("confiance", "confiance"),
        ("occurrences", "occurrences"),
        ("debut", "observée le"),
        ("dernier", "dernière observation"),
        ("faits_observes", "faits observés"),
        ("explication", "explication"),
        ("faux_positifs", "faux positifs possibles"),
    ],
}


def _cellule(valeur: Any) -> str:
    """Rend une valeur exportable en texte, sans jamais lever.

    Les listes deviennent du texte séparé par des barres verticales : un CSV n'a pas de
    case pour une liste, et la remplir de virgules casserait le fichier.
    """
    if valeur is None:
        return ""
    if isinstance(valeur, bool):
        return "oui" if valeur else "non"
    if isinstance(valeur, (list, tuple)):
        return " | ".join(str(element) for element in valeur)
    if isinstance(valeur, dict):
        return json.dumps(valeur, ensure_ascii=False)
    return str(valeur)


def vers_csv(lignes: list[dict[str, Any]], vue: str, separateur: str = ";") -> str:
    """Rend un CSV lisible par un tableur français, avec sa marque d'encodage.

    Le BOM en tête n'est pas une élégance : sans lui, Excel ouvre le fichier en supposant
    un autre encodage et transforme chaque accent en deux caractères. C'est le genre de
    détail qui fait qu'un export « ne marche pas » alors qu'il est correct.
    """
    colonnes = COLONNES.get(vue)
    if colonnes is None:
        raise ValueError(f"Vue inconnue : {vue}")

    tampon = io.StringIO()
    # QUOTE_MINIMAL laisse le module gérer les guillemets : c'est lui qui sait qu'un texte
    # contenant le séparateur, un guillemet ou un retour à la ligne doit être protégé.
    ecrivain = csv.writer(tampon, delimiter=separateur, quoting=csv.QUOTE_MINIMAL,
                          lineterminator="\r\n")
    ecrivain.writerow([intitule for _, intitule in colonnes])
    for ligne in lignes[:LIGNES_MAX]:
        ecrivain.writerow([_cellule(ligne.get(cle)) for cle, _ in colonnes])
    return "\ufeff" + tampon.getvalue()


def vers_json(lignes: list[dict[str, Any]], vue: str) -> str:
    """Rend un JSON indenté, qui garde la structure que le CSV aplatit."""
    return json.dumps({
        "vue": vue,
        "lignes": len(lignes[:LIGNES_MAX]),
        "tronque": len(lignes) > LIGNES_MAX,
        "donnees": lignes[:LIGNES_MAX],
    }, ensure_ascii=False, indent=2, default=str)


def nom_de_fichier(vue: str, format_: str, horodatage: str) -> str:
    """Un nom de fichier qui dit ce qu'il contient et quand il a été produit.

    Sans date, deux exports du même jour s'écrasent dans le dossier des téléchargements,
    et l'on ne sait plus lequel est le bon.
    """
    date = "".join(caractere for caractere in horodatage[:19] if caractere.isdigit())
    return f"network-analyzer_{vue}_{date}.{format_}"

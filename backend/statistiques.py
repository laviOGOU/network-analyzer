"""Statistiques d'une capture — répartitions, extrémmités, débit.

POURQUOI UN MODULE DU BACKEND, ET NON DU STOCKAGE
-------------------------------------------------
Les mêmes chiffres doivent sortir du stockage en mémoire et de PostgreSQL. Écrire le calcul
deux fois, c'est garantir qu'il divergera : un pourcentage corrigé d'un côté, oublié de
l'autre, et deux tableaux de bord qui ne disent pas la même chose sans que personne ne
sache lequel croire.

Ce module reçoit donc des paquets, quelle qu'en soit la provenance, et rend des chiffres.
Les deux stockages lui donnent les mêmes, et il n'existe qu'un endroit où corriger.

CE QUE LES POURCENTAGES VEULENT DIRE
------------------------------------
Un pourcentage n'a de sens que si le total est nommé. « 62 % de TCP » ne veut rien dire si
l'on ignore si le reste est de l'UDP, de l'ARP, ou des paquets non analysés. Chaque
répartition rend donc **son total**, et un contrôle vérifie que la somme des pourcentages
retombe sur 100 % — aux arrondis près.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

#: Nombre d'extrémités rendues dans le classement. Au-delà, la liste cesse d'être lisible
#: et le classement n'apprend plus rien.
EXTREMITES_RENDUES = 20

#: Taille d'un seau du graphique de débit, en secondes. Assez court pour montrer une
#: accélération, assez long pour qu'une capture de quelques minutes ne produise pas mille
#: points illisibles.
SEAU_SECONDES = 1.0


def _secondes(horodatage: Any) -> float | None:
    if not horodatage:
        return None
    if isinstance(horodatage, (int, float)):
        return float(horodatage)
    texte = str(horodatage).replace("Z", "+00:00")
    try:
        moment = dt.datetime.fromisoformat(texte)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return moment.timestamp()


def _octets(paquet: dict[str, Any]) -> int:
    try:
        return int(paquet.get("taille") or 0)
    except (TypeError, ValueError):
        return 0


def _pourcentages(comptes: dict[str, int]) -> list[dict[str, Any]]:
    """Répartit des comptes en pourcentages, du plus fréquent au plus rare.

    Le reste de la division est absorbé par la part la plus grande, et non réparti au
    hasard : la somme doit retomber sur 100, sinon un lecteur qui additionne trouve 99 ou
    101 et cesse de croire au tableau.
    """
    total = sum(comptes.values())
    if not total:
        return []

    parts = []
    for nom, compte in sorted(comptes.items(), key=lambda item: (-item[1], str(item[0]))):
        parts.append({"nom": nom, "paquets": compte, "pourcent": round(100 * compte / total, 1)})

    ecart = round(100.0 - sum(part["pourcent"] for part in parts), 1)
    if parts and ecart:
        parts[0]["pourcent"] = round(parts[0]["pourcent"] + ecart, 1)

    for part in parts:
        part["pourcent"] = round(part["pourcent"], 1)
    return parts


def hierarchie(paquets: list[dict[str, Any]]) -> dict[str, Any]:
    """Répartition par protocole, en comptes et en pourcentages.

    Les paquets dont l'analyse est partielle sont comptés **à part**, jamais fondus dans un
    protocole connu : leur classer une famille serait inventer une information que le
    parseur n'a pas su lire.
    """
    comptes: dict[str, int] = {}
    partiels = 0

    for paquet in paquets:
        if paquet.get("analyse_partielle"):
            partiels += 1
            continue
        protocole = paquet.get("protocole") or "inconnu"
        comptes[protocole] = comptes.get(protocole, 0) + 1

    if partiels:
        comptes["analyse partielle"] = partiels

    return {
        "total": len(paquets),
        "protocoles": _pourcentages(comptes),
        "note": "Le total porte sur les paquets conservés dans la fenêtre analysée.",
    }


def extremites(paquets: list[dict[str, Any]]) -> dict[str, Any]:
    """Les machines qui parlent le plus — « top talkers ».

    Deux chiffres par machine : ce qu'elle a **émis** et ce qu'elle a **reçu**. Un classement
    sur le seul volume total confondrait un serveur qui répond beaucoup et une machine qui
    interroge beaucoup — or c'est précisément la distinction qui intéresse.
    """
    par_adresse: dict[str, dict[str, int]] = {}

    def fiche(adresse: str) -> dict[str, int]:
        return par_adresse.setdefault(adresse, {"emis": 0, "recus": 0,
                                                "octets_emis": 0, "octets_recus": 0,
                                                "ports": 0})

    for paquet in paquets:
        source = paquet.get("ip_source")
        destination = paquet.get("ip_destination")
        taille = _octets(paquet)

        if source:
            compte = fiche(str(source))
            compte["emis"] += 1
            compte["octets_emis"] += taille
        if destination:
            compte = fiche(str(destination))
            compte["recus"] += 1
            compte["octets_recus"] += taille

    classement = []
    for adresse, compte in par_adresse.items():
        classement.append({
            "adresse": adresse,
            "emis": compte["emis"],
            "recus": compte["recus"],
            "total": compte["emis"] + compte["recus"],
            "octets_emis": compte["octets_emis"],
            "octets_recus": compte["octets_recus"],
            "octets_total": compte["octets_emis"] + compte["octets_recus"],
        })

    classement.sort(key=lambda f: (-f["total"], f["adresse"]))
    return {
        "total": len(classement),
        "extremites": classement[:EXTREMITES_RENDUES],
        "note": "Émis et reçus sont distingués : un serveur qui répond beaucoup et une "
                "machine qui interroge beaucoup n'ont pas le même profil.",
    }


def debit(paquets: list[dict[str, Any]], seau: float = SEAU_SECONDES) -> dict[str, Any]:
    """Le volume échangé dans le temps, par seaux réguliers.

    Les seaux sont calés sur le premier paquet vu, pas sur l'horloge de la machine : un
    fichier `.pcap` rejoué plus tard doit produire le même graphique que la capture qui l'a
    produit. C'est la même décision que pour l'âge des conversations.
    """
    horodatages = [(_secondes(paquet.get("horodatage")), paquet) for paquet in paquets]
    horodatages = [(moment, paquet) for moment, paquet in horodatages if moment is not None]
    if not horodatages:
        return {"seau_secondes": seau, "points": [], "note": "Aucun paquet daté."}

    debut = min(moment for moment, _ in horodatages)
    comptes: dict[int, dict[str, int]] = {}

    for moment, paquet in horodatages:
        index = int((moment - debut) / seau)
        case = comptes.setdefault(index, {"paquets": 0, "octets": 0})
        case["paquets"] += 1
        case["octets"] += _octets(paquet)

    points = [
        {"offset_s": round(index * seau, 3), "paquets": case["paquets"], "octets": case["octets"]}
        for index, case in sorted(comptes.items())
    ]

    return {
        "seau_secondes": seau,
        "points": points,
        "maximum_octets": max((point["octets"] for point in points), default=0),
        "note": "Les seaux partent du premier paquet vu, jamais de l'horloge de la machine : "
                "un fichier rejoué produit le même graphique.",
    }


def ensemble(paquets: list[dict[str, Any]]) -> dict[str, Any]:
    """Toutes les statistiques d'un coup, avec le nombre de paquets examinés."""
    return {
        "paquets_examines": len(paquets),
        "hierarchie": hierarchie(paquets),
        "extremites": extremites(paquets),
        "debit": debit(paquets),
    }

"""Anomalies TCP — l'Expert Info du projet.

CE QUE CE MODULE AJOUTE
-----------------------
Un tableau de paquets se lit mal : quatre mille lignes où l'œil ne distingue rien. Ce que
Wireshark appelle l'Expert Info répond à une autre question — « y a-t-il quelque chose
d'anormal ici ? » — et c'est cette question que ce module traite.

CE QU'UNE ANOMALIE EST, ET N'EST PAS
------------------------------------
Une anomalie est un **fait mesuré** : « ce numéro de séquence a été envoyé deux fois »,
« cette fenêtre vaut zéro ». Elle n'est pas une conclusion. Une retransmission est souvent
un réseau lent, pas une attaque ; une fenêtre à zéro est un mécanisme normal de régulation,
pas une panne.

Le module rend donc des **observations**, jamais des alertes. La règle du projet reste
entière : aucune règle isolée ne produit une alerte — il faut trois indices convergents,
dans des familles différentes, et c'est le rôle d'`agent/detection.py`.

POURQUOI CES QUATRE-LÀ, ET PAS DIX
----------------------------------
Elles sont mesurables avec ce que l'analyseur conserve, et chacune correspond à un
phénomène qu'un débutant peut comprendre et vérifier dans les paquets. Une règle qu'on ne
peut pas expliquer ne vaut rien ici.
"""

from __future__ import annotations

from typing import Any

#: Nombre de paquets d'une même conversation relus pour l'analyse. Au-delà, les anomalies
#: deviennent difficiles à attribuer, et le coût de la relecture n'est plus justifié.
PAQUETS_ANALYSES = 3000


def _vivant(valeur: Any) -> bool:
    return valeur is not None and valeur != ""


def _entier(valeur: Any) -> int | None:
    try:
        return int(valeur)
    except (TypeError, ValueError):
        return None


def _drapeaux(paquet: dict[str, Any]) -> list[str]:
    """Les drapeaux, quelle que soit la forme reçue.

    Ils arrivent en **chaîne** — `"SYN, ACK"` — et une version antérieure les parcourait
    comme une liste de caractères : aucun drapeau n'était reconnu. La leçon a coûté assez
    cher pour être répétée ici en toutes lettres.
    """
    brut = paquet.get("flags_tcp") or (paquet.get("details") or {}).get("tcp_flags") or []
    if isinstance(brut, str):
        brut = brut.split(",")
    return [str(drapeau).strip().upper() for drapeau in brut if str(drapeau).strip()]


def _sens(paquet: dict[str, Any]) -> tuple | None:
    """Le sens d'un paquet : le couple (source, destination) avec ses ports."""
    source = paquet.get("ip_source")
    destination = paquet.get("ip_destination")
    if not _vivant(source) or not _vivant(destination):
        return None
    return (source, paquet.get("port_source"), destination, paquet.get("port_destination"))


def _conversation(paquet: dict[str, Any]) -> frozenset | None:
    """La conversation, indépendamment du sens — pour regrouper les deux directions."""
    sens = _sens(paquet)
    if sens is None:
        return None
    source, port_source, destination, port_destination = sens
    return frozenset({(source, port_source), (destination, port_destination)})


def _seq(paquet: dict[str, Any]) -> int | None:
    return _entier((paquet.get("details") or {}).get("seq"))


def _charge(paquet: dict[str, Any]) -> int:
    return _entier((paquet.get("details") or {}).get("charge_utile")) or 0


def _tri(paquets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Trié par horodatage. Un ordre non garanti n'est pas un ordre."""
    return sorted(paquets, key=lambda p: str(p.get("horodatage") or ""))


# --------------------------------------------------------------------------- #
#  Les quatre anomalies
# --------------------------------------------------------------------------- #
def retransmissions(paquets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Une même donnée envoyée deux fois dans le même sens.

    Le critère est précis : **même conversation, même sens, même numéro de séquence, et une
    charge utile non nulle**. Le dernier point est essentiel — un ACK pur sans données
    partage souvent un numéro de séquence avec le paquet précédent, et le compter comme une
    retransmission remplirait la liste de faux positifs.

    Une retransmission signale presque toujours un paquet perdu en route. C'est un fait ;
    la cause, elle, demande de regarder ailleurs.
    """
    vus: dict[tuple, list[dict[str, Any]]] = {}
    for paquet in _tri(paquets):
        sens = _sens(paquet)
        numero = _seq(paquet)
        if sens is None or numero is None or _charge(paquet) == 0:
            continue
        vus.setdefault((sens, numero), []).append(paquet)

    resultats = []
    for (sens, numero), occurrences in vus.items():
        if len(occurrences) < 2:
            continue
        premier, dernier = occurrences[0], occurrences[-1]
        resultats.append({
            "anomalie": "retransmission",
            "conversation": " ↔ ".join(f"{a}:{b}" for a, b in sorted(
                {(premier.get("ip_source"), premier.get("port_source")),
                 (premier.get("ip_destination"), premier.get("port_destination"))},
                key=str)),
            "sens": f"{sens[0]}:{sens[1]} → {sens[2]}:{sens[3]}",
            "seq": numero,
            "occurrences": len(occurrences),
            "premier": premier.get("horodatage"),
            "dernier": dernier.get("horodatage"),
            "criteres": [
                f"même sens : {sens[0]}:{sens[1]} → {sens[2]}:{sens[3]}",
                f"même numéro de séquence : {numero}",
                "charge utile non nulle (un accusé de réception seul n'est pas compté)",
                f"observé {len(occurrences)} fois",
            ],
        })
    return resultats


def fenetres_nulles(paquets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fenêtre d'annonce à zéro : l'émetteur demande à l'autre de s'arrêter.

    C'est un mécanisme **normal** de régulation de flux — un récepteur qui n'a plus de place
    dans son tampon l'annonce ainsi. Le compter comme une anomalie serait une erreur ; le
    signaler comme une observation permet de comprendre une pause inexpliquée.
    """
    resultats = []
    for paquet in _tri(paquets):
        fenetre = _entier((paquet.get("details") or {}).get("fenetre"))
        if fenetre != 0:
            continue
        resultats.append({
            "anomalie": "fenetre_nulle",
            "sens": f"{paquet.get('ip_source')}:{paquet.get('port_source')} → "
                    f"{paquet.get('ip_destination')}:{paquet.get('port_destination')}",
            "horodatage": paquet.get("horodatage"),
            "seq": _seq(paquet),
            "criteres": [
                "champ « fenêtre » de l'en-tête TCP égal à zéro",
                "la source demande à l'autre de cesser d'émettre",
                "mécanisme de régulation normal, pas une anomalie en soi",
            ],
        })
    return resultats


def resets_inattendus(paquets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Un RST en tout premier paquet d'une conversation : la rupture avant l'ouverture.

    Une fermeture brutale **après** une conversation établie est banale. Un RST **avant**
    tout échange l'est moins : il dit qu'un côté a refusé la conversation d'emblée — port
    fermé, service arrêté, ou intermédiaire qui bloque.
    """
    premiers: dict[frozenset, tuple] = {}
    for paquet in _tri(paquets):
        conversation = _conversation(paquet)
        sens = _sens(paquet)
        if conversation is None or sens is None:
            continue
        premiers.setdefault(conversation, (paquet, sens))

    resultats = []
    for conversation, (paquet, sens) in premiers.items():
        if "RST" not in _drapeaux(paquet):
            continue
        resultats.append({
            "anomalie": "reset_inattendu",
            "sens": f"{sens[0]}:{sens[1]} → {sens[2]}:{sens[3]}",
            "horodatage": paquet.get("horodatage"),
            "criteres": [
                "drapeau RST présent",
                "ce paquet est le PREMIER de la conversation : aucun échange avant",
                "un port fermé, un service arrêté ou un filtrage produisent le même effet",
            ],
        })
    return resultats


def poignees_incompletes(paquets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Une demande d'ouverture restée sans réponse dans les paquets observés.

    **La prudence est ici obligatoire.** Une poignée de main incomplète peut signifier trois
    choses très différentes : la cible ne répond pas, le paquet de réponse n'a pas été
    capturé, ou le service est filtré. Le module ne choisit pas — il énonce les trois.
    """
    # On ne fusionne pas les drapeaux de toute la conversation : on retient **qui a demandé**
    # et **qui a répondu**. La première version se contentait de chercher un ACK quelque
    # part — or un ACK ordinaire apparaît sur presque tous les paquets d'une conversation
    # établie, et il innocenterait une demande restée sans réponse. Seul un SYN-ACK (SYN
    # *et* ACK sur le même paquet) prouve qu'un serveur a répondu.
    par_conversation: dict[frozenset, dict[str, bool]] = {}
    for paquet in _tri(paquets):
        conversation = _conversation(paquet)
        if conversation is None:
            continue
        etat = par_conversation.setdefault(conversation, {"demande": False, "reponse": False})
        drapeaux = _drapeaux(paquet)
        if "SYN" in drapeaux and "ACK" in drapeaux:
            etat["reponse"] = True
        elif "SYN" in drapeaux:
            etat["demande"] = True

    resultats = []
    for conversation, etat in par_conversation.items():
        if etat["demande"] and not etat["reponse"]:
            resultats.append({
                "anomalie": "poignee_incomplete",
                "conversation": " ↔ ".join(str(c) for c in sorted(conversation, key=str)),
                "criteres": [
                    "un SYN a été observé",
                    "aucun SYN-ACK en réponse dans les paquets analysés",
                    "trois explications possibles : cible muette, réponse non capturée, "
                    "ou service filtré — le paquet seul ne les distingue pas",
                ],
            })
    return resultats


# --------------------------------------------------------------------------- #
#  Vue d'ensemble
# --------------------------------------------------------------------------- #
def analyser(paquets: list[dict[str, Any]]) -> dict[str, Any]:
    """Rend toutes les anomalies observées, avec leur compte par famille.

    Le résultat porte le nombre de paquets examinés : sans lui, une liste vide ne
    distinguerait pas « rien d'anormal » de « rien à analyser » — et c'est exactement le
    genre de silence trompeur que ce projet refuse.
    """
    examines = paquets[:PAQUETS_ANALYSES] if paquets else []

    familles = {
        "retransmission": retransmissions(examines),
        "poignee_incomplete": poignees_incompletes(examines),
        "reset_inattendu": resets_inattendus(examines),
        "fenetre_nulle": fenetres_nulles(examines),
    }

    return {
        "paquets_examines": len(examines),
        "total": sum(len(liste) for liste in familles.values()),
        "comptes": {nom: len(liste) for nom, liste in familles.items()},
        "anomalies": [anomalie for liste in familles.values() for anomalie in liste],
        "niveau": "observation",
        "note": "Une anomalie est un fait mesuré, jamais une conclusion : aucune ne produit "
                "une alerte à elle seule.",
    }

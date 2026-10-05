"""Raconter une conversation — la chronologie, puis le récit.

POURQUOI UN MODULE À PART
-------------------------
Le reste du projet *compte* et *classe* : des paquets, des communications, des niveaux. Ici,
on **raconte**. Le même fait, écrit pour quelqu'un qui découvre le réseau, ne se présente
pas comme une ligne de tableau.

LA RÈGLE QUI GOUVERNE CE MODULE
-------------------------------
Chaque phrase est **soit un fait observé, soit une lecture**, et les deux ne se mélangent
jamais dans la même phrase. « 18,3 ko ont été envoyés » est un fait. « Le volume reçu
domine : c'est le profil d'une consultation » est une lecture — et elle est annoncée comme
telle, avec le critère qui l'a déclenchée.

C'est la règle n°4 du projet, appliquée à la phrase : jamais d'hypothèse présentée comme
une certitude. Un lecteur doit pouvoir dire, à chaque ligne, ce qui a été vu et ce qui a
été pensé.

CE QUE CE MODULE NE PEUT PAS DIRE
---------------------------------
Il ne connaît que ce qui a été conservé. Une conversation vue en cours de route n'a pas de
début ; l'absence de fermeture ne veut pas dire que la conversation est encore ouverte, mais
que **la fermeture n'a pas été vue**. Le module écrit exactement cela, et pas autre chose.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

#: Au-delà de ce rapport entre les deux sens, on parle de volume déséquilibré. Trois fois
#: plus dans un sens que dans l'autre : c'est un seuil, pas une vérité — il est nommé ici
#: pour qu'on puisse le discuter et le changer à un seul endroit.
RAPPORT_DESEQUILIBRE = 3.0

#: Durée au-delà de laquelle une conversation est dite « longue ». Une minute n'a rien de
#: magique : c'est l'ordre de grandeur d'une session interactive (une messagerie) face à un
#: échange bref (une requête).
DUREE_LONGUE_S = 60.0


def _secondes(horodatage: Any) -> float | None:
    """Rend un horodatage stocké sous forme de secondes depuis l'époque, ou None."""
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


def _heure(horodatage: Any) -> str:
    """L'heure, en heure locale, pour un lecteur humain."""
    secondes = _secondes(horodatage)
    if secondes is None:
        return "à un moment non daté"
    return dt.datetime.fromtimestamp(secondes).strftime("à %H:%M:%S")


def _octets(valeur: Any) -> int:
    try:
        return int(valeur or 0)
    except (TypeError, ValueError):
        return 0


def _drapeaux(paquet: dict[str, Any]) -> list[str]:
    """Les drapeaux TCP d'un paquet, quelle que soit la forme reçue.

    Ils arrivent en **chaîne** — `"SYN, ACK"` — et la première version les parcourait comme
    une liste de caractères : elle ne reconnaissait donc aucun drapeau, la chronologie
    restait vide, et le récit affirmait que l'ouverture n'avait pas été observée alors qu'un
    SYN avait bel et bien été vu. Une affirmation fausse est le pire défaut possible ici.
    """
    brut = paquet.get("flags_tcp") or (paquet.get("details") or {}).get("tcp_flags") or []
    if isinstance(brut, str):
        brut = brut.split(",")
    return [str(drapeau).strip().upper() for drapeau in brut if str(drapeau).strip()]


def _nombre(valeur: float, decimales: int = 1) -> str:
    """Un nombre en écriture française : la virgule, et rien d'autre de transformé."""
    return f"{valeur:.{decimales}f}".replace(".", ",")


def _taille(octets: int) -> str:
    """Une taille lisible. Le séparateur décimal est la virgule française."""
    if octets < 1000:
        return f"{octets} octets"
    if octets < 1_000_000:
        return f"{octets / 1000:.1f} ko".replace(".", ",")
    return f"{octets / 1_000_000:.1f} Mo".replace(".", ",")


def _nom_cote(communication: dict[str, Any], cote: str) -> str:
    """Désigne une extrémité : son nom s'il est connu, sinon son adresse."""
    nom = communication.get(f"nom_{cote}")
    adresse = communication.get(f"ip_{cote}")
    port = communication.get(f"port_{cote}")
    if nom:
        return f"{nom} ({adresse})" if not port else f"{nom} ({adresse}:{port})"
    return str(adresse) if not port else f"{adresse}:{port}"


# --------------------------------------------------------------------------- #
#  La chronologie
# --------------------------------------------------------------------------- #
def chronologie(paquets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Les moments qui comptent dans une conversation, dans l'ordre.

    Tous les paquets ne sont pas retenus : quarante échanges de données ne racontent rien
    de plus que le premier. On garde les **événements** — l'ouverture, l'acceptation, la
    première donnée, la fermeture — et on compte le reste.

    Les paquets sont d'abord triés par horodatage : comme pour les noms de domaine, un
    ordre non garanti n'est pas un ordre.
    """
    ordonnes = sorted(paquets, key=lambda p: _secondes(p.get("horodatage")) or 0.0)
    if not ordonnes:
        return []

    debut = _secondes(ordonnes[0].get("horodatage"))
    moments: list[dict[str, Any]] = []
    deja_vus: set[str] = set()

    for paquet in ordonnes:
        drapeaux = _drapeaux(paquet)
        moment = None
        description = None

        if "SYN" in drapeaux and "ACK" not in drapeaux:
            moment, description = "ouverture", "demande d'ouverture (SYN)"
        elif "SYN" in drapeaux and "ACK" in drapeaux:
            moment, description = "acceptation", "ouverture acceptée (SYN-ACK)"
        elif "RST" in drapeaux:
            moment, description = "rupture", "rupture brutale (RST)"
        elif "FIN" in drapeaux:
            moment, description = "fermeture", "demande de fermeture (FIN)"

        if moment is None or moment in deja_vus:
            continue
        # L'acceptation et la fermeture peuvent se produire deux fois — une par sens.
        deja_vus.add(moment if moment in ("ouverture", "rupture") else f"{moment}{len(moments)}")

        secondes = _secondes(paquet.get("horodatage"))
        moments.append({
            "moment": moment,
            "description": description,
            "horodatage": paquet.get("horodatage"),
            "depuis_debut_s": round(secondes - debut, 3) if secondes and debut else None,
            "sens": f"{paquet.get('ip_source')} → {paquet.get('ip_destination')}",
        })

    return moments


# --------------------------------------------------------------------------- #
#  Le récit
# --------------------------------------------------------------------------- #
def raconter(communication: dict[str, Any],
             moments: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    """Rend le récit d'une conversation : une liste de phrases classées.

    Chaque phrase porte son **genre** — `fait` ou `lecture` — pour que l'interface puisse
    les présenter différemment. Le texte seul ne suffirait pas : un lecteur doit voir d'un
    coup d'œil ce qui a été observé et ce qui a été interprété.
    """
    phrases: list[dict[str, str]] = []

    def fait(texte: str) -> None:
        phrases.append({"genre": "fait", "texte": texte})

    def lecture(texte: str) -> None:
        phrases.append({"genre": "lecture", "texte": texte})

    protocole = communication.get("protocole") or "un protocole inconnu"
    cote_a = _nom_cote(communication, "a")
    cote_b = _nom_cote(communication, "b")

    # --- L'ouverture ------------------------------------------------------- #
    fait(f"{_heure(communication.get('debut')).capitalize()}, {cote_a} a engagé une "
         f"conversation {protocole} avec {cote_b}.")

    # --- L'établissement --------------------------------------------------- #
    ouverture = next((m for m in (moments or []) if m["moment"] == "ouverture"), None)
    acceptation = next((m for m in (moments or []) if m["moment"] == "acceptation"), None)

    # L'ordre de ces conditions compte. Un SYN vu interdit d'écrire que le début n'a pas
    # été observé — la première version testait la certitude avant l'ouverture et pouvait
    # donc se contredire dans la même page.
    if ouverture and acceptation:
        fait("L'ouverture a été acceptée : la conversation a bien été établie dans les deux sens.")
    elif ouverture:
        lecture("La demande d'ouverture a été vue, mais pas son acceptation. La conversation "
                "n'a peut-être jamais été établie — ou sa réponse n'a pas été capturée.")
    elif communication.get("vu_depuis_le_debut") is False or communication.get("etat_certain") is False:
        lecture("Le début de cette conversation n'a pas été vu : la capture a commencé "
                "après. On ne peut donc pas affirmer qu'elle a été établie.")

    # --- Le volume et la durée --------------------------------------------- #
    recus = _octets(communication.get("octets_b_vers_a"))
    envoyes = _octets(communication.get("octets_a_vers_b"))
    total = recus + envoyes
    debut = _secondes(communication.get("debut"))
    fin = _secondes(communication.get("dernier_paquet"))
    duree = (fin - debut) if debut and fin and fin >= debut else None

    if total:
        fait(f"{_taille(total)} ont été échangés : {_taille(envoyes)} dans un sens, "
             f"{_taille(recus)} dans l'autre.")

    if duree is not None and duree > 0:
        # Le remplacement de la virgule porte sur **le nombre seul**. Appliqué à la phrase
        # entière, il transformait aussi le point final en virgule — ce que la vérification
        # sur trafic réel a montré.
        fait(f"La conversation a duré {_nombre(duree, 1)} seconde(s).")

    if total and recus and envoyes:
        rapport = max(recus / envoyes, envoyes / recus)
        if rapport >= RAPPORT_DESEQUILIBRE:
            sens_dominant = "reçus" if recus > envoyes else "envoyés"
            lecture(f"Le volume est très déséquilibré — plus de trois fois plus de données "
                    f"{sens_dominant} que dans l'autre sens. C'est le profil d'un service "
                    f"qui rend beaucoup et demande peu : consultation, mise à jour, "
                    f"téléchargement.")

    if duree is not None and duree >= DUREE_LONGUE_S:
        lecture("La durée dépasse une minute : c'est le profil d'une session maintenue "
                "ouverte — messagerie, flux continu, connexion persistante — plutôt qu'un "
                "échange ponctuel.")

    # --- La fin ------------------------------------------------------------ #
    rupture = next((m for m in (moments or []) if m["moment"] == "rupture"), None)
    fermeture = next((m for m in (moments or []) if m["moment"] == "fermeture"), None)
    etat = communication.get("etat")

    if rupture:
        fait("La conversation a été interrompue brutalement par un RST. C'est une fin "
             "immédiate, qui ne laisse pas les tampons se vider.")
        lecture("Un RST peut signaler un port fermé, un logiciel qui coupe la connexion, ou "
                "un intermédiaire réseau qui la refuse. Le paquet seul ne le dit pas.")
    elif fermeture:
        if etat == "fermée":
            fait("Les deux côtés ont demandé la fermeture (FIN en chacun) : la fin est "
                 "propre et certaine.")
        else:
            fait("Une demande de fermeture (FIN) a été vue, dans un seul sens.")
            lecture("Un FIN dans un seul sens ne ferme pas une conversation : l'autre côté "
                    "peut encore envoyer. La fermeture n'est donc pas certaine.")
    elif etat == "en cours":
        fait("La conversation était encore en cours à la fin de la capture : aucune "
             "fermeture n'a été observée.")
        lecture("Cela ne veut pas dire qu'elle est encore ouverte — seulement que la suite "
                "n'a pas été vue. Un service qui garde ses connexions ouvertes en donne "
                "l'image sans qu'il se passe rien.")
    elif etat:
        fait(f"L'état retenu est « {etat} ».")

    # --- La certitude ------------------------------------------------------ #
    if communication.get("etat_certain") is False:
        explication = communication.get("note_etat") or (
            "Les premiers paquets de cette conversation n'ont pas été vus.")
        lecture(f"À prendre avec réserve : {explication}")

    return phrases

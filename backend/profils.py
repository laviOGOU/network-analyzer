"""Profils d'analyse — garder plusieurs configurations sous un nom.

À QUOI ÇA SERT
--------------
Analyser un réseau, ce n'est pas la même chose selon ce qu'on cherche. « Est-ce que la
messagerie passe ? » demande un filtre ; « y a-t-il des anomalies ? » en demande un autre.
Retaper la même expression à chaque fois, c'est la garantie de se tromper un jour — et de
croire un résultat qui ne portait pas sur ce qu'on croyait.

Un profil est un nom, un filtre d'affichage, et une phrase qui dit à quoi il sert.

CE QUI GARANTIT QU'UN PROFIL EST UTILISABLE
-------------------------------------------
Le filtre est **validé par le parseur du lot A au moment de l'enregistrement**, pas au moment
où on l'applique. Un profil enregistré ne peut donc pas échouer plus tard : s'il existe, son
filtre est syntaxiquement valide. C'est la différence entre refuser une erreur à l'entrée et
la découvrir en pleine analyse.

CE QUI N'EST PAS DANS UN PROFIL
-------------------------------
Aucun secret, aucun jeton, aucune adresse de base de données : un profil décrit **une façon de
regarder**, rien d'autre. Le fichier est écrit en clair, lisible par son propriétaire, et
n'est pas versionné — c'est le poste qui le porte, pas le dépôt.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any

from backend import filtres as mod_filtres
from backend import filtres_sql as mod_filtres_sql

#: Fichier des profils, à côté du projet. Volontairement hors du dépôt : c'est la
#: configuration d'un poste, pas une propriété du logiciel.
CHEMIN_PROFILS = os.environ.get(
    "ANALYZER_PROFILS",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "profils.json"),
)

#: Nombre de profils gardés. Au-delà, la liste devient un fouillis qu'on ne lit plus — et un
#: profil qu'on ne retrouve pas ne sert à rien.
MAX_PROFILS = 40

#: Longueurs bornées : ce qui vient d'un formulaire ne doit pas pouvoir grossir le fichier
#: sans limite.
LONGUEUR_NOM = 60
LONGUEUR_DESCRIPTION = 200
LONGUEUR_FILTRE = 300

#: Profils proposés d'emblée. Ils ne sont écrits dans le fichier que si l'utilisateur les
#: modifie : tant qu'il n'a rien changé, ils sont rendus depuis ici.
PROFILS_INCLUS: list[dict[str, str]] = [
    {
        "nom": "Tout",
        "filtre": "",
        "description": "Aucun filtre : tout ce qui a été capturé.",
    },
    {
        "nom": "Web chiffré",
        "filtre": "proto:tcp port:443",
        "description": "Le trafic HTTPS, sans jamais le déchiffrer.",
    },
    {
        "nom": "Résolutions DNS",
        "filtre": "proto:udp port:53",
        "description": "Les questions posées au DNS — ce que les machines cherchent à joindre.",
    },
    {
        "nom": "Trafic sortant vers l'extérieur",
        # La valeur contient une espace : elle doit être entre guillemets, comme l'exige la
        # syntaxe du lot A. Écrit sans guillemets, ce profil proposé était refusé à
        # l'enregistrement — un profil livré qui ne peut pas s'enregistrer serait une
        # promesse en l'air. C'est un test qui l'a montré.
        "filtre": 'proto:tcp etat:"en cours"',
        "description": "Les conversations TCP encore ouvertes : ce qui parle en ce moment.",
    },
    {
        "nom": "Conversations terminées",
        "filtre": "etat:fermée",
        "description": "Ce qui s'est terminé proprement, pour comparer avec ce qui reste ouvert.",
    },
]

_verrou = threading.Lock()


class ProfilInvalide(Exception):
    """Un profil refusé, avec la raison — jamais un refus muet."""


def _nettoyer(valeur: Any, longueur: int) -> str:
    """Ramène une valeur de formulaire à quelque chose d'affichable et de borné."""
    if valeur is None:
        return ""
    texte = str(valeur).strip()
    # Les caractères de contrôle n'ont rien à faire dans un nom ou un filtre, et les retirer
    # évite qu'une valeur détournée se retrouve dans un fichier de configuration.
    texte = "".join(caractere for caractere in texte if ord(caractere) >= 32)
    return texte[:longueur]


def valider(profil: dict[str, Any]) -> dict[str, str]:
    """Rend un profil propre, ou lève `ProfilInvalide` avec la raison.

    Le filtre est confié au parseur du lot A : un profil ne peut pas être enregistré avec une
    expression que l'application refusera plus tard. L'erreur est refusée à l'entrée, quand
    celui qui la commet est encore devant l'écran.
    """
    nom = _nettoyer(profil.get("nom"), LONGUEUR_NOM)
    if not nom:
        raise ProfilInvalide("Un profil doit porter un nom.")

    filtre = _nettoyer(profil.get("filtre"), LONGUEUR_FILTRE)
    if filtre:
        # `analyser` refuse une syntaxe incomprise en levant `ErreurFiltre` ; `separer`
        # distingue ensuite les critères qui s'appliquent aux paquets de ceux qui ne les
        # concernent pas. Les deux sont nécessaires : un profil enregistré doit pouvoir
        # s'appliquer, pas seulement s'écrire.
        try:
            criteres = mod_filtres.analyser(filtre)
        except mod_filtres.ErreurFiltre as erreur:
            raise ProfilInvalide(f"Filtre refusé : {erreur}") from erreur

        # Un filtre s'applique à **plusieurs listes**, et chaque critère est appliqué là où
        # il a un sens : `etat:fermée` décrit une communication, `port:443` un paquet. Le lot
        # A écarte les critères sans objet pour une liste donnée, et l'annonce, plutôt que de
        # refuser le filtre entier.
        #
        # La première version de cette validation ne regardait que les paquets : elle
        # refusait « Conversations terminées », un profil parfaitement légitime. Une
        # validation plus stricte que l'application interdit des choses qui marchent —
        # c'est un défaut, pas de la prudence.
        applique_quelque_part = False
        for table in ("paquets", "communications", "detections"):
            applicables, _ = mod_filtres_sql.separer(criteres, table)
            if applicables:
                applique_quelque_part = True
                break

        if not applique_quelque_part:
            raise ProfilInvalide(
                "Aucun critère de ce filtre ne s'applique à une des listes affichées : un "
                "profil ainsi enregistré n'afficherait jamais rien."
            )

    return {
        "nom": nom,
        "filtre": filtre,
        "description": _nettoyer(profil.get("description"), LONGUEUR_DESCRIPTION),
    }


def charger() -> list[dict[str, str]]:
    """Les profils enregistrés, ou les profils proposés si le fichier n'existe pas encore.

    Un fichier illisible ne fait pas échouer l'application : on retombe sur les profils
    proposés. Un tableau de bord qui refuse de s'ouvrir parce qu'un fichier de configuration
    est abîmé serait une panne pour rien.
    """
    try:
        with open(CHEMIN_PROFILS, encoding="utf-8") as fichier:
            contenu = json.load(fichier)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return [dict(profil) for profil in PROFILS_INCLUS]

    if not isinstance(contenu, list):
        return [dict(profil) for profil in PROFILS_INCLUS]

    profils = []
    for entree in contenu:
        if not isinstance(entree, dict):
            continue
        try:
            profils.append(valider(entree))
        except ProfilInvalide:
            # Une entrée abîmée est écartée, les autres restent. Refuser tout le fichier pour
            # une ligne fautive ferait perdre les profils valides.
            continue
    return profils or [dict(profil) for profil in PROFILS_INCLUS]


def _ecrire(profils: list[dict[str, str]]) -> None:
    dossier = os.path.dirname(CHEMIN_PROFILS)
    if dossier:
        os.makedirs(dossier, exist_ok=True)
    with open(CHEMIN_PROFILS, "w", encoding="utf-8") as fichier:
        json.dump(profils, fichier, ensure_ascii=False, indent=2)


def enregistrer(profil: dict[str, Any]) -> list[dict[str, str]]:
    """Ajoute ou remplace un profil — même nom, remplacement. Rend la liste à jour."""
    propre = valider(profil)

    with _verrou:
        profils = [p for p in charger() if p["nom"].lower() != propre["nom"].lower()]
        profils.append(propre)
        if len(profils) > MAX_PROFILS:
            raise ProfilInvalide(
                f"Trop de profils : {MAX_PROFILS} au maximum. Supprimez-en un avant d'en ajouter."
            )
        _ecrire(profils)
    return profils


def supprimer(nom: str) -> list[dict[str, str]]:
    """Retire un profil. Supprimer un nom absent n'est pas une erreur : le résultat voulu est
    atteint, et refuser obligerait l'appelant à vérifier avant — pour rien."""
    cible = _nettoyer(nom, LONGUEUR_NOM).lower()

    with _verrou:
        profils = [p for p in charger() if p["nom"].lower() != cible]
        _ecrire(profils)
    return profils

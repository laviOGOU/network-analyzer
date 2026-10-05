"""Traduction des critères de filtre en conditions SQL.

POURQUOI CE MODULE EST SÉPARÉ
-----------------------------
Le stockage PostgreSQL fait déjà six cents lignes : y ajouter la traduction des filtres
aurait produit un fichier que personne ne relit. Ici, la règle est simple et tient en une
phrase — **les valeurs sont toujours des paramètres liés, jamais du texte concaténé**.

Ce qui vient de l'utilisateur, ce sont les *valeurs*. Les *colonnes* viennent d'une table
de correspondances écrite dans ce fichier. Une valeur ne peut donc pas devenir une colonne,
ni une clause, ni quoi que ce soit d'autre : elle arrive dans la requête sous forme de
paramètre, à une place que le code a fixée.

C'est la différence entre « filtrer » et « exécuter ce que l'utilisateur a écrit ». Elle
ne se voit pas à la lecture du résultat — les deux donnent les mêmes lignes sur une
expression honnête — mais elle décide de ce qui se passe sur une expression hostile.
"""

from __future__ import annotations

from typing import Any

from backend.filtres import Critere
from backend.identifiants import identifiant_session

#: Colonnes correspondant à chaque champ de filtre, par table.
#:
#: Chaque entrée est un couple de colonnes quand le champ désigne deux emplacements
#: possibles — une adresse est en source *ou* en destination, un port est à l'un *ou*
#: l'autre bout. La condition devient alors un « ou » entre les deux, ce qui correspond à
#: ce que l'utilisateur cherche : un port, pas un rôle.
CORRESPONDANCES: dict[str, dict[str, tuple[str, ...]]] = {
    "paquets": {
        "proto": ("protocole",),
        "ip": ("ip_source", "ip_destination"),
        "port": ("port_source", "port_destination"),
        "taille": ("taille",),
        "session": ("session_id",),
        "texte": ("protocole", "resume_texte", "details_texte"),
    },
    "communications": {
        "proto": ("protocole",),
        "ip": ("ip_a", "ip_b"),
        "port": ("port_a", "port_b"),
        "etat": ("etat",),
        "session": ("session_id",),
        "texte": ("protocole", "etat", "note_etat"),
    },
    "detections": {
        "niveau": ("niveau",),
        "ip": ("ip_concernee",),
        "session": ("session_id",),
        "texte": ("titre", "constat", "interpretation", "regle"),
    },
}

#: Colonnes calculées, écrites telles quelles dans la requête. Elles ne viennent pas de
#: l'utilisateur : ce sont des expressions figées, définies ici et nulle part ailleurs.
COLONNES_CALCULEES: dict[str, str] = {
    # Les détails d'un paquet sont un objet JSON : on le compare en texte, ce qui permet
    # à la recherche libre de retrouver un nom de domaine sans connaître la clé.
    "resume_texte": "COALESCE(details->>'dns_question', '')",
    "details_texte": "details::text",
    "ip_source_txt": "host(ip_source)",
    "ip_destination_txt": "host(ip_destination)",
    "ip_a_txt": "host(ip_a)",
    "ip_b_txt": "host(ip_b)",
    "ip_concernee_txt": "host(ip_concernee)",
}

#: Colonnes d'adresses, à traiter comme du texte pour les préfixes.
COLONNES_ADRESSES = {"ip_source", "ip_destination", "ip_a", "ip_b", "ip_concernee"}

#: Opérateurs acceptés, et rien d'autre. Un opérateur vient du critère, mais il est
#: d'abord passé par cette table : ce qui n'y figure pas ne peut pas atteindre la requête.
OPERATEURS = {">": ">", "<": "<", ">=": ">=", "<=": "<=", "=": "="}

#: Traduction des niveaux de détection : le schéma écrit « hypothese », l'interface
#: affiche « hypothèse ». La conversion se fait ici, en un seul endroit.
NIVEAUX = {"observation": "observation", "hypothèse": "hypothese", "hypothese": "hypothese",
           "alerte": "alerte"}


class ErreurFiltreSQL(ValueError):
    """Un critère ne s'applique pas à cette table."""


def _colonne(nom: str) -> str:
    """Rend une colonne utilisable : soit une colonne réelle, soit une expression figée."""
    if nom in COLONNES_CALCULEES:
        return COLONNES_CALCULEES[nom]
    if nom in COLONNES_ADRESSES:
        return f"host({nom})"
    return nom


def conditions(criteres: list[Critere], table: str) -> tuple[str, list[Any]]:
    """Rend un fragment SQL et ses paramètres liés.

    Le fragment ne contient que des noms de colonnes, des opérateurs et des `%s`. Aucune
    valeur de l'utilisateur n'y est écrite : elles sont toutes dans la liste rendue à côté,
    que le pilote de base de données lie aux `%s`.
    """
    if not criteres:
        return "", []

    if table not in CORRESPONDANCES:
        raise ErreurFiltreSQL(f"Table inconnue pour le filtrage : {table}")

    colonnes_connues = CORRESPONDANCES[table]
    fragments: list[str] = []
    parametres: list[Any] = []

    for critere in criteres:
        if critere.champ not in colonnes_connues:
            raise ErreurFiltreSQL(
                f"Le champ « {critere.champ} » ne s'applique pas à cette vue "
                f"({', '.join(sorted(colonnes_connues))}).")

        morceaux = []
        for nom_colonne in colonnes_connues[critere.champ]:
            colonne = _colonne(nom_colonne)

            if critere.champ == "taille":
                # L'opérateur passe par une table de correspondance : ce qui n'y figure pas
                # ne peut pas atteindre la requête. Un opérateur inventé est refusé, et non
                # inséré tel quel.
                operateur = OPERATEURS.get(critere.comparateur)
                if operateur is None:
                    raise ErreurFiltreSQL(
                        f"Opérateur inconnu : « {critere.comparateur} ».")
                morceaux.append(f"{colonne} {operateur} %s")
                parametres.append(int(critere.valeur))
                continue

            if critere.champ in ("proto", "niveau", "etat"):
                valeur = (NIVEAUX.get(critere.valeur, critere.valeur)
                          if critere.champ == "niveau" else critere.valeur)
                # Comparaison en minuscules des deux côtés : la casse de ce qui a été
                # capturé ne doit pas décider si le filtre trouve la ligne.
                morceaux.append(f"lower({colonne}) = %s")
                parametres.append(valeur.lower())
                continue

            if critere.champ == "ip" and critere.valeur.endswith("."):
                morceaux.append(f"{colonne} LIKE %s")
                parametres.append(f"{critere.valeur}%")
                continue

            if critere.champ == "session":
                # Le libellé doit être converti en identifiant avant la comparaison, comme
                # il l'est au moment de l'écriture. Sans cela, « capture-du-matin » ne
                # trouverait jamais rien : la base contient des UUID.
                morceaux.append(f"{colonne} = %s")
                parametres.append(identifiant_session(critere.valeur))
                continue

            if critere.champ in ("ip", "port"):
                # Comparaison, et non recherche libre. Un port est un nombre : le chercher
                # en texte ferait correspondre 443 avec 1443 ou 4430. C'est l'erreur que la
                # première version commettait, et un test l'a montrée.
                morceaux.append(f"{colonne} = %s")
                parametres.append(critere.valeur)
                continue

            # Recherche libre : on cherche dans toutes les colonnes listées.
            morceaux.append(f"lower({colonne}) LIKE %s")
            parametres.append(f"%{critere.valeur.lower()}%")

        fragments.append("(" + " OR ".join(morceaux) + ")")

    return " AND ".join(fragments), parametres


def separer(criteres: list[Critere], table: str) -> tuple[list[Critere], list[Critere]]:
    """Sépare les critères applicables à une vue de ceux qui ne le sont pas.

    Un même filtre s'applique aux trois listes de l'interface : `proto:tcp port:443`
    vaut pour les paquets et les communications, mais « proto » ne veut rien dire pour une
    détection — elle n'a pas de protocole.

    Trois comportements étaient possibles, et deux sont mauvais :

        - lever une erreur : la liste des détections refuse de s'afficher à cause d'un
          critère qui ne la concernait pas ;
        - ignorer en silence : elle s'affiche, l'utilisateur croit son filtre appliqué, et
          lit des résultats complets en croyant lire des résultats filtrés ;
        - **écarter en le disant** : la liste s'affiche, et l'interface annonce quels
          critères n'ont pas pu être appliqués dans cette vue.

    C'est la troisième qui est retenue. Elle est la seule qui ne mente pas et ne casse pas.
    """
    applicables, ignorees = [], []
    colonnes = CORRESPONDANCES.get(table, {})
    for critere in criteres:
        (applicables if critere.champ in colonnes else ignorees).append(critere)
    return applicables, ignorees


def compte_conditions(criteres: list[Critere], table: str) -> int:
    """Nombre de conditions produites, pour les tests et le diagnostic."""
    fragment, _ = conditions(criteres, table)
    return fragment.count(" AND ") + 1 if fragment else 0

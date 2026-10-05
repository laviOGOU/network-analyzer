"""Filtres d'affichage — la syntaxe lisible de l'interface.

POURQUOI UNE SYNTAXE PLUTÔT QU'UN FORMULAIRE
--------------------------------------------
Une liste déroulante par champ oblige à autant de formulaires qu'il y a de champs, et elle
interdit la combinaison libre. Une syntaxe courte — `proto:tcp port:443` — se retient, se
tape vite, se copie d'un message à l'autre, et se capture dans une phrase. C'est ce qui
rend un filtre utilisable pendant une démonstration.

CE QUE CE MODULE FAIT, ET CE QU'IL REFUSE
-----------------------------------------
Il traduit une expression en **critères structurés** — jamais en chaîne de requête. Le
stockage reçoit une liste de critères et les traduit lui-même : paramètres liés en SQL,
comparaisons Python en mémoire. Aucun fragment de l'expression de l'utilisateur ne se
retrouve concaténé dans une requête. C'est la règle, et elle est tenue par la forme des
données qui circulent entre les deux : des couples (champ, valeur) énumérés, pas du texte.

Un champ inconnu est **refusé avec la liste des champs valides**. Ignorer silencieusement
ce qu'on n'a pas compris est la façon la plus sûre de faire croire à un filtre qui
fonctionne : l'utilisateur voit moins de résultats, et attribue la différence au filtre
alors qu'il ne s'applique pas.

LA SYNTAXE
----------
    proto:tcp              TCP, udp, dns, icmp, arp — insensible à la casse
    port:443               le port, à la source comme à la destination
    ip:192.168.1.5         l'adresse, à la source comme à la destination
    ip:192.168.1.          un préfixe : tout le sous-réseau
    etat:établie           l'état d'une communication (« échec probable » se met entre guillemets)
    niveau:hypothèse       le niveau d'une détection : observation, hypothèse, alerte
    taille:>1000           comparaison : > < >= <=
    texte:example.com      recherche libre (nom de domaine, motif)
    session:abc-123        la session de capture

Plusieurs critères se cumulent (ET logique). Les valeurs contenant une espace s'écrivent
entre guillemets : `etat:"échec probable"`.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass
from typing import Any

#: Longueur maximale d'une expression. Une expression plus longue n'est pas un filtre :
#: c'est une tentative, et la refuser tôt évite de la faire traverser tout le système.
LONGUEUR_MAX = 300

#: Nombre maximal de critères. Au-delà, la liste de résultats serait de toute façon vide
#: ou illisible — et chaque critère supplémentaire coûte une comparaison par ligne.
CRITERES_MAX = 8

#: Champs acceptés, avec leur description pour le message d'erreur. La description sert
#: deux fois : elle explique le refus, et elle sert de référence dans l'interface.
CHAMPS: dict[str, str] = {
    "proto": "protocole : tcp, udp, dns, icmp, arp",
    "port": "numéro de port, source ou destination",
    "ip": "adresse IP, source ou destination (un préfixe est accepté)",
    "etat": "état d'une communication : établie, en cours, tentative, fermée…",
    "niveau": "niveau d'une détection : observation, hypothèse, alerte",
    "taille": "taille d'un paquet, avec > < >= <=",
    "texte": "recherche libre dans les données affichées",
    "session": "identifiant de session de capture",
}

#: Champs pour lesquels une comparaison chiffrée a un sens.
CHAMPS_NUMERIQUES = {"port", "taille"}

#: Champs qui acceptent un comparateur explicite.
COMPARATEURS = (">=", "<=", ">", "<", "=")

#: Caractères autorisés dans une valeur. Ce n'est pas un contrôle de sécurité — les
#: valeurs ne sont jamais concaténées dans une requête — mais un garde-fou contre les
#: fautes de frappe qui produiraient un filtre vide sans que personne ne comprenne.
_MOTIF_ADRESSE = re.compile(r"^[0-9a-fA-F:.%]+$")
_MOTIF_VALEUR = re.compile(r"^[^\x00-\x1f]+$")


class ErreurFiltre(ValueError):
    """L'expression ne peut pas être comprise. Le message dit pourquoi, et quoi écrire."""


@dataclass(frozen=True)
class Critere:
    """Un critère de filtrage, sous forme de données — jamais de texte à exécuter."""

    champ: str
    valeur: str
    comparateur: str = "="

    def vers_dict(self) -> dict[str, str]:
        return {"champ": self.champ, "valeur": self.valeur,
                "comparateur": self.comparateur}


def _message_champs() -> str:
    return "\n".join(f"  {nom:>8} : {aide}" for nom, aide in CHAMPS.items())


def _valeur_numerique(champ: str, valeur: str) -> tuple[str, int]:
    """Extrait un comparateur éventuel et le nombre. Rend (« > », 1000)."""
    for comparateur in COMPARATEURS:
        if valeur.startswith(comparateur):
            reste = valeur[len(comparateur):].strip()
            if not reste.isdigit():
                raise ErreurFiltre(
                    f"« {champ} » attend un nombre après « {comparateur} », "
                    f"or il reçoit « {reste} ».")
            return comparateur, int(reste)
    if not valeur.isdigit():
        raise ErreurFiltre(
            f"« {champ} » attend un nombre, or il reçoit « {valeur} ».\n"
            "  Exemples : taille:>1000 · port:443")
    return "=", int(valeur)


def analyser(expression: str | None) -> list[Critere]:
    """Traduit une expression de filtre en critères structurés.

    Rend une liste vide pour une expression vide : « pas de filtre » n'est pas une erreur,
    c'est le cas le plus courant.

    Lève `ErreurFiltre` — avec un message qui dit quoi écrire — dès qu'un élément n'est
    pas compris. Un filtre partiellement appliqué serait pire qu'un filtre refusé : il
    montrerait des résultats incomplets sans le dire.
    """
    if not expression or not expression.strip():
        return []

    expression = expression.strip()
    if len(expression) > LONGUEUR_MAX:
        raise ErreurFiltre(
            f"Expression trop longue ({len(expression)} caractères, maximum {LONGUEUR_MAX}).")

    # `shlex` gère les guillemets comme un shell : c'est ce qui permet d'écrire
    # etat:"échec probable" sans inventer une convention de plus.
    try:
        morceaux = shlex.split(expression)
    except ValueError as erreur:
        raise ErreurFiltre(f"Guillemets mal fermés : {erreur}") from erreur

    if len(morceaux) > CRITERES_MAX:
        raise ErreurFiltre(
            f"{len(morceaux)} critères, maximum {CRITERES_MAX}. Au-delà, le filtre ne "
            "sélectionne plus rien d'utile.")

    criteres: list[Critere] = []
    for morceau in morceaux:
        if ":" not in morceau:
            raise ErreurFiltre(
                f"« {morceau} » n'est pas un critère.\n"
                "  La forme attendue est champ:valeur — par exemple proto:tcp.\n"
                f"  Champs disponibles :\n{_message_champs()}")

        champ, _, valeur = morceau.partition(":")
        champ = champ.lower().strip()
        valeur = valeur.strip()

        if champ not in CHAMPS:
            raise ErreurFiltre(
                f"Champ inconnu : « {champ} ».\n"
                f"  Champs disponibles :\n{_message_champs()}")

        if not valeur:
            raise ErreurFiltre(f"« {champ} » est vide : préciser une valeur.")
        if not _MOTIF_VALEUR.match(valeur):
            raise ErreurFiltre(f"« {valeur} » contient des caractères de contrôle.")

        if champ in CHAMPS_NUMERIQUES:
            comparateur, nombre = _valeur_numerique(champ, valeur)
            criteres.append(Critere(champ, str(nombre), comparateur))
            continue

        if champ == "ip":
            if not _MOTIF_ADRESSE.match(valeur):
                raise ErreurFiltre(f"« {valeur} » ne ressemble pas à une adresse IP.")
            # Une adresse complète est validée ; un préfixe est accepté tel quel, c'est
            # ce qui permet de filtrer tout un sous-réseau d'un coup.
            if "." in valeur and not valeur.endswith("."):
                try:
                    ipaddress.ip_address(valeur.split("/")[0])
                except ValueError as erreur:
                    raise ErreurFiltre(
                        f"« {valeur} » n'est pas une adresse IP valide.") from erreur
            criteres.append(Critere(champ, valeur.lower()))
            continue

        criteres.append(Critere(champ, valeur.lower() if champ in ("proto", "niveau",
                                                                   "etat") else valeur))

    return criteres


def criteres_vers_texte(criteres: list[Critere]) -> str:
    """Reconstitue l'expression, pour l'afficher telle qu'elle a été comprise.

    L'interface réaffiche le filtre interprété : un utilisateur qui a mal orthographié un
    mot le voit tout de suite, au lieu de se demander pourquoi la liste est vide.
    """
    morceaux = []
    for critere in criteres:
        valeur = critere.valeur
        if " " in valeur:
            valeur = f'"{valeur}"'
        prefixe = critere.comparateur if critere.comparateur != "=" else ""
        morceaux.append(f"{critere.champ}:{prefixe}{valeur}")
    return " ".join(morceaux)


# --------------------------------------------------------------------------- #
#  Application en mémoire
# --------------------------------------------------------------------------- #
def _champ(fiche: dict[str, Any], nom: str) -> Any:
    """Lit un champ, en acceptant les deux orthographes employées dans le projet.

    Le vocabulaire de l'API (« ip_a », « port_b ») et celui de la base (« ip_source »,
    « port_destination ») diffèrent — volontairement. Le filtre accepte les deux, sinon il
    faudrait deux syntaxes selon la vue, ce qui serait une source de confusion pour rien.
    """
    # Le nom du filtre n'est pas toujours celui du champ. `proto` désigne `protocole` :
    # c'est plus court à taper, et c'est ainsi que les autres outils le nomment.
    equivalences = {
        "proto": ("protocole",),
        "ip": ("ip_source", "ip_destination", "ip_a", "ip_b"),
        "port": ("port_source", "port_destination", "port_a", "port_b"),
    }
    if nom in equivalences:
        return [fiche.get(cle) for cle in equivalences[nom]]
    return fiche.get(nom)


def correspond(critere: Critere, fiche: dict[str, Any]) -> bool:
    """Un enregistrement satisfait-il un critère ? Fonction pure, donc testable seule."""
    if critere.champ == "texte":
        # La recherche libre regarde tout ce qui est affiché, sans avoir à énumérer les
        # champs : c'est ce qu'on attend d'une recherche.
        contenu = " ".join(
            str(valeur) for valeur in
            [fiche.get("resume"), fiche.get("protocole"), fiche.get("etat"),
             fiche.get("note_etat"), fiche.get("titre"), fiche.get("cible"),
             json_details(fiche.get("details"))]
            if valeur
        ).lower()
        return critere.valeur.lower() in contenu

    valeurs = _champ(fiche, critere.champ)
    if not isinstance(valeurs, list):
        valeurs = [valeurs]

    if critere.champ in CHAMPS_NUMERIQUES:
        nombre = int(critere.valeur)
        for valeur in valeurs:
            if valeur is None:
                continue
            try:
                actuel = int(valeur)
            except (TypeError, ValueError):
                continue
            if critere.comparateur == ">" and actuel > nombre:
                return True
            if critere.comparateur == "<" and actuel < nombre:
                return True
            if critere.comparateur == ">=" and actuel >= nombre:
                return True
            if critere.comparateur == "<=" and actuel <= nombre:
                return True
            if critere.comparateur == "=" and actuel == nombre:
                return True
        return False

    for valeur in valeurs:
        if valeur is None:
            continue
        texte = str(valeur).lower()
        if critere.champ == "ip" and critere.valeur.endswith("."):
            if texte.startswith(critere.valeur):
                return True
            continue
        if critere.champ in ("proto", "etat", "niveau"):
            if texte == critere.valeur:
                return True
            continue
        if critere.valeur.lower() in texte:
            return True
    return False


def filtrer(criteres: list[Critere], fiches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Applique tous les critères (ET logique)."""
    if not criteres:
        return fiches
    return [fiche for fiche in fiches
            if all(correspond(critere, fiche) for critere in criteres)]


def json_details(details: Any) -> str:
    """Rend les détails lisibles sous forme de texte, pour la recherche libre."""
    if not details:
        return ""
    if isinstance(details, str):
        return details
    try:
        import json

        return json.dumps(details, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(details)

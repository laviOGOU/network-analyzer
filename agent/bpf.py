"""Validation du filtre de capture (BPF) — Lot A.

POURQUOI UN FILTRE DE CAPTURE N'EST PAS UN FILTRE D'AFFICHAGE
-------------------------------------------------------------
Un filtre d'affichage trie ce qu'on **regarde**. Un filtre de capture décide ce qui est
**réellement capturé** : ce qui est exclu n'existe plus, et aucune manipulation ultérieure
ne le fera revenir. Une erreur ici est irréversible — un `port:443` tapé par erreur dans
le mauvais champ, et la capture du jour ne contient plus qu'un protocole.

D'où la règle : **on refuse plutôt que de deviner**. Une expression qui ne compile pas
arrête le démarrage avec un message qui explique, au lieu de lancer une capture qui ne
montrera rien.

COMMENT ON VALIDE
-----------------
On ne réécrit pas un analyseur de syntaxe BPF : ce serait long, incomplet, et différent de
celui qui s'exécutera réellement. On demande à **la bibliothèque qui filtrera** de compiler
l'expression — c'est la seule validation qui garantisse que ce qui est accepté ici sera
accepté là. Si Npcap refuse l'expression, mieux vaut le savoir avant la capture.

Les garde-fous de forme (longueur, caractères de contrôle) ne remplacent pas cette
vérification : ils évitent les fautes de frappe évidentes et bornent ce qu'on accepte.
"""

from __future__ import annotations

#: Longueur maximale. Un filtre BPF utile tient en une ligne ; au-delà, c'est une erreur
#: de copier-coller, et on évite de la faire traverser tout le système.
LONGUEUR_MAX = 200

#: Exemples donnés dans le message d'erreur. Un message qui dit seulement « invalide »
#: oblige à chercher la syntaxe BPF ; un message qui montre trois filtres utiles permet de
#: repartir tout de suite.
EXEMPLES = (
    'tcp port 443          tout le trafic web chiffré',
    'not port 53           tout sauf le DNS',
    'host 192.168.1.5      une seule machine',
    'udp and port 53       uniquement les requêtes DNS',
)


class ErreurFiltreBPF(ValueError):
    """Le filtre de capture est refusé. Le message dit pourquoi, et propose des exemples."""


def valider(expression: str | None) -> str:
    """Valide un filtre de capture. Rend l'expression nettoyée, ou lève une erreur.

    Un filtre vide est valide : c'est le cas le plus courant, et il signifie « tout
    capturer », qui est le bon réglage par défaut.
    """
    if expression is None:
        return ""
    expression = expression.strip()

    if not expression:
        return ""
    if len(expression) > LONGUEUR_MAX:
        raise ErreurFiltreBPF(
            f"Filtre de capture trop long ({len(expression)} caractères, "
            f"maximum {LONGUEUR_MAX}).\n"
            "  Un filtre utile tient en une ligne. Exemples :\n    "
            + "\n    ".join(EXEMPLES))
    if any(ord(caractere) < 32 for caractere in expression):
        raise ErreurFiltreBPF("Le filtre contient des caractères de contrôle.")

    # La seule validation qui compte : celle de la bibliothèque qui filtrera réellement.
    try:
        from scapy.arch.common import compile_filter

        compile_filter(expression)
    except ErreurFiltreBPF:
        raise
    except ImportError:                      # pragma: no cover
        # Sans Npcap ni libpcap, on ne peut pas compiler — et on ne peut pas capturer non
        # plus. La capture échouera de toute façon, avec son propre message.
        return expression
    except Exception as erreur:                                  # noqa: BLE001
        raise ErreurFiltreBPF(
            f"Filtre de capture refusé : {expression}\n"
            f"  ({type(erreur).__name__})\n"
            "  La syntaxe BPF n'est pas celle du filtre d'affichage : elle s'écrit\n"
            "  « tcp port 443 », et non « proto:tcp port:443 ».\n"
            "  Exemples :\n    " + "\n    ".join(EXEMPLES)) from erreur

    return expression

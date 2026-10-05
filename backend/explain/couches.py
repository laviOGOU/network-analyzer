"""Les couches réseau — ce qu'elles sont, et comment les montrer.

LA VUE EN TROIS NIVEAUX
-----------------------
C'est la façon de lire un paquet qui s'est imposée partout : une ligne dans une liste, le
détail par couche quand on clique, et une vue hexadécimale quand on veut voir les octets.
Ce module fournit la connaissance des deux derniers niveaux.

DEUX CHOSES QU'IL FAUT SAVOIR AVANT DE LIRE LA VUE HEXADÉCIMALE
---------------------------------------------------------------
**1. Elle est reconstruite, pas recopiée.** Le projet ne transporte aucun octet brut : ni
au repos, ni en transit. Les octets affichés sont **recalculés** à partir des champs
analysés. C'est une contrainte assumée — elle garantit qu'aucun contenu de message ne peut
se retrouver dans un fichier ou dans une base — et elle a une conséquence visible : ce que
l'outil n'a pas analysé ne peut pas être montré.

**2. Donc les trous se voient, et c'est voulu.** Les numéros de séquence, la fenêtre TCP,
les sommes de contrôle ne sont pas extraits aujourd'hui : la vue les affiche `??`. Un
affichage qui compléterait ces octets par des zéros serait plus joli et faux. Montrer
l'ignorance est ici la seule attitude honnête — et c'est aussi la plus utile, parce qu'on
voit exactement ce que l'outil sait.

C'est ce qui distingue cette vue de celle d'un outil qui capture réellement les octets :
elle ne prétend pas montrer le paquet, elle montre **ce que l'analyseur en a compris**.
"""

from __future__ import annotations

from typing import Any

#: Description des couches, dans l'ordre d'encapsulation.
#:
#: `champs` décrit la disposition des octets tels qu'ils apparaissent sur le fil. Chaque
#: entrée porte la clé du champ dans la fiche d'un paquet — ou `None` quand l'outil ne
#: l'extrait pas, auquel cas la vue affiche `??`.
COUCHES: list[dict[str, Any]] = [
    {
        "cle": "ethernet",
        "nom": "Ethernet",
        "role": ("La couche du réseau local. Elle porte les adresses matérielles des cartes "
                 "réseau — celles qui permettent à deux machines branchées sur le même "
                 "câble ou la même borne de se trouver, sans rien savoir d'Internet."),
        "champs": [
            {"libelle": "MAC destination", "octets": 6, "source": "mac_destination"},
            {"libelle": "MAC source", "octets": 6, "source": "mac_source"},
            {"libelle": "Type (IPv4, IPv6, ARP…)", "octets": 2, "source": None},
        ],
    },
    {
        "cle": "ip",
        "nom": "IP (Internet Protocol)",
        "role": ("La couche qui achemine d'un réseau à l'autre. C'est elle qui porte les "
                 "adresses IP et qui permet à un paquet de traverser plusieurs réseaux "
                 "avant d'arriver — ce qu'Ethernet ne sait pas faire."),
        "champs": [
            {"libelle": "Version et longueur d'en-tête", "octets": 1, "source": "version_ip"},
            {"libelle": "Longueur totale", "octets": 2, "source": "taille"},
            {"libelle": "Durée de vie (TTL)", "octets": 1, "source": "ttl"},
            {"libelle": "Protocole transporté", "octets": 1, "source": "protocole"},
            {"libelle": "Adresse source", "octets": "variable", "source": "ip_source"},
            {"libelle": "Adresse destination", "octets": "variable", "source": "ip_destination"},
            {"libelle": "Somme de contrôle", "octets": 2, "source": None},
        ],
    },
    {
        "cle": "transport",
        "nom": "TCP / UDP",
        "role": ("La couche qui fait parler les programmes. Elle ajoute les numéros de "
                 "port, qui désignent le service visé — c'est ce qui permet à une même "
                 "machine de faire tourner un serveur web et une messagerie en même temps."),
        "champs": [
            {"libelle": "Port source", "octets": 2, "source": "port_source"},
            {"libelle": "Port destination", "octets": 2, "source": "port_destination"},
            {"libelle": "Numéro de séquence", "octets": 4, "source": None},
            {"libelle": "Numéro d'acquittement", "octets": 4, "source": None},
            {"libelle": "Indicateurs (SYN, ACK…)", "octets": 2, "source": "flags_tcp"},
            {"libelle": "Taille de fenêtre", "octets": 2, "source": None},
            {"libelle": "Somme de contrôle", "octets": 2, "source": None},
        ],
    },
    {
        "cle": "application",
        "nom": "Couche applicative",
        "role": ("Le contenu du message, propre à chaque logiciel : une requête web, une "
                 "question DNS, une commande de messagerie. **Cet outil ne la conserve "
                 "pas** : il n'en garde que des indices — un nom de domaine demandé, un "
                 "type de message — jamais la charge utile elle-même."),
        "champs": [
            {"libelle": "Indice applicatif (domaine, type)", "octets": "variable",
             "source": "details"},
            {"libelle": "Charge utile", "octets": "non conservée", "source": None},
        ],
    },
]

#: Phrase affichée avec la vue hexadécimale. Elle est ici, et non dans l'interface, parce
#: qu'elle fait partie de ce que l'outil affirme — et qu'une affirmation se relit.
AVERTISSEMENT_HEX = (
    "Vue reconstruite à partir des métadonnées analysées, et non recopiée du réseau : "
    "aucun octet brut n'est transporté ni conservé. « ?? » marque ce que l'outil n'extrait "
    "pas encore — numéros de séquence, fenêtre TCP, sommes de contrôle. Ces octets sont "
    "laissés visibles plutôt que comblés, parce qu'un affichage complet mais inventé serait "
    "plus trompeur qu'un affichage incomplet."
)


def description() -> dict[str, Any]:
    """Rend la connaissance des couches, pour l'interface.

    Le rôle de chaque couche est la réponse à « à quoi sert cette couche ? » — la question
    qu'un débutant se pose devant une liste d'en-têtes, et à laquelle la documentation
    technique répond rarement en une phrase.
    """
    return {
        "couches": COUCHES,
        "avertissement_hex": AVERTISSEMENT_HEX,
        "extraits": [
            champ["libelle"]
            for couche in COUCHES for champ in couche["champs"]
            if champ["source"] is not None
        ],
    }

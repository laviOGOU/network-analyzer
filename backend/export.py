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


def _latin1(texte: str) -> str:
    """Ramène un texte à ce que les polices de base de fpdf2 savent écrire.

    Les polices livrées avec fpdf2 ne connaissent que le latin-1. Les accents français en font
    partie — « é » est écrit correctement — mais les caractères typographiques non : la flèche,
    le tiret long, le point médian, les guillemets français. Sans ce nettoyage, fpdf2 les
    remplace par un caractère de substitution et le document sort avec des trous.

    Les remplacer plutôt que les supprimer garde le sens : « A → B » devient « A -> B », qui se
    lit encore, au lieu de « A  B », qui ne se lit plus.
    """
    remplacements = {
        "\u2192": "->", "\u2190": "<-", "\u2014": "-", "\u2013": "-", "\u00b7": "-",
        "\u2026": "...", "\u2019": "'", "\u2018": "'", "\u00ab": '"', "\u00bb": '"',
        "\u202f": " ", "\u00a0": " ", "\u2265": ">=", "\u2264": "<=", "\u00d7": "x",
    }
    for avant, apres in remplacements.items():
        texte = texte.replace(avant, apres)
    return texte.encode("latin-1", "replace").decode("latin-1")


def vers_texte_couche(couche: dict[str, Any], valeurs: dict[str, Any] | None = None,
                      horodatage: str = "") -> str:
    """Rend l'explication d'une couche en texte brut, lisible sans aucun outil.

    C'est le format qui survit à tout : il s'ouvre dans un terminal, un bloc-notes, un journal
    de bord. Les autres formats s'adressent à un programme ; celui-ci s'adresse à un lecteur.
    """
    valeurs = valeurs or {}
    lignes = [
        "FlowScope - explication d'une couche reseau",
        "=" * 46,
        "",
        f"Couche    : {couche.get('nom', '?')}",
        f"Produit le: {horodatage or 'date inconnue'}",
        "",
        "CE QUE FAIT CETTE COUCHE",
        "-" * 46,
        str(couche.get("role", "")),
        "",
        "LES CHAMPS QU'ELLE PORTE",
        "-" * 46,
    ]
    for champ in couche.get("champs", []):
        libelle = champ.get("libelle", "?")
        octets = champ.get("octets", "?")
        lignes.append(f"  {libelle} ({octets} octet(s))")
        valeur = valeurs.get(champ.get("source")) if champ.get("source") else None
        if valeur not in (None, ""):
            lignes.append(f"      valeur dans ce paquet : {valeur}")
        else:
            lignes.append("      valeur dans ce paquet : non extraite")
        lignes.append("")
    lignes += ["-" * 46,
               "Chaque fait ci-dessus est mesure. Les valeurs absentes sont ecrites comme",
               "absentes plutot que devinees : l'incertitude fait partie de l'information.",
               "", "FlowScope - capturer, analyser, comprendre, expliquer."]
    return "\n".join(lignes)


def vers_pdf_couche(couche: dict[str, Any], valeurs: dict[str, Any] | None = None,
                    horodatage: str = "") -> bytes:
    """Rend l'explication d'une couche en PDF, avec fpdf2 - Python pur, sans dépendance système.

    Un PDF est le format qu'on remet a quelqu'un : il s'ouvre partout, il a la meme tete partout,
    et il ne se modifie pas par accident. C'est le format d'un document, pas d'une donnee.
    """
    from fpdf import FPDF

    valeurs = valeurs or {}
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    def texte(contenu: str, taille: int = 11, style: str = "", hauteur: float = 6) -> None:
        pdf.set_font("helvetica", style, taille)
        pdf.multi_cell(0, hauteur, _latin1(contenu), new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("helvetica", "B", 20)
    pdf.cell(0, 12, "FlowScope", new_x="LMARGIN", new_y="NEXT")
    texte("Capturer, analyser, comprendre, expliquer", 10)
    pdf.ln(4)
    pdf.set_draw_color(109, 141, 255)
    pdf.set_line_width(0.8)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)

    texte(f"Couche : {couche.get('nom', '?')}", 15, "B", 9)
    if horodatage:
        texte(f"Document produit le {horodatage}", 9)
    pdf.ln(3)

    texte("Ce que fait cette couche", 13, "B", 8)
    texte(str(couche.get("role", "")))
    pdf.ln(3)

    texte("Les champs qu'elle porte", 13, "B", 8)
    for champ in couche.get("champs", []):
        libelle = champ.get("libelle", "?")
        octets = champ.get("octets", "?")
        texte(f"- {libelle} ({octets} octet(s))", 11, "B", 6)
        valeur = valeurs.get(champ.get("source")) if champ.get("source") else None
        if valeur not in (None, ""):
            texte(f"    Valeur dans ce paquet : {valeur}", 10, "", 5)
        else:
            texte("    Valeur dans ce paquet : non extraite", 10, "", 5)
        pdf.ln(1)

    pdf.ln(4)
    texte("Chaque ligne ci-dessus est un fait mesure, jamais une deduction. Les valeurs que",
          9, "", 4.5)
    texte("FlowScope n'a pas pu extraire sont ecrites comme absentes plutot que devinees :",
          9, "", 4.5)
    texte("l'incertitude fait partie de l'information et ne se cache pas.", 9, "", 4.5)

    sortie = pdf.output()
    return bytes(sortie)


def vers_csv_couche(couche: dict[str, Any], valeurs: dict[str, Any] | None = None) -> str:
    """Rend les champs d'une couche en CSV, une ligne par champ.

    Cette fonction est distincte de `vers_csv`, et ce n'est pas un doublon : `vers_csv` a des
    colonnes FIXES par vue (paquets, communications, detections), parce qu'un tableau exporte
    doit avoir la meme forme a chaque fois. Une couche, elle, a un nombre de champs variable
    selon la couche. Lui imposer les colonnes d'une autre vue aurait produit un fichier aux
    colonnes vides, ou une erreur. Deux besoins differents, deux fonctions.

    Le point-virgule et le BOM sont ceux de `vers_csv` : c'est ce qu'attend un tableur
    francais, ou la virgule est un separateur decimal.
    """
    valeurs = valeurs or {}
    tampon = io.StringIO()
    ecrivain = csv.writer(tampon, delimiter=";", lineterminator="\r\n", quoting=csv.QUOTE_ALL)
    ecrivain.writerow(["Couche", "Champ", "Octets", "Valeur dans ce paquet", "Origine de la valeur"])
    for champ in couche.get("champs", []):
        source = champ.get("source")
        valeur = valeurs.get(source) if source else None
        ecrivain.writerow([
            _cellule(couche.get("nom")),
            _cellule(champ.get("libelle")),
            _cellule(champ.get("octets")),
            _cellule(valeur) if valeur not in (None, "") else "non extraite",
            _cellule(source) if source else "non extraite",
        ])
    return "\ufeff" + tampon.getvalue()

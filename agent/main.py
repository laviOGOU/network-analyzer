"""Point d'entrée de l'agent de capture.

L'agent fait cinq choses, dans cet ordre, et rien d'autre :

    capture → analyse → file d'attente → envoi HTTPS → comptes rendus

Il tourne sur la machine dont on veut voir le trafic, parce qu'un serveur en ligne ne
peut pas écouter un réseau local. C'est la contrainte d'architecture qui justifie son
existence séparée du backend.

Utilisation
-----------
    python agent/main.py --interfaces                      # que voit-on ?
    python agent/main.py --interface "Wi-Fi" --a-blanc     # sans rien envoyer
    python agent/main.py --interface "Wi-Fi" --backend http://127.0.0.1:8000 --jeton ...
    python agent/main.py --pcap capture.pcap               # mode replay (phase ultérieure)

`--a-blanc` n'est pas un détail de confort : c'est le mode qui permet de vérifier que la
capture et l'analyse fonctionnent avant de mettre en jeu un backend ou un jeton.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import sys
import time
import uuid
from pathlib import Path

# Permet `python agent/main.py` depuis la racine du dépôt comme depuis le dossier agent.
RACINE = Path(__file__).resolve().parent.parent
if str(RACINE) not in sys.path:
    sys.path.insert(0, str(RACINE))

from agent import capture as mod_capture          # noqa: E402
from agent import sender as mod_sender            # noqa: E402


def construire_analyseur() -> argparse.ArgumentParser:
    """Déclare les options. Chaque option est documentée là où elle est définie."""
    analyseur = argparse.ArgumentParser(
        prog="agent",
        description="Agent de capture et d'analyse de paquets réseau.",
        epilog="Autorisation : ne capturez que sur un réseau que vous administrez "
               "ou pour lequel vous disposez d'une autorisation écrite.",
    )
    analyseur.add_argument("--interfaces", action="store_true",
                           help="liste les interfaces réseau disponibles, puis quitte")
    analyseur.add_argument("--interface", "-i", default=None,
                           help="interface à écouter : nom (« Wi-Fi »), description ou adresse")
    analyseur.add_argument("--filtre", "-f", default="",
                           help="filtre BPF, ex. « tcp or udp » (vide = tout capturer)")
    analyseur.add_argument("--duree", "-d", type=float, default=0,
                           help="durée de capture en secondes (0 = jusqu'à Ctrl+C)")
    analyseur.add_argument("--backend", default=os.getenv("ANALYZER_BACKEND", ""),
                           help="adresse du backend (défaut : ANALYZER_BACKEND)")
    analyseur.add_argument("--jeton", default=os.getenv("ANALYZER_AGENT_TOKEN", ""),
                           help="jeton d'agent (défaut : ANALYZER_AGENT_TOKEN)")
    analyseur.add_argument("--a-blanc", action="store_true",
                           help="analyse sans rien envoyer : vérifie la chaîne locale")
    analyseur.add_argument("--nom", default=socket.gethostname(),
                           help="nom de l'agent, visible dans l'interface")
    analyseur.add_argument("--verbose", "-v", action="count", default=0,
                           help="-v : journal détaillé, -vv : très détaillé")
    return analyseur


def configurer_journal(niveau: int) -> None:
    """Journalisation : les détails vont dans les journaux, pas dans l'interface."""
    logging.basicConfig(
        level=logging.DEBUG if niveau > 1 else (logging.INFO if niveau else logging.WARNING),
        format="%(asctime)s  %(levelname)-7s %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


def afficher_interfaces() -> int:
    """Liste les interfaces comme un humain peut les lire."""
    interfaces = mod_capture.lister_interfaces()
    if not interfaces:
        print("Aucune interface réseau détectée.")
        print(f"Moteur de capture : {mod_capture.moteur_disponible()}")
        return 1

    print(f"\nMoteur de capture : {mod_capture.moteur_disponible()}")
    print(f"{len(interfaces)} interface(s) :\n")
    for indice, iface in enumerate(interfaces, 1):
        adresses = ", ".join(iface.adresses) or "sans adresse"
        print(f"  {indice:2}. {iface.nom}")
        if iface.description and iface.description != iface.nom:
            print(f"      {iface.description}")
        print(f"      adresses : {adresses}")
        if iface.adresse_mac:
            print(f"      matériel : {iface.adresse_mac}")
        print()
    print("Choix :  --interface \"<nom affiché>\"  (ou une de ses adresses)\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Assemble les briques et fait tourner la capture."""
    options = construire_analyseur().parse_args(argv)
    configurer_journal(options.verbose)

    if options.interfaces:
        return afficher_interfaces()

    # ---------------------------------------------------------------- destination
    envoyeur: mod_sender.Envoyeur
    if options.a_blanc:
        memoire = mod_sender.EnvoyeurMemoire()
        envoyeur = mod_sender.Envoyeur(memoire)
        print("Mode à blanc : rien ne sera envoyé.")
    else:
        if not options.backend or not options.jeton:
            print("Backend et jeton obligatoires (--backend et --jeton), ou utilisez "
                  "--a-blanc pour vérifier la capture sans rien envoyer.")
            return 2
        client = mod_sender.ClientBackend(options.backend, options.jeton,
                                          nom_agent=options.nom, session="")
        envoyeur = mod_sender.Envoyeur(client.envoyer)

    # ------------------------------------------------------------------ interface
    try:
        interface = mod_capture.choisir_interface(options.interface)
    except mod_capture.ErreurCapture as erreur:
        print(f"\n{erreur}\n")
        return 2

    if interface is None:
        print("Aucune interface précisée : préciser --interface (voir --interfaces).")
        return 2

    # -------------------------------------------------------------------- capture
    session = str(uuid.uuid4())
    if not options.a_blanc:
        client.session = session                     # rattache les lots à cette session

    def sur_paquet(fiche: dict) -> None:
        envoyeur.ajouter(fiche)

    capteur = mod_capture.Capture(interface=interface, filtre=options.filtre,
                                  sur_paquet=sur_paquet)

    print(f"\nInterface : {interface}")
    print(f"Filtre    : {options.filtre or 'aucun (tout capturer)'}")
    print(f"Session   : {session}")
    if options.duree:
        print(f"Durée     : {options.duree:.0f} s")

    try:
        capteur.demarrer()
    except mod_capture.ErreurCapture as erreur:
        print(f"\n{erreur}\n")
        return 2

    envoyeur.demarrer()
    print("Capture en cours — Ctrl+C pour arrêter.\n")

    # Arrêt propre : on intercepte Ctrl+C pour vider la file avant de sortir, sinon les
    # dernières secondes de capture — souvent les plus intéressantes — seraient perdues.
    arret = {"demande": False}

    def sur_interruption(*_args: object) -> None:
        arret["demande"] = True

    ancien = signal.signal(signal.SIGINT, sur_interruption)

    debut = time.monotonic()
    try:
        while not arret["demande"]:
            if options.duree and (time.monotonic() - debut) >= options.duree:
                break
            time.sleep(0.5)
            _afficher_avancement(capteur, envoyeur, debut, interface)
    finally:
        signal.signal(signal.SIGINT, ancien)
        capteur.arreter()
        envoyeur.arreter(vider=True)

    print(f"\n\nCapture arrêtée.")
    print(f"  paquets capturés   : {capteur.recus}")
    print(f"  analyses partielles: {capteur.erreurs_analyse}")
    print(f"  {envoyeur.stats.resume()}")
    if options.a_blanc:
        print(f"  (mode à blanc : {len(memoire.paquets)} paquets analysés, aucun envoi)")
    return 0


def _afficher_avancement(capteur: mod_capture.Capture, envoyeur: mod_sender.Envoyeur,
                         debut: float, interface: str) -> None:
    """Une seule ligne réécrite sur place : lisible sans noyer le terminal."""
    ecoule = time.monotonic() - debut
    debit = capteur.recus / ecoule if ecoule > 0 else 0
    ligne = (f"\r  {ecoule:6.1f}s · capturés {capteur.recus:6d} ({debit:5.1f}/s) · "
             f"envoyés {envoyeur.stats.envoyes:6d} · file {envoyeur.stats.file:4d}"
             + (f" · abandons {envoyeur.stats.abandonnes}" if envoyeur.stats.abandonnes else "")
             + (f" · échecs {envoyeur.stats.echecs}" if envoyeur.stats.echecs else ""))
    print(ligne[:140].ljust(140), end="", flush=True)


if __name__ == "__main__":
    sys.exit(main())

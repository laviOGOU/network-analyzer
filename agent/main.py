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
import datetime as dt
import logging
import os
import signal
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

# Permet `python agent/main.py` depuis la racine du dépôt comme depuis le dossier agent.
RACINE = Path(__file__).resolve().parent.parent
if str(RACINE) not in sys.path:
    sys.path.insert(0, str(RACINE))

from agent import capture as mod_capture          # noqa: E402
from agent import detection as mod_detection      # noqa: E402
from agent import replay as mod_replay            # noqa: E402
from agent import flows as mod_flows              # noqa: E402
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
    analyseur.add_argument("--pcap", default=None,
                           help="Rejouer un fichier .pcap au lieu de capturer en direct")
    analyseur.add_argument("--vitesse", type=float, default=0.0,
                           help="Vitesse de rejeu : 0 = aussi vite que possible (défaut), "
                                "1 = rythme réel, 10 = dix fois plus vite")
    analyseur.add_argument("--inspecter", action="store_true",
                           help="Décrire le fichier .pcap sans le rejouer")
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

    # ------------------------------------------------------------- mode replay
    # Un fichier .pcap remplace la capture : le reste de la chaîne — analyseur, table des
    # communications, détection, transmission — est exactement le même. C'est ce qui fait
    # du replay une vérification utile, et non une démonstration à part.
    if options.inspecter:
        if not options.pcap:
            print("--inspecter demande un fichier : ajouter --pcap <fichier>")
            return 2
        try:
            resume_fichier = mod_replay.resumer_fichier(options.pcap)
        except mod_replay.ErreurReplay as erreur:
            print(f"\n{erreur}\n")
            return 2
        print(f"\nFichier   : {resume_fichier['fichier']}")
        print(f"Taille    : {resume_fichier['octets'] / 1024:.1f} ko")
        print(f"Paquets   : {resume_fichier['paquets']}")
        print(f"Période   : {resume_fichier['debut']} → {resume_fichier['fin']}")
        print(f"Durée     : {resume_fichier['duree_secondes']:.1f} s\n")
        return 0

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
        # La destination joint les communications au lot de paquets correspondant.
        envoyeur = mod_sender.Envoyeur(
            lambda lot: client.envoyer(lot,
                                       communications=communications_a_transmettre(),
                                       detections=detections_a_transmettre()))

    # ------------------------------------------------------------------ interface
    # En mode replay, aucune interface n'est nécessaire : les paquets viennent du fichier.
    # On saute donc la sélection, au lieu d'imposer une interface qui ne servirait à rien.
    if options.pcap:
        interface = f"fichier {Path(options.pcap).name}"
    else:
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

    # Table des communications. `a_envoyer` contient les versions à transmettre : celles
    # qui évoluent, et celles qui viennent de se terminer — sans quoi la dernière version
    # d'une conversation, souvent la plus intéressante, ne partirait jamais.
    table = mod_flows.SuiviCommunications()
    # Le détecteur vit aussi longtemps que la capture : c'est lui qui se souvient des
    # machines déjà vues, la seule information qu'un lot isolé ne peut pas fournir.
    detecteur = mod_detection.Detecteur()
    a_envoyer: dict[str, dict] = {}
    verrou = threading.Lock()      # accès partagé entre le fil de capture et celui d'envoi

    def _instant_du_paquet(fiche: dict) -> dt.datetime | None:
        """L'horodatage porté par la fiche, ou `None` s'il est illisible.

        L'import est local et explicite : le nom du module de dates varie d'un fichier à
        l'autre de ce dépôt, et c'est précisément l'erreur qu'a produite la première
        version — un `NameError` au premier paquet, invisible en tests puisque le rejeu
        n'était pas encore exercé de bout en bout.
        """
        try:
            return dt.datetime.fromisoformat(
                (fiche.get("horodatage") or "").replace("Z", "+00:00"))
        except (ValueError, AttributeError, TypeError):
            return None

    def sur_paquet(fiche: dict) -> None:
        communication = table.ajouter(fiche)
        if communication is not None:
            # L'état se calcule à l'heure **du paquet**, et non à celle de la machine.
            # En capture en direct les deux coïncident ; en rejeu elles diffèrent de
            # plusieurs mois, et confondre les deux ferait paraître abandonnée toute
            # connexion d'un fichier ancien.
            communication = mod_flows.maj_etat(
                communication, _instant_du_paquet(fiche))
            fiche_communication = communication.vers_dict()
            with verrou:
                a_envoyer[fiche_communication["cle"]] = fiche_communication
        envoyeur.ajouter(fiche)

    def retirer_communications_terminees() -> None:
        """Sort de la table les conversations terminées, et les garde à transmettre."""
        for communication in table.retirer_terminées(capteur.maintenant()):
            fiche_communication = communication.vers_dict()
            with verrou:
                a_envoyer[fiche_communication["cle"]] = fiche_communication

    def detections_a_transmettre() -> list[dict]:
        """Relance la détection sur l'ensemble des conversations vivantes.

        On lui donne la table entière, et non le seul lot courant : un balayage répartit
        ses tentatives sur plusieurs lots, et ne serait jamais vu si on ne lui montrait
        que le lot en cours. Le coût reste faible — quelques centaines de communications,
        huit règles sans aucune entrée-sortie.

        Seules les détections créées ou mises à jour sont renvoyées : le backend les
        indexe par (règle, cible), donc une détection déjà connue est actualisée plutôt
        que dupliquée.
        """
        vivantes = [communication.vers_dict() for communication in table.actives()]
        return [detection.vers_dict() for detection in detecteur.analyser(vivantes)]

    def communications_a_transmettre() -> list[dict]:
        """Rend les communications en attente, évaluées à l'instant présent.

        On copie puis on vide sous verrou : sans cela, un paquet arrivé pendant l'envoi
        serait perdu, ou envoyé deux fois.
        """
        table.completer_etat(capteur.maintenant())
        with verrou:
            en_attente = list(a_envoyer.values())
            a_envoyer.clear()
        return en_attente

    # La source change, le reste ne change pas : `sur_paquet` alimente la même table de
    # communications et le même détecteur, et l'envoyeur transmet de la même façon.
    if options.pcap:
        try:
            capteur = mod_replay.ReplayPcap(options.pcap, sur_paquet=sur_paquet,
                                            vitesse=options.vitesse)
        except mod_replay.ErreurReplay as erreur:
            print(f"\n{erreur}\n")
            return 2
    else:
        capteur = mod_capture.Capture(interface=interface, filtre=options.filtre,
                                      sur_paquet=sur_paquet)

    print(f"\n{'Fichier' if options.pcap else 'Interface'} : {interface}")
    print(f"Filtre    : {options.filtre or 'aucun (tout capturer)'}")
    print(f"Session   : {session}")
    if options.duree:
        print(f"Durée     : {options.duree:.0f} s")

    try:
        capteur.demarrer()
    except (mod_capture.ErreurCapture, mod_replay.ErreurReplay) as erreur:
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
            # Un fichier a une fin : le rejeu annonce qu'il a tout lu, et la boucle
            # s'arrête. Sans cela, la ligne de commande tournerait indéfiniment après la
            # fin du fichier — elle attendrait un paquet qui ne viendra jamais.
            if options.pcap and getattr(capteur, "termine", False):
                break
            if options.duree and (time.monotonic() - debut) >= options.duree:
                break
            time.sleep(0.5)
            # Repère les SYN restés sans réponse : sans cet appel, leur état ne serait
            # réévalué qu'à l'arrivée du paquet suivant — qui n'arrivera jamais.
            retirer_communications_terminees()
            _afficher_avancement(capteur, envoyeur, debut, interface, table)
    finally:
        signal.signal(signal.SIGINT, ancien)
        capteur.arreter()
        retirer_communications_terminees()
        envoyeur.arreter(vider=True)

    print(f"\n\nCapture arrêtée.")
    print(f"  paquets capturés   : {capteur.recus}")
    print(f"  analyses partielles: {capteur.erreurs_analyse}")
    print(f"  {envoyeur.stats.resume()}")
    # Les détections avant l'arrêt : le dernier passage doit porter sur le trafic
    # complet, sinon les formes apparues dans les dernières secondes ne seraient
    # jamais signalées.
    table.completer_etat(capteur.maintenant())
    detecteur.analyser([communication.vers_dict() for communication in table.actives()])
    comptes = detecteur.compter()
    print(f"  détections         : {comptes.get('observation', 0)} observation(s) · "
          f"{comptes.get('hypothèse', 0)} hypothèse(s) · "
          f"{comptes.get('alerte', 0)} alerte(s)")
    resume = mod_flows.resume_chiffre(table.actives())
    print(f"  communications     : {len(table.actives())} encore ouvertes "
          f"· {resume['etats_incertains']} d'état incertain")
    if options.a_blanc:
        print(f"  (mode à blanc : {len(memoire.paquets)} paquets analysés, aucun envoi)")
    return 0


def _afficher_avancement(capteur: mod_capture.Capture, envoyeur: mod_sender.Envoyeur,
                         debut: float, interface: str,
                         table: mod_flows.SuiviCommunications | None = None) -> None:
    """Une seule ligne réécrite sur place : lisible sans noyer le terminal."""
    ecoule = time.monotonic() - debut
    debit = capteur.recus / ecoule if ecoule > 0 else 0
    ligne = (f"\r  {ecoule:6.1f}s · capturés {capteur.recus:6d} ({debit:5.1f}/s) · "
             f"envoyés {envoyeur.stats.envoyes:6d} · file {envoyeur.stats.file:4d}"
             + (f" · conversations {len(table.actives()):4d}" if table else "")
             + (f" · abandons {envoyeur.stats.abandonnes}" if envoyeur.stats.abandonnes else "")
             + (f" · échecs {envoyeur.stats.echecs}" if envoyeur.stats.echecs else ""))
    print(ligne[:140].ljust(140), end="", flush=True)


if __name__ == "__main__":
    sys.exit(main())

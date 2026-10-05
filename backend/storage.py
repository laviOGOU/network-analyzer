"""Conservation des paquets reçus — version en mémoire (phase 1).

Pourquoi une interface plutôt qu'un accès direct à une base
-----------------------------------------------------------
Les routes ne connaissent que les méthodes décrites ici. En phase 5, Supabase prendra la
place de cette mémoire vive : seule cette classe changera, les routes resteront
identiques. C'est le point d'étranglement unique — le même principe qui a permis de
basculer Au Djassa de SQLite à PostgreSQL sans toucher aux pages.

Deux compteurs distincts, et ce n'est pas un détail
---------------------------------------------------
`total_recus` compte **tout** ce qui est arrivé depuis le démarrage.
`paquets` ne garde que les `taille_max` derniers.

Confondre les deux est l'erreur classique : `len(paquets)` plafonne à la taille du
tampon, et l'on croirait que le réseau s'est calmé alors que c'est le tampon qui est
plein. L'interface affiche donc les deux — « 854 reçus · 200 conservés ».

Le verrou n'est pas décoratif : FastAPI exécute les routes synchrones dans un groupe de
fils, et deux lots peuvent arriver en même temps.
"""

from __future__ import annotations

import threading
from collections import Counter, deque
from typing import Any

from backend import filtres

#: Taille du dictionnaire de détails conservé tel quel. Au-delà, on le tronque : ce qui
#: compte pour l'observateur, ce sont les faits saillants, pas l'exhaustivité.
#: Nombre de clés de détail conservées par paquet. Borné, parce que ce qui vient du réseau
#: ne doit pas pouvoir faire grossir la base à volonté — mais assez large pour porter ce
#: dont les vues ont besoin, y compris les deux clés qui relient une adresse à son nom.
MAX_DETAILS_CONSERVES = 16


class Stockage:
    """Tampon circulaire de paquets, avec statistiques recalculées à la demande."""

    def __init__(self, taille_max: int = 2000) -> None:
        self.taille_max = taille_max
        self._verrou = threading.Lock()
        #: `deque(maxlen=…)` jette automatiquement le plus ancien : la mémoire est bornée
        #: par construction, sans code de nettoyage à maintenir.
        self._paquets: deque[dict[str, Any]] = deque(maxlen=taille_max)
        self._sessions: dict[str, dict[str, Any]] = {}
        self._total_recus = 0
        self._octets_recus = 0
        self._analyses_partielles = 0
        self._par_protocole: Counter[str] = Counter()
        self._par_source: Counter[str] = Counter()
        self._par_destination: Counter[str] = Counter()
        self._par_port: Counter[int] = Counter()
        self._premier: str | None = None
        self._dernier: str | None = None

        # Communications, refondues par clé : l'agent revoit la même conversation
        # évoluer, et la dernière version reçue est la bonne.
        self._communications: dict[str, dict[str, Any]] = {}
        self._communications_vues = 0
        # Détections, indexées par (session, règle, cible) pour la même raison que les
        # communications : la version la plus récente fait foi, sans doublon.
        self._detections: dict[str, dict[str, Any]] = {}
        self._detections_vues = 0

    # ------------------------------------------------------------------ écriture
    def enregistrer_lot(self, session: str, agent: str, paquets: list[dict[str, Any]]) -> int:
        """Enregistre un lot validé. Renvoie le nombre de paquets acceptés.

        Un lot vide est accepté sans rien faire : le modèle Pydantic l'interdit déjà, mais
        cette méthode peut être appelée directement par un test ou un script, et une
        exception ici ferait échouer tout un envoi pour rien.
        """
        if not paquets:
            return 0

        with self._verrou:
            for paquet in paquets:
                self._ajouter(paquet)
                self._paquets.append(paquet)

            suivie = self._sessions.setdefault(session, {
                "session": session,
                "agent": agent,
                "debut": paquet_horodatage(paquets[0]),
                "paquets": 0,
                "octets": 0,
                "dernier": None,
            })
            suivie["paquets"] += len(paquets)
            suivie["octets"] += sum(p.get("taille") or 0 for p in paquets)
            suivie["dernier"] = paquet_horodatage(paquets[-1])

            return len(paquets)

    def _ajouter(self, paquet: dict[str, Any]) -> None:
        """Met à jour les compteurs. Appelé sous verrou."""
        self._total_recus += 1
        self._octets_recus += paquet.get("taille") or 0
        if paquet.get("analyse_partielle"):
            self._analyses_partielles += 1

        self._par_protocole[paquet.get("protocole") or "inconnu"] += 1

        source = paquet.get("ip_source")
        if source:
            self._par_source[source] += 1
        destination = paquet.get("ip_destination")
        if destination:
            self._par_destination[destination] += 1

        # Pour les ports, on ne compte que ceux qui identifient un service côté serveur :
        # un port source tiré au hasard (49 703) ne dit rien et noierait les ports
        # vraiment fréquentés (443, 53, 80).
        port = paquet.get("port_destination")
        if port is not None:
            self._par_port[port] += 1

        horodatage = paquet.get("horodatage")
        if horodatage:
            self._premier = self._premier or horodatage
            self._dernier = horodatage

    def enregistrer_communications(self, session: str,
                                   communications: list[dict[str, Any]]) -> int:
        """Refond les communications reçues, par clé.

        Pourquoi la session fait partie de l'index : deux agents — ou deux captures
        successives — peuvent observer la même conversation. Indexer sur la seule clé
        ferait que la seconde écraserait la première, et le tableau de bord attribuerait à
        une capture les chiffres d'une autre. Le schéma SQL déclare la même contrainte
        (unicité sur session et clé) : les deux doivent dire la même chose.

        On ne conserve pas tout indéfiniment : un nombre borné, les plus récentes d'abord.
        Un tableau de bord vivant n'a pas besoin de l'intégralité de l'historique, et
        laisser grossir le dictionnaire ferait exactement ce qu'on reproche aux programmes
        qui fuient — en silence.
        """
        if not communications:
            return 0
        with self._verrou:
            for communication in communications:
                cle = communication.get("cle")
                if not cle:
                    continue
                index = f"{session}|{cle}"
                if index not in self._communications:
                    self._communications_vues += 1
                self._communications[index] = {**communication, "session": session}

            # Élagage : on garde les plus récentes, et l'on compte celles qui sortent
            # séparément (`_communications_vues` ne redescend jamais).
            if len(self._communications) > self.taille_max:
                triees = sorted(self._communications.items(),
                                key=lambda element: element[1].get("dernier_paquet") or "",
                                reverse=True)
                self._communications = dict(triees[:self.taille_max])
            return len(communications)

    def enregistrer_detections(self, session: str,
                               detections: list[dict[str, Any]]) -> int:
        """Refond les détections reçues, indexées par (session, règle, cible).

        La même détection, revue à chaque lot par l'agent, doit mettre à jour son compteur
        et non apparaître en double : sinon le tableau de bord afficherait cent fois la
        même phrase, et plus rien d'autre.
        """
        if not detections:
            return 0
        with self._verrou:
            for detection in detections:
                regle = detection.get("regle")
                if not regle:
                    continue
                index = f"{session}|{regle}|{detection.get('cible') or ''}"
                if index not in self._detections:
                    self._detections_vues += 1
                self._detections[index] = {**detection, "session": session}

            # Même règle de bornage que pour les communications : on garde les plus
            # récentes, et on laisse tomber les plus anciennes.
            if len(self._detections) > self.taille_max:
                triees = sorted(self._detections.items(),
                                key=lambda element: element[1].get("dernier") or "",
                                reverse=True)
                self._detections = dict(triees[:self.taille_max])
            return len(detections)

    def detections(self, limite: int = 200, niveau: str | None = None,
                   session: str | None = None,
                   filtre: list | None = None) -> list[dict[str, Any]]:
        """Détections conservées, la plus récente d'abord."""
        with self._verrou:
            liste = list(self._detections.values())

        if session:
            liste = [d for d in liste if d.get("session") == session]
        if niveau:
            liste = [d for d in liste if d.get("niveau") == niveau]
        if filtre:
            liste = filtres.filtrer(filtre, liste)
        liste.sort(key=lambda d: (d.get("dernier") or "", d.get("debut") or ""), reverse=True)
        return liste[:limite]

    def vider(self) -> None:
        """Remet le tampon et les compteurs à zéro. Utilisé par les tests.

        Les champs sont réinitialisés un par un, plutôt qu'en rappelant le constructeur :
        une remise à zéro doit rester lisible, et si un compteur est ajouté plus tard,
        l'oubli se voit ici.
        """
        with self._verrou:
            self._paquets.clear()
            self._sessions.clear()
            self._total_recus = 0
            self._octets_recus = 0
            self._analyses_partielles = 0
            self._par_protocole.clear()
            self._par_source.clear()
            self._par_destination.clear()
            self._par_port.clear()
            self._premier = None
            self._dernier = None
            self._communications.clear()
            self._communications_vues = 0
            self._detections.clear()
            self._detections_vues = 0

    # ------------------------------------------------------------------ lecture
    def paquets(self, limite: int = 100, protocole: str | None = None,
                  session: str | None = None, recherche: str | None = None,
                  filtre: list | None = None) -> list[dict[str, Any]]:
        """Derniers paquets, du plus récent au plus ancien, filtrés si demandé."""
        with self._verrou:
            paquets = list(self._paquets)

        if protocole:
            paquets = [p for p in paquets if (p.get("protocole") or "").lower() == protocole.lower()]
        if session:
            # Le horodatage borne la session : en phase 1 le stockage ne garde pas de
            # lien direct paquet→session, et l'inventer serait pire que de le dire.
            bornes = self._sessions.get(session)
            if bornes:
                debut, fin = bornes.get("debut"), bornes.get("dernier")
                paquets = [p for p in paquets
                           if (debut is None or p.get("horodatage", "") >= debut)
                           and (fin is None or p.get("horodatage", "") <= fin)]
        if recherche:
            besoin = recherche.lower()
            paquets = [p for p in paquets if besoin in _texte_paquet(p)]
        # Le filtre d'affichage s'applique **avant** la troncature : couper d'abord puis
        # filtrer rendrait un nombre de lignes qui dépend de l'ordre d'arrivée, ce qui
        # donnerait des résultats différents d'un rafraîchissement à l'autre.
        if filtre:
            paquets = filtres.filtrer(filtre, paquets)

        return list(reversed(paquets))[:max(0, limite)]

    def communication(self, cle: str, session: str | None = None) -> dict[str, Any] | None:
        """Retrouve une communication par sa clé.

        La clé seule peut désigner plusieurs communications : la même conversation observée
        par deux captures porte la même clé dans deux sessions différentes. Sans session
        précisée, on rend la plus récemment vue — plutôt que la première trouvée, dont le
        choix dépendrait de l'ordre interne du dictionnaire.
        """
        with self._verrou:
            if session:
                return self._communications.get(f"{session}|{cle}")
            candidates = [c for index, c in self._communications.items()
                          if index.endswith(f"|{cle}")]
        if not candidates:
            return None
        return max(candidates, key=lambda c: c.get("dernier_paquet") or "")

    def communications(self, limite: int = 100, etat: str | None = None,
                       protocole: str | None = None, session: str | None = None,
                       recherche: str | None = None,
                       filtre: list | None = None) -> list[dict[str, Any]]:
        """Communications conservées, la plus récente d'abord."""
        with self._verrou:
            liste = list(self._communications.values())

        if session:
            liste = [c for c in liste if c.get("session") == session]
        if etat:
            liste = [c for c in liste if (c.get("etat") or "").lower() == etat.lower()]
        if protocole:
            liste = [c for c in liste
                     if (c.get("protocole") or "").lower() == protocole.lower()]
        if recherche:
            besoin = recherche.lower()
            liste = [c for c in liste
                     if besoin in f"{c.get('ip_a','')} {c.get('ip_b','')} "
                                  f"{c.get('port_a','')} {c.get('port_b','')} "
                                  f"{c.get('etat','')}".lower()]

        if filtre:
            liste = filtres.filtrer(filtre, liste)

        liste.sort(key=lambda c: c.get("dernier_paquet") or "", reverse=True)
        return liste[:max(0, limite)]

    def statistiques(self) -> dict[str, Any]:
        """Chiffres du tableau de bord, calculés ici et jamais par le navigateur."""
        with self._verrou:
            return {
                "paquets_total": self._total_recus,
                "paquets_conserves": len(self._paquets),
                "octets_total": self._octets_recus,
                "par_protocole": dict(self._par_protocole.most_common()),
                "top_sources": _classement(self._par_source, 5),
                "top_destinations": _classement(self._par_destination, 5),
                "ports_frequents": [{"valeur": port, "nombre": nombre}
                                    for port, nombre in self._par_port.most_common(8)],
                "premier_paquet": self._premier,
                "dernier_paquet": self._dernier,
                "analyses_partielles": self._analyses_partielles,
                "sessions": len(self._sessions),
                "detections_total": self._detections_vues,
                "detections_conservees": len(self._detections),
                "detections_par_niveau": dict(Counter(
                    d.get("niveau") or "inconnu" for d in self._detections.values())),
                "communications_total": self._communications_vues,
                "communications_conservees": len(self._communications),
                "communications_par_etat": dict(
                    Counter((c.get("etat") or "inconnue")
                            for c in self._communications.values()).most_common()),
                "communications_incertaines": sum(
                    1 for c in self._communications.values() if not c.get("etat_certain")),
            }

    def session(self, identifiant: str) -> dict[str, Any] | None:
        with self._verrou:
            return dict(self._sessions.get(identifiant) or {}) or None

    def sessions(self) -> list[dict[str, Any]]:
        with self._verrou:
            return sorted(self._sessions.values(), key=lambda s: s.get("dernier") or "",
                          reverse=True)


# --------------------------------------------------------------------------- #
#  Utilitaires
# --------------------------------------------------------------------------- #
def _classement(compteur: Counter[str], limite: int) -> list[dict[str, Any]]:
    """Transforme un compteur en liste classée, lisible telle quelle en JSON."""
    return [{"valeur": valeur, "nombre": nombre}
            for valeur, nombre in compteur.most_common(limite)]


def _texte_paquet(paquet: dict[str, Any]) -> str:
    """Concatène les champs interrogeables d'un paquet, pour la recherche libre."""
    morceaux = [
        str(paquet.get("ip_source") or ""),
        str(paquet.get("ip_destination") or ""),
        str(paquet.get("protocole") or ""),
        str(paquet.get("resume") or ""),
        str(paquet.get("port_destination") or ""),
        str(paquet.get("details", {}).get("dns_question") or ""),
    ]
    return " ".join(morceaux).lower()


def paquet_horodatage(paquet: dict[str, Any]) -> str | None:
    """Horodatage d'un paquet, sous forme de chaîne comparable.

    On compare des chaînes ISO 8601 plutôt que des dates : elles s'ordonnent
    correctement tant qu'elles portent le même fuseau, et cela évite une conversion à
    chaque comparaison.
    """
    horodatage = paquet.get("horodatage")
    if horodatage is None:
        return None
    return horodatage if isinstance(horodatage, str) else str(horodatage)


def details_reduits(details: dict[str, Any]) -> dict[str, Any]:
    """Ne conserve que les détails les plus utiles, et borne leur nombre."""
    if not isinstance(details, dict):
        return {}
    # L'ordre compte : ce qui figure en tête est conservé en priorité si la limite est
    # atteinte. Les deux clés `dns_adresse` et `dns_reponse_nom` ont été ajoutées après
    # coup — sans elles, relier une adresse à son nom est impossible, et la fonctionnalité
    # paraîtrait « ne pas marcher » alors que la donnée n'avait jamais été conservée.
    # C'est le genre d'oubli qu'on ne voit qu'en regardant les données réelles.
    # Les clés de TLS et de HTTP ont été ajoutées avec leurs fonctionnalités : sans elles
    # ici, elles seraient jetées à l'ingestion, et l'interface afficherait un vide que
    # personne ne saurait expliquer. C'est l'erreur qui a déjà coûté les noms de domaine.
    # `seq`, `ack`, `fenetre` et `charge_utile` sont en tete : ce sont eux qui portent les
    # analyses de l'Expert Info, et ils doivent survivre meme si la limite est atteinte.
    ordre = ("seq", "ack", "fenetre", "charge_utile", "processus_local", "processus_pid",
             "dns_question", "dns_reponse_nom", "dns_adresse", "dns_type", "dns_reponse",
             "tls_sni", "tls_version", "http_methode", "http_hote", "http_code",
             "icmp_lisible", "type_icmp", "operation_arp", "tronque", "type_ethernet",
             "tls_illisible", "http_illisible")
    retenus: dict[str, Any] = {}
    for cle in ordre:
        if cle in details:
            retenus[cle] = details[cle]
        if len(retenus) >= MAX_DETAILS_CONSERVES:
            break
    return retenus or dict(list(details.items())[:MAX_DETAILS_CONSERVES])

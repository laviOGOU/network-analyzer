"""Enrichissement par API externe — ce que l'on peut savoir d'une adresse.

CE QUE CE MODULE APPORTE
------------------------
Une adresse IP ne dit rien à personne. Enrichie, elle devient : « Serveur d'Amazon à
Dublin », « Adresse signalée 47 fois pour du balayage », « Opérateur mobile ivoirien ».
C'est le passage de la donnée à l'information.

LES DEUX FOURNISSEURS, ET POURQUOI EUX
--------------------------------------
    ipinfo.io     situation géographique, opérateur, numéro de réseau (ASN)
    AbuseIPDB     réputation : l'adresse a-t-elle été signalée, et combien de fois

Ils répondent à deux questions différentes, et c'est ce qui justifie d'en interroger
deux plutôt qu'un. La géographie dit **où**, la réputation dit **si l'on s'en méfie**.
Un serveur d'Amazon à Dublin n'est pas suspect ; la même adresse signalée quarante fois
pour du balayage mérite un regard.

CE QUE CE MODULE REFUSE DE FAIRE
--------------------------------
**Il n'enrichit jamais une adresse privée.** Ni 192.168.x, ni 10.x, ni fe80::. Ces
adresses ne sortent pas sur Internet : aucun service externe ne peut rien en dire, et
les interroger reviendrait à envoyer sur le réseau la topologie de votre réseau local.
Le schéma de base de données interdit déjà ces lignes par une contrainte ; le code les
écarte en amont. Une règle vérifiée à deux endroits vaut mieux qu'une règle espérée.

**Il n'ajoute jamais d'information à une explication.** L'enrichissement est affiché à
part, avec sa source et sa date. Un score de réputation n'est pas une preuve : c'est
l'avis d'un tiers, formulé à un instant donné.

CE QUI SE PASSE SANS CLÉ D'API
------------------------------
Rien de grave, et c'est voulu : l'enrichissement est **facultatif**. Sans clé, il ne se
passe simplement rien — les adresses s'affichent sans contexte, et tout le reste de
l'outil fonctionne. Un outil d'analyse qui cesserait de fonctionner sans accès à un
service tiers serait inutilisable au pire moment, et sur un réseau isolé il ne
fonctionnerait pas du tout.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import threading
import time
from collections import deque
from typing import Any

logger = logging.getLogger(__name__)

#: Durée de validité d'une réponse. Une géolocalisation ne change pas d'une heure à
#: l'autre, et un score de réputation évolue lentement : on interroge donc rarement, ce
#: qui économise le quota des deux services — ils sont gratuits jusqu'à un millier
#: d'appels par jour.
VALIDITE_SECONDES = 24 * 3600

#: Délais courts : plutôt renoncer à un contexte que faire attendre le tableau de bord.
DELAI_SECONDES = 6.0

#: Nombre d'appels autorisés par minute, tous fournisseurs confondus. Les offres
#: gratuites plafonnent à quelques dizaines d'appels par minute ; dépasser ferait
#: répondre une erreur que l'on prendrait pour une panne.
APPELS_PAR_MINUTE = 20


def _privee(ip: str) -> bool:
    """Vrai pour une adresse qui ne sort pas sur Internet.

    On écarte aussi les adresses de service — diffusion, multidiffusion, indéfinie,
    locales de lien : aucun tiers ne peut rien en dire, et elles ne désignent aucune
    machine.
    """
    try:
        adresse = ipaddress.ip_address(ip)
    except ValueError:
        return True                       # adresse illisible : traitée comme non enrichissable
    return (adresse.is_private or adresse.is_loopback or adresse.is_link_local
            or adresse.is_multicast or adresse.is_unspecified)


class Enrichissement:
    """Interroge les deux fournisseurs, garde les réponses en cache, et tient le rythme.

    Le cache et le limiteur sont dans la même classe parce qu'ils servent la même
    contrainte : ne pas dépasser le quota d'un service gratuit. Le cache évite de
    redemander ce qu'on sait ; le limiteur évite de demander trop vite ce qu'on ne sait
    pas encore.
    """

    def __init__(self, cle_ipinfo: str = "", cle_abuseipdb: str = "") -> None:
        self.cle_ipinfo = cle_ipinfo
        self.cle_abuseipdb = cle_abuseipdb
        self._cache: dict[str, dict[str, Any]] = {}
        self._appels: deque[float] = deque()      # horodatage des appels récents
        self._verrou = threading.Lock()
        self._desactive = False                   # mis à vrai après un échec définitif

    # ---------------------------------------------------------------- état
    def disponible(self) -> bool:
        """Y a-t-il au moins un fournisseur configuré ?"""
        return bool(self.cle_ipinfo or self.cle_abuseipdb)

    def etat(self) -> dict[str, Any]:
        """Décrit la configuration, pour l'afficher honnêtement dans l'interface."""
        fournisseurs = []
        if self.cle_ipinfo:
            fournisseurs.append("ipinfo.io")
        if self.cle_abuseipdb:
            fournisseurs.append("AbuseIPDB")
        return {
            "active": self.disponible(),
            "fournisseurs": fournisseurs,
            "message": ("Enrichissement actif : "
                        + " et ".join(fournisseurs) + " sont interrogés."
                        if fournisseurs else
                        "Enrichissement inactif : aucune clé configurée. Les adresses "
                        "s'affichent sans contexte, et tout le reste fonctionne."),
            "adresses_en_cache": len(self._cache),
        }

    # ---------------------------------------------------------------- rythme
    def _autoriser_un_appel(self) -> bool:
        """Autorise un appel si le rythme le permet. Un « non » n'est pas une erreur."""
        maintenant = time.monotonic()
        with self._verrou:
            while self._appels and maintenant - self._appels[0] > 60:
                self._appels.popleft()
            if len(self._appels) >= APPELS_PAR_MINUTE:
                return False
            self._appels.append(maintenant)
            return True

    # ---------------------------------------------------------------- cache
    def _en_cache(self, ip: str) -> dict[str, Any] | None:
        with self._verrou:
            entree = self._cache.get(ip)
        if entree is None:
            return None
        if time.time() - entree["_le"] > VALIDITE_SECONDES:
            with self._verrou:
                self._cache.pop(ip, None)
            return None
        return entree

    def _mettre_en_cache(self, ip: str, donnees: dict[str, Any]) -> None:
        with self._verrou:
            self._cache[ip] = {**donnees, "_le": time.time()}

    # ---------------------------------------------------------------- fournisseurs
    def _ipinfo(self, ip: str) -> dict[str, Any]:
        """Situation géographique et opérateur, par ipinfo.io."""
        import httpx

        reponse = httpx.get(
            f"https://ipinfo.io/{ip}/json",
            # Le jeton passe en en-tête plutôt que dans l'adresse : une clé dans une URL
            # finit dans les journaux du serveur, des proxys et des historiques.
            headers={"Authorization": f"Bearer {self.cle_ipinfo}"} if self.cle_ipinfo else {},
            timeout=DELAI_SECONDES,
            params={"token": self.cle_ipinfo} if self.cle_ipinfo else None,
        )
        reponse.raise_for_status()
        donnees = reponse.json()
        return {
            "pays": donnees.get("country"),
            "region": donnees.get("region"),
            "ville": donnees.get("city"),
            "organisation": donnees.get("org"),
            "reseau": donnees.get("network"),
            "fuseau": donnees.get("timezone"),
            "source_geo": "ipinfo.io",
        }

    def _abuseipdb(self, ip: str) -> dict[str, Any]:
        """Réputation de l'adresse, par AbuseIPDB."""
        import httpx

        reponse = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.cle_abuseipdb, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=DELAI_SECONDES,
        )
        reponse.raise_for_status()
        donnees = reponse.json().get("data", {})
        return {
            "score_abus": donnees.get("abuseConfidenceScore"),
            "signalements": donnees.get("totalReports"),
            "dernier_signalement": donnees.get("lastReportedAt"),
            "usage": donnees.get("usageType"),
            "domaine": donnees.get("domain"),
            "pays_abus": donnees.get("countryCode"),
            "liste_noire": bool(donnees.get("isWhitelisted") is False),
            "source_reputation": "AbuseIPDB",
        }

    # ---------------------------------------------------------------- point d'entrée
    def enrichir(self, ip: str) -> dict[str, Any] | None:
        """Rend ce que l'on sait d'une adresse, ou `None` si l'on ne peut rien en dire.

        L'ordre compte : le cache d'abord, car il ne coûte rien ; la nature de l'adresse
        ensuite, car une adresse privée ne doit jamais partir sur le réseau ; la
        disponibilité des clés enfin, car sans elles il n'y a rien à tenter.
        """
        if not ip or _privee(ip):
            return None
        if not self.disponible():
            return None
        if self._desactive:
            return None

        en_cache = self._en_cache(ip)
        if en_cache is not None:
            return {k: v for k, v in en_cache.items() if not k.startswith("_")}

        if not self._autoriser_un_appel():
            # Rythme atteint : on rend ce qu'on a, sans rien inventer et sans erreur.
            return {"ip": ip, "en_attente": True, "message": "Rythme d'interrogation atteint"}

        resultat: dict[str, Any] = {"ip": ip}
        echecs = []

        if self.cle_ipinfo:
            try:
                resultat.update(self._ipinfo(ip))
            except Exception as erreur:                        # noqa: BLE001
                echecs.append(f"ipinfo.io : {type(erreur).__name__}")

        if self.cle_abuseipdb:
            try:
                resultat.update(self._abuseipdb(ip))
            except Exception as erreur:                        # noqa: BLE001
                echecs.append(f"AbuseIPDB : {type(erreur).__name__}")

        # Aucun des deux n'a répondu : on ne met rien en cache, sinon un incident
        # temporaire serait mémorisé vingt-quatre heures durant.
        if len(resultat) == 1:
            resultat["echecs"] = echecs
            return resultat

        if echecs:
            resultat["echecs"] = echecs
        self._mettre_en_cache(ip, resultat)
        return resultat

    @staticmethod
    def resume(enrichi: dict[str, Any] | None) -> str:
        """Une phrase lisible, pour l'interface. Jamais de conclusion, seulement des faits."""
        if not enrichi:
            return "Non enrichie (adresse locale, ou enrichissement inactif)"

        morceaux = []
        if enrichi.get("organisation"):
            morceaux.append(str(enrichi["organisation"]))
        lieu = " ".join(str(enrichi.get(k)) for k in ("ville", "pays") if enrichi.get(k))
        if lieu:
            morceaux.append(lieu)

        score = enrichi.get("score_abus")
        if score is not None:
            signalements = enrichi.get("signalements") or 0
            if int(score) == 0:
                morceaux.append("aucun signalement connu")
            else:
                morceaux.append(f"score de signalement {score}/100 "
                                f"({signalements} signalement(s))")

        return " · ".join(morceaux) if morceaux else "Aucune information disponible"

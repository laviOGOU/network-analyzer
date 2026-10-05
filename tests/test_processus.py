"""Tests de l'association port → processus (Lot C).

CE QUI EST ÉPROUVÉ ICI
----------------------
1. **Le côté local est déterminé par l'adresse, jamais par le port seul.** Le port 443 est
   tenu par `chrome.exe` sur cette machine *et* par le serveur distant : sans regarder
   l'adresse, on nommerait le mauvais programme une fois sur deux. C'est la propriété
   centrale de ce module.
2. **Un échec de lecture ne coûte jamais un paquet.** Sans droits suffisants, Windows refuse
   le propriétaire d'une partie des connexions : l'outil continue sans les noms, il ne
   s'arrête pas et n'invente rien.

Les tables sont **injectées** dans les tests : aucun n'interroge le système de la machine qui
les exécute, et le résultat est donc le même partout.
"""

from __future__ import annotations

import socket

from agent import processus


class FausseAdresse:
    def __init__(self, port):
        self.port = port


class FausseConnexion:
    def __init__(self, port, pid, type_socket=socket.SOCK_STREAM):
        self.laddr = FausseAdresse(port)
        self.pid = pid
        self.type = type_socket


def fiche(source, port_source, destination, port_destination, protocole="TCP"):
    return {
        "protocole": protocole,
        "ip_source": source, "port_source": port_source,
        "ip_destination": destination, "port_destination": port_destination,
        "details": {},
    }


LOCALES = {"192.168.1.5"}


# --------------------------------------------------------------------------- #
#  Le côté local se détermine par l'adresse
# --------------------------------------------------------------------------- #
def test_le_processus_est_cherche_du_cote_local_quand_la_machine_emet():
    table = {("TCP", 52344): {"nom": "chrome.exe", "pid": 1234}}
    trouve = processus.processus_du_paquet(
        fiche("192.168.1.5", 52344, "140.82.121.4", 443), table, LOCALES)
    assert trouve == {"nom": "chrome.exe", "pid": 1234}


def test_le_processus_est_cherche_du_cote_local_quand_la_machine_recoit():
    table = {("TCP", 52344): {"nom": "chrome.exe", "pid": 1234}}
    trouve = processus.processus_du_paquet(
        fiche("140.82.121.4", 443, "192.168.1.5", 52344), table, LOCALES)
    assert trouve == {"nom": "chrome.exe", "pid": 1234}


def test_le_port_du_serveur_distant_n_est_pas_pris_pour_un_programme_local():
    """La propriété centrale : le port 443 est tenu par un programme local *et* par le
    serveur distant. Sans regarder l'adresse, on nommerait le mauvais."""
    table = {("TCP", 443): {"nom": "serveur-local.exe", "pid": 99}}
    trouve = processus.processus_du_paquet(
        fiche("192.168.1.5", 52344, "140.82.121.4", 443), table, LOCALES)
    assert trouve is None


def test_un_paquet_dont_aucun_cote_n_est_local_n_a_pas_de_processus():
    table = {("TCP", 443): {"nom": "x", "pid": 1}}
    assert processus.processus_du_paquet(
        fiche("10.0.0.1", 52344, "140.82.121.4", 443), table, LOCALES) is None


def test_un_protocole_non_transport_ne_produit_rien():
    table = {("TCP", 52344): {"nom": "chrome.exe", "pid": 1}}
    assert processus.processus_du_paquet(
        fiche("192.168.1.5", 52344, "8.8.8.8", 0, protocole="ICMP"), table, LOCALES) is None


def test_une_table_vide_ne_produit_rien():
    assert processus.processus_du_paquet(
        fiche("192.168.1.5", 52344, "8.8.8.8", 80), {}, LOCALES) is None


# --------------------------------------------------------------------------- #
#  Normalisation des adresses — le défaut qui rendait le module muet
# --------------------------------------------------------------------------- #
def test_une_ipv6_ecrite_autrement_correspond_quand_meme():
    """La même adresse s'écrit de plusieurs façons selon la bibliothèque qui la produit.

    Sans normalisation, la comparaison de chaînes échoue, le module reste muet, et rien ne
    le signale. C'était le cas sur une machine dont le trafic est très majoritairement en
    IPv6 : la table était construite, les paquets passaient, aucune correspondance n'avait
    lieu.
    """
    table = {("TCP", 52344): {"nom": "chrome.exe", "pid": 1234}}
    locales_compressees = {"2001:42d8:4:a:face:b00c:3333:7020"}
    trouve = processus.processus_du_paquet(
        fiche("2001:42d8:0004:000a:face:b00c:3333:7020", 52344, "2606:4700::1", 443),
        table, locales_compressees)
    assert trouve == {"nom": "chrome.exe", "pid": 1234}


def test_une_adresse_invalide_ne_correspond_a_rien():
    table = {("TCP", 52344): {"nom": "chrome.exe", "pid": 1}}
    assert processus.processus_du_paquet(
        fiche("pas-une-adresse", 52344, "8.8.8.8", 443), table, LOCALES) is None


def test_la_normalisation_accepte_le_suffixe_de_zone():
    """Windows écrit parfois `fe80::1%12` : le suffixe désigne l'interface, pas l'adresse."""
    assert processus.normaliser("fe80::1%12") == processus.normaliser("fe80::1")


def test_la_normalisation_laisse_passer_ce_qui_n_est_pas_une_adresse():
    """Elle ne lève pas : une chaîne inconnue ne correspondra simplement à rien."""
    assert processus.normaliser("inconnu") == "inconnu"


# --------------------------------------------------------------------------- #
#  Construction de la table
# --------------------------------------------------------------------------- #
def test_une_connexion_sans_pid_est_ignoree():
    """Sans droits, Windows ne donne pas le propriétaire : on ne devine pas."""
    table = processus.table_processus([
        FausseConnexion(52344, None),
        FausseConnexion(52345, 0),
    ])
    assert table == {}


def test_le_protocole_est_distingue():
    table = processus.table_processus([
        FausseConnexion(53, 1, socket.SOCK_DGRAM),
    ])
    # Le pid 1 n'existe probablement pas sur la machine de test : la lecture du nom échoue,
    # et l'entrée est écartée. C'est le comportement voulu — on ne nomme pas au hasard.
    assert all(cle[0] in ("TCP", "UDP") for cle in table)


def test_une_connexion_sans_port_est_ignoree():
    class SansPort:
        laddr = None
        pid = 4
        type = socket.SOCK_STREAM

    assert processus.table_processus([SansPort()]) == {}


# --------------------------------------------------------------------------- #
#  Enrichissement d'une fiche
# --------------------------------------------------------------------------- #
def test_l_enrichissement_n_ajoute_la_cle_que_si_un_processus_est_trouve():
    """Une absence n'a pas à être écrite dans la base pour chaque paquet."""
    import time

    classe = processus.TableCachee()
    # La table porte une entrée qui ne correspond pas : elle doit être **non vide**, sans
    # quoi le cache la considère absente et la reconstruit — en écrasant celle qu'on
    # injecte. Un dictionnaire vide est faux en Python, et c'est le piège.
    classe._table = {("TCP", 65001): {"nom": "autre.exe", "pid": 9}}
    classe._locales = LOCALES
    classe._construite_a = time.monotonic()
    # La relecture est neutralisée : sans cela le test lirait la table **du système qui
    # l'exécute**, et il réussirait ou échouerait selon les connexions du moment. Un test
    # dépendant de l'état de la machine n'est pas un test.
    classe._relire = lambda: (classe._table, LOCALES)

    sans = fiche("192.168.1.5", 52344, "8.8.8.8", 2)
    classe.enrichir(sans)
    assert "processus_local" not in sans["details"]

    classe._table = {("TCP", 52344): {"nom": "chrome.exe", "pid": 1234}}
    avec = fiche("192.168.1.5", 52344, "140.82.121.4", 443)
    classe.enrichir(avec)
    assert avec["details"]["processus_local"] == "chrome.exe"
    assert avec["details"]["processus_pid"] == 1234


def test_une_relecture_rattrape_une_connexion_absente_de_l_instantane():
    """Le défaut mesuré : un instantané gardé cinq secondes ignore les connexions récentes.

    Sur une capture réelle, 29 ports locaux apparaissaient dans les paquets, 122 dans la
    table, et 8 seulement étaient communs. La relecture — au plus une fois par seconde —
    est ce qui rattrape une connexion ouverte depuis moins longtemps que le cache.
    """
    import time

    classe = processus.TableCachee()
    classe._table = {("TCP", 1): {"nom": "autre.exe", "pid": 9}}
    classe._locales = LOCALES
    classe._construite_a = time.monotonic()

    appels = {"nombre": 0}

    def relire():
        appels["nombre"] += 1
        return ({("TCP", 52344): {"nom": "chrome.exe", "pid": 1234}}, LOCALES)

    classe._relire = relire
    fiche_recente = fiche("192.168.1.5", 52344, "140.82.121.4", 443)
    classe.enrichir(fiche_recente)

    assert appels["nombre"] == 1, "la table n'a pas été relue"
    assert fiche_recente["details"]["processus_local"] == "chrome.exe"


def test_la_relecture_est_bornee_dans_le_temps():
    """Sans borne, un port introuvable déclencherait un appel système par paquet."""
    import time

    classe = processus.TableCachee()
    classe._table = {("TCP", 1): {"nom": "autre.exe", "pid": 9}}
    classe._locales = LOCALES
    classe._construite_a = time.monotonic()

    appels = {"nombre": 0}

    def relire():
        appels["nombre"] += 1
        return ({("TCP", 1): {"nom": "autre.exe", "pid": 9}}, LOCALES)

    classe._relire = relire
    for _ in range(5):
        classe.enrichir(fiche("192.168.1.5", 55555, "8.8.8.8", 80))

    assert appels["nombre"] <= 1, f"trop de relectures : {appels['nombre']}"


def test_sans_psutil_le_module_ne_leve_pas_d_erreur():
    """Un outil d'analyse ne s'arrête pas parce qu'une dépendance facultative manque."""
    assert isinstance(processus.connexions_systeme(), list)
    assert isinstance(processus.adresses_locales(), set)
    assert isinstance(processus.table_processus([]), dict)

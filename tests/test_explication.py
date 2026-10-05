"""Tests du moteur d'explication (phase 3).

Le moteur d'explication est la pièce que l'énoncé désigne comme la plus importante : c'est
lui qui fait passer l'outil de « voici des paquets » à « voici ce qui se passe ». Ces tests
portent donc surtout sur deux propriétés, et non sur des phrases exactes :

    1. **Jamais de certitude sur une hypothèse.** Le port 443 ne prouve pas HTTPS. Un test
       qui vérifierait le texte exact se casserait à la première reformulation ; un test qui
       vérifie que « probablement » est présent, et que la phrase n'affirme pas, survit aux
       réécritures et protège la propriété qui compte.
    2. **Jamais d'échec.** Une règle fautive, une donnée absurde ou un protocole inconnu
       doivent produire une explication valide, jamais une exception : sur un tableau de
       bord, une case vide est un moindre mal, une erreur cinq cents l'est beaucoup moins.

La structure est vérifiée une fois, pour toutes les règles, via un jeu d'entrées variées.
"""

from __future__ import annotations

import pytest

from backend.explain import llm
from backend.explain import rules as moteur

#: Les cinq parties de la structure fixe, plus l'identifiant de la règle.
CLES = {"titre", "faits_observes", "interpretation", "confiance",
        "explication_simple", "regle"}


def explication_de(entree, nom_de_regle):
    """Retrouve l'explication produite par une règle précise.

    Nécessaire parce que `expliquer()` ne rend que l'explication principale — la première
    applicable, celle qui répond à « qu'est-ce que c'est ? ». Les propriétés testées ici
    (certitude de l'état, équilibre du volume, situation locale ou externe) vivent dans les
    explications suivantes. Les chercher dans la principale reviendrait à tester un ordre
    de priorité, pas la propriété visée.
    """
    for explication in moteur.explications(entree):
        if explication["regle"] == nom_de_regle:
            return explication
    raise AssertionError(f"aucune explication produite par la règle « {nom_de_regle} »")


def communication(**remplacements):
    """Une communication TCP complète, dont chaque test ne change que ce qui l'intéresse."""
    base = {
        "cle": "TCP|192.168.1.5:49703|93.184.216.34:443",
        "protocole": "TCP",
        "ip_a": "192.168.1.5", "port_a": 49703,
        "ip_b": "93.184.216.34", "port_b": 443,
        "initiateur": "192.168.1.5",
        "etat": "établie", "etat_certain": True, "note_etat": "",
        "indicateurs": ["SYN", "SYN-ACK", "ACK"],
        "paquets_a_vers_b": 8, "paquets_b_vers_a": 6, "paquets_total": 14,
        "octets_a_vers_b": 1200, "octets_b_vers_a": 45000, "octets_total": 46200,
    }
    base.update(remplacements)
    return base


# --------------------------------------------------------------------------- #
#  La structure
# --------------------------------------------------------------------------- #
def test_structure_toujours_complete():
    """Toute explication a exactement la même forme, quelle que soit la règle appliquée."""
    entrees = [
        communication(),
        communication(protocole="UDP", port_b=53),
        communication(protocole="ICMP", port_a=None, port_b=None),
        communication(protocole="ARP", port_a=None, port_b=None),
        communication(port_b=44444),
        communication(protocole="ZORG", port_b=None, port_a=None, etat="inconnue"),
    ]
    for entree in entrees:
        for explication in moteur.explications(entree):
            assert set(explication) == CLES, f"structure incomplète : {explication}"
            assert explication["titre"]
            assert isinstance(explication["faits_observes"], list)
            assert explication["confiance"] in ("faible", "moyenne", "haute")
            assert explication["explication_simple"]
            assert explication["regle"]


def test_les_faits_observes_sont_nommes():
    """Les faits doivent être vérifiables : ils citent les valeurs observées."""
    explication = moteur.expliquer(communication())
    texte = " ".join(explication["faits_observes"])
    assert "443" in texte
    assert "TCP" in texte


# --------------------------------------------------------------------------- #
#  La règle absolue : pas de certitude sur une hypothèse
# --------------------------------------------------------------------------- #
def test_le_port_ne_prouve_pas_le_service():
    """Le port 443 est une convention, pas une preuve : le texte doit rester prudent."""
    explication = moteur.expliquer(communication())
    assert "HTTPS" in explication["titre"]
    assert "probable" in (explication["titre"] + explication["interpretation"]).lower()
    assert "preuve" in explication["interpretation"].lower()


def test_un_service_sensible_n_est_pas_une_attaque():
    """Signaler un service sensible, oui — laisser croire à une attaque, non.

    C'est la différence entre un outil utile et un outil qui fait peur sans raison. Un
    partage de fichiers Windows sur son propre réseau est parfaitement normal.
    """
    explication = moteur.expliquer(communication(port_b=445, protocole="TCP"))
    assert "SMB" in explication["titre"]
    assert "sensible" in explication["interpretation"].lower()
    assert "pas un signe d'attaque" in explication["interpretation"].lower()

    telnet = moteur.expliquer(communication(port_b=23, protocole="TCP"))
    assert "Telnet" in telnet["titre"]


def test_la_confiance_suit_la_certitude_de_l_observation():
    """Un état déduit ne peut pas porter une confiance haute, ni un état observé une faible."""
    observe = explication_de(communication(etat="établie", etat_certain=True), "etat_observe")
    deduit = explication_de(communication(etat="établie", etat_certain=False,
                                          note_etat="Capture commencée en cours de route."),
                            "etat_deduit")
    assert observe["confiance"] == "haute"
    assert deduit["confiance"] == "faible"
    # L'explication déduite doit dire qu'elle est déduite, et pourquoi.
    assert "déduction" in deduit["interpretation"]
    assert "Capture commencée en cours de route." in " ".join(deduit["faits_observes"])


def test_le_port_udp_porte_une_confiance_moindre():
    """Sur UDP, les conventions de ports sont plus lâches : la confiance doit baisser."""
    sur_tcp = moteur.expliquer(communication(protocole="TCP", port_b=443))
    sur_udp = moteur.expliquer(communication(protocole="UDP", port_b=443))
    assert sur_tcp["confiance"] == "haute"
    assert sur_udp["confiance"] == "moyenne"


# --------------------------------------------------------------------------- #
#  Les règles particulières
# --------------------------------------------------------------------------- #
def test_port_non_repertorie_le_dit_sans_broder():
    """Un port inconnu n'est pas suspect : le texte ne doit pas le laisser croire."""
    explication = moteur.expliquer(communication(port_b=44444))
    assert "non répertorié" in explication["titre"].lower()
    assert explication["confiance"] == "faible"
    assert "ne veut pas dire qu'il est suspect" in explication["interpretation"]


def test_dns_dit_ce_que_les_requetes_revelent():
    """Le point le plus sensible du projet : les noms disent quels sites sont consultés."""
    explication = explication_de(communication(protocole="UDP", port_a=51000, port_b=53,
                                               ip_b="192.168.1.1"), "dns_resolution")
    assert "DNS" in explication["titre"]
    assert "sensible" in explication["interpretation"].lower()
    assert "sites consultés" in explication["interpretation"]


def test_mdns_est_presente_comme_normal():
    """Une annonce entre appareils du réseau local ne doit pas inquiéter."""
    explication = explication_de(communication(protocole="UDP", port_b=5353), "mdns_decouverte")
    assert "mDNS" in explication["titre"]
    assert "normales" in explication["interpretation"]


def test_icmp_distingue_le_ping_du_message_isole():
    """Un aller-retour ICMP est un ping ; un sens unique n'en est pas un."""
    ping = moteur.expliquer(communication(protocole="ICMP", port_a=None, port_b=None,
                                          paquets_a_vers_b=2, paquets_b_vers_a=2,
                                          paquets_total=4))
    seul = moteur.expliquer(communication(protocole="ICMP", port_a=None, port_b=None,
                                          paquets_a_vers_b=3, paquets_b_vers_a=0,
                                          paquets_total=3))
    assert "disponibilité" in ping["titre"]
    assert "disponibilité" not in seul["titre"]
    assert ping["confiance"] == "haute"


def test_arp_explique_la_traduction_d_adresse():
    explication = moteur.expliquer(communication(protocole="ARP", port_a=None, port_b=None))
    assert "ARP" in explication["titre"]
    assert "annuaire" in explication["explication_simple"]


def test_echange_local_contre_echange_externe():
    """Situer la communication : c'est le contexte qui manque le plus à un débutant."""
    local = explication_de(communication(ip_a="192.168.1.5", ip_b="192.168.1.42"),
                           "echange_local")
    assert "local" in local["titre"].lower()

    # Le cas le plus fréquent de tous : une machine du réseau joint Internet.
    sortant = explication_de(communication(ip_a="192.168.1.5", ip_b="142.250.75.14"),
                             "vers_exterieur")
    assert "extérieur" in sortant["titre"].lower()

    # Le cas inverse, plus rare et plus intéressant : de la connexion entrante.
    entrant = explication_de(communication(ip_a="142.250.75.14", ip_b="192.168.1.5"),
                             "connexion_entrante")
    assert "entrante" in entrant["titre"].lower()

    # Deux adresses publiques : ni l'une ni l'autre n'est chez nous. Attention au piège,
    # 10.0.0.0/8 est un bloc privé — deux adresses publiques sont nécessaires ici.
    externe = explication_de(communication(ip_a="93.184.216.34", ip_b="142.250.75.14"),
                             "echange_public")
    assert "publiques" in externe["titre"]

    # Et l'ordre : pour un port connu, l'explication principale reste celle du service.
    # Une règle générale ne doit pas passer devant une règle précise — sinon « échange
    # local » remplacerait « probablement HTTPS », qui en dit beaucoup plus.
    principale = moteur.expliquer(communication(ip_a="192.168.1.5", ip_b="142.250.75.14"))
    assert principale["regle"] == "port_service_connu"


def test_le_desequilibre_du_volume_est_detecte():
    """Beaucoup reçu contre peu envoyé : le profil d'un téléchargement."""
    explication = explication_de(communication(paquets_a_vers_b=2, paquets_b_vers_a=40,
                                               paquets_total=42), "echange_desequilibre")
    assert "reçoit" in explication["explication_simple"].lower()
    assert explication["confiance"] == "moyenne"


# --------------------------------------------------------------------------- #
#  Les propriétés de robustesse
# --------------------------------------------------------------------------- #
def test_meme_entree_meme_sortie():
    """Le déterminisme est ce qui rend le moteur vérifiable : on peut rejouer et comparer."""
    entree = communication()
    premier = moteur.explications(entree)
    second = moteur.explications(entree)
    assert premier == second


@pytest.mark.parametrize("entree", [
    {},
    {"protocole": None, "port_a": None, "port_b": None, "ip_a": None, "ip_b": None,
     "etat": None, "etat_certain": None},
    {"protocole": "TCP", "port_a": "pas un port", "port_b": "443"},
    {"protocole": "TCP", "port_a": -5, "port_b": 99999},
    {"protocole": "TCP", "ip_a": "<script>alert(1)</script>", "ip_b": "93.184.216.34",
     "port_b": 443},
    {"protocole": "ZORG", "port_a": 1, "port_b": 2, "etat": "état inventé"},
])
def test_aucune_entree_ne_provoque_d_erreur(entree):
    """Aucune donnée ne doit faire échouer le moteur : c'est le rôle du repli par règle.

    Un paquet malformé vient du réseau : le moteur doit le traiter comme une donnée, pas
    comme une hypothèse de travail. Sur un tableau de bord public, une explication vide est
    acceptable, une erreur cinq cents ne l'est pas.
    """
    resultat = moteur.expliquer(entree)
    assert set(resultat) == CLES
    assert resultat["titre"]


def test_aucun_balisage_ne_traverse():
    """Les adresses viennent du réseau : elles sont affichées, donc elles sont filtrées."""
    explication = moteur.expliquer(communication(ip_a="<script>alert(1)</script>",
                                                  ip_b="<b>gras</b>"))
    texte = " ".join(explication["faits_observes"]) + explication["interpretation"]
    assert "<script>" not in texte
    assert "<b>" not in texte


def test_aucune_regle_ne_s_applique_dit_qu_elle_ne_sait_pas():
    """Ne rien savoir est un résultat : il s'annonce, il ne s'invente pas."""
    # Un protocole inconnu, aucun port, aucun état, aucune adresse : rien ne s'applique.
    explication = moteur.expliquer({"protocole": "ZORG"})
    assert len(moteur.explications({"protocole": "ZORG"})) == 0
    assert explication["regle"] == "aucune_regle"
    assert "sans interprétation" in explication["titre"].lower()


def test_les_nombres_sont_ecrits_a_la_francaise():
    """Une seule convention de nombre dans toute l'interface : la virgule décimale."""
    explication = moteur.expliquer(communication(octets_total=46200, paquets_total=14))
    texte = " ".join(explication["faits_observes"])
    assert "46,2 ko" in texte
    assert "46.2 ko" not in texte


def test_la_base_de_connaissances_est_utilisable():
    """Un garde-fou simple : la base ne doit pas se vider par accident."""
    assert moteur.services_connus() >= 30


# --------------------------------------------------------------------------- #
#  La couche IA : facultative, et jamais bloquante
# --------------------------------------------------------------------------- #
def test_sans_cle_la_couche_ia_est_inactive(monkeypatch):
    monkeypatch.delenv("ANALYZER_LLM_KEY", raising=False)
    assert llm.disponible() is False
    etat = llm.etat()
    assert etat["active"] is False
    assert "règles" in etat["message"]


def test_sans_cle_l_explication_reste_complete(monkeypatch):
    """C'est la promesse de conception : sans IA, l'utilisateur ne perd rien."""
    monkeypatch.delenv("ANALYZER_LLM_KEY", raising=False)
    entree = moteur.expliquer(communication())
    resultat = llm.reformuler(entree)
    assert resultat["source"] == "regles"
    assert resultat["explication_simple"] == entree["explication_simple"]
    assert resultat["faits_observes"] == entree["faits_observes"]


def test_une_panne_de_la_couche_ia_ne_bloque_pas(monkeypatch):
    """Adresse injoignable : le repli doit jouer, sans exception qui remonte."""
    monkeypatch.setenv("ANALYZER_LLM_KEY", "cle-de-test")
    monkeypatch.setenv("ANALYZER_LLM_URL", "http://127.0.0.1:9/injoignable")
    entree = moteur.expliquer(communication())
    resultat = llm.reformuler(entree)
    assert resultat["source"] == "regles"
    assert resultat["explication_simple"] == entree["explication_simple"]


def test_les_chiffres_inventes_font_rejeter_la_reponse():
    """Le contrôle qui protège du défaut le plus dangereux d'un modèle : inventer une valeur.

    On simule une réponse de modèle qui ajoute un débit jamais observé. Elle doit être
    écartée, parce qu'aucun chiffre ne doit apparaître dans l'explication finale s'il ne
    figurait pas dans les faits.
    """
    explication = moteur.expliquer(communication())
    explication["faits_observes"] = ["Port de destination = 443", "Protocole = TCP"]

    honnete = {"explication_simple": "Le port 443 est probablement utilisé par un service "
                                     "chiffré, ce qui reste une convention et non une preuve."}
    assert llm._reponse_utilisable(honnete, explication) is not None

    inventif = {"explication_simple": "Le port 443 transporte 46200 octets par seconde vers "
                                      "un service chiffré, ce qui est une convention."}
    assert llm._reponse_utilisable(inventif, explication) is None


def test_une_reponse_trop_courte_est_rejetee():
    """Une reformulation vide ou triviale n'apporte rien : on garde le texte des règles."""
    explication = moteur.expliquer(communication())
    assert llm._reponse_utilisable({"explication_simple": "ok"}, explication) is None
    assert llm._reponse_utilisable({}, explication) is None

"""Tests du moteur de détection (phase 4).

Deux propriétés portent tout le module, et ce sont elles que ces tests défendent :

    1. **Aucune règle isolée ne produit une alerte.** Une alerte naît d'un faisceau de
       trois indices de familles différentes convergents sur une même machine. Si un test
       laissait passer une alerte sur un seul indice, le module deviendrait un générateur
       de bruit — et un outil qui crie au loup cesse d'être lu.

    2. **Chaque détection nomme ses faux positifs.** C'est une exigence du sujet, et
       c'est aussi ce qui rend une détection utilisable : sans cette mention, un lecteur
       prend une forme pour une conclusion. Le test est direct — le champ doit être rempli
       et substantiel — parce que la propriété est simple et la vérifier ne coûte rien.

Le reste éprouve les seuils, l'absence de doublons, et la résistance aux données
inattendues.
"""

from __future__ import annotations

import pytest

from agent.detection import (
    NIVEAU_ALERTE,
    NIVEAU_HYPOTHESE,
    NIVEAU_OBSERVATION,
    SEUILS,
    Detecteur,
)

CHAMPS_OBLIGATOIRES = {"regle", "famille", "niveau", "titre", "faits_observes",
                       "explication", "confiance", "faux_positifs", "cible",
                       "debut", "dernier", "occurrences"}


def communication(source="192.168.1.5", cible="93.184.216.34", port_source=51000, port=443,
                  protocole="TCP", etat="fermée", debut="2026-10-05T10:00:00+00:00",
                  fin="2026-10-05T10:00:05+00:00", **remplacements):
    """Une communication complète, dont chaque test ne change que ce qui l'intéresse."""
    base = {
        "cle": f"{protocole}|{source}:{port_source}|{cible}:{port}",
        "protocole": protocole,
        "ip_a": source, "port_a": port_source,
        "ip_b": cible, "port_b": port,
        "initiateur": source,
        "etat": etat, "etat_certain": True, "note_etat": "",
        "debut": debut, "dernier_paquet": fin,
        "paquets_a_vers_b": 5, "paquets_b_vers_a": 4, "paquets_total": 9,
        "octets_a_vers_b": 900, "octets_b_vers_a": 4000, "octets_total": 4900,
    }
    base.update(remplacements)
    return base


def balayage(machine="192.168.1.5", cible="93.184.216.34", ports=20, etat="échec probable",
             debut="2026-10-05T10:00:00+00:00", fin="2026-10-05T10:00:20+00:00"):
    """Un balayage : la même machine contacte beaucoup de ports différents, très vite."""
    return [
        communication(source=machine, cible=cible, port=1000 + i, etat=etat,
                      debut=debut, fin=fin)
        for i in range(ports)
    ]


def repetition(machine="192.168.1.5", cible="93.184.216.34", port=443, nombre=12):
    """Des connexions répétées vers la même destination, à intervalle régulier."""
    return [
        communication(source=machine, cible=cible, port=port, port_source=51000 + i,
                      debut=f"2026-10-05T10:00:{i * 5:02d}+00:00",
                      fin=f"2026-10-05T10:00:{i * 5 + 1:02d}+00:00")
        for i in range(nombre)
    ]


def envoi_massif(machine="192.168.1.5", cible="93.184.216.34",
                 octets=SEUILS["volume_sortant_octets"] * 2):
    """Un envoi important vers l'extérieur, avec peu de retour."""
    return [communication(source=machine, cible=cible, port=443,
                          octets_a_vers_b=octets, octets_b_vers_a=100,
                          octets_total=octets + 100)]


# --------------------------------------------------------------------------- #
#  La structure et les faux positifs
# --------------------------------------------------------------------------- #
def toutes_les_regles():
    """Un jeu d'entrées qui déclenche chaque règle, y compris la plus difficile."""
    detecteur = Detecteur()
    detecteur.analyser([communication()])              # première vue des machines
    return detecteur.analyser(
        balayage()
        + repetition()
        + envoi_massif()
        + [communication(source="192.168.1.5", cible=f"93.184.216.{i}", port=443)
           for i in range(1, SEUILS["destinations_distinctes"] + 2)]
        + [communication(source="192.168.1.5", cible="8.8.8.8", port=53,
                         protocole="UDP", port_source=53000 + i)
           for i in range(SEUILS["dns_requetes"] + 2)]
        + [communication(source="142.250.75.14", cible="192.168.1.42", port=445,
                         port_source=52000)]
        + [communication(source=f"192.168.1.{90 + i}", cible="93.184.216.34")
           for i in range(3)]
    )


def test_toute_detection_a_la_structure_complete():
    """Chaque détection porte tout ce qu'il faut pour la juger, sans exception."""
    for detection in toutes_les_regles():
        assert set(detection.vers_dict()) == CHAMPS_OBLIGATOIRES, detection.regle
        # L'attribut s'appelle `faits`, la clé du dictionnaire `faits_observes` : c'est
        # volontaire — le vocabulaire exposé est plus explicite que le nom interne.
        assert detection.titre
        assert detection.faits
        assert detection.explication
        assert detection.confiance in ("faible", "moyenne", "haute")
        assert detection.niveau in (NIVEAU_OBSERVATION, NIVEAU_HYPOTHESE, NIVEAU_ALERTE)


def test_chaque_detection_nomme_ses_faux_positifs():
    """L'exigence du sujet, et la condition pour qu'une détection soit utilisable.

    Une détection qui ne dit pas ce qu'elle peut avoir de faux laisse croire à une
    conclusion. Le champ doit donc être non seulement présent, mais consistant.
    """
    for detection in toutes_les_regles():
        assert detection.faux_positifs, f"{detection.regle} ne nomme aucun faux positif"
        assert len(detection.faux_positifs) > 40, \
            f"{detection.regle} : faux positifs trop vagues"


def test_les_huit_regles_existent():
    """Aucune règle ne doit disparaître silencieusement au fil des modifications."""
    regles = {d.regle for d in toutes_les_regles()}
    attendues = {"scan_ports", "connexions_repetees", "echecs_repetes",
                 "service_sensible_entrant", "volume_sortant",
                 "multiplication_destinations", "dns_volume", "machine_inconnue"}
    assert attendues <= regles, f"règles absentes : {attendues - regles}"


# --------------------------------------------------------------------------- #
#  La règle centrale : pas d'alerte sur un indice isolé
# --------------------------------------------------------------------------- #
def test_un_seul_indice_ne_produit_jamais_une_alerte():
    """La promesse du module, éprouvée sur chacune des formes, une par une.

    Chacune se produit naturellement plusieurs fois par jour sur un réseau domestique.
    Si l'une d'elles suffisait à déclencher une alerte, l'outil crierait au loup en
    permanence et ne serait plus lu.
    """
    formes = {
        "balayage": balayage(),
        "répétition": repetition(),
        "envoi massif": envoi_massif(),
        "dispersion": [communication(cible=f"93.184.216.{i}", port=443)
                       for i in range(1, SEUILS["destinations_distinctes"] + 2)],
        "résolutions": [communication(cible="8.8.8.8", port=53, protocole="UDP",
                                      port_source=53000 + i)
                        for i in range(SEUILS["dns_requetes"] + 2)],
        "connexion entrante": [communication(source="142.250.75.14", cible="192.168.1.42",
                                             port=445, port_source=52000)],
    }
    for nom, lot in formes.items():
        detecteur = Detecteur()
        detecteur.analyser([communication()])
        detections = detecteur.analyser(lot)
        alertes = [d for d in detections if d.niveau == NIVEAU_ALERTE]
        assert not alertes, f"« {nom} » a produit une alerte à lui seul : {alertes}"


def test_trois_indices_convergents_produisent_une_alerte():
    """Trois familles différentes sur la même machine : là, oui."""
    detecteur = Detecteur()
    detecteur.analyser([communication()])
    # Trois règles portant une hypothèse, et non des observations : une alerte naît de
    # suppositions convergentes, pas de faits constatés. La dispersion, elle, est une
    # observation — le comportement normal d'un navigateur — et ne compte pas.
    detections = detecteur.analyser(balayage() + repetition() + envoi_massif())
    alertes = [d for d in detections if d.niveau == NIVEAU_ALERTE]
    assert alertes, "trois formes convergentes n'ont pas produit d'alerte"

    alerte = alertes[0]
    assert alerte.regle == "faisceau_indices"
    assert alerte.cible == "192.168.1.5"
    # L'alerte doit énumérer les indices qui la composent : c'est ce qui la rend
    # vérifiable, et ce qui distingue une alerte d'une intuition.
    assert len(alerte.faits) >= 4
    assert "convergent" in alerte.titre.lower()


def test_deux_indices_ne_suffisent_pas():
    """La limite exacte : deux formes ne font pas une alerte, trois oui."""
    detecteur = Detecteur()
    detecteur.analyser([communication()])
    detections = detecteur.analyser(balayage() + repetition())
    assert not [d for d in detections if d.niveau == NIVEAU_ALERTE]


def test_une_observation_ne_compte_pas_comme_un_indice():
    """Les observations décrivent des faits sans rien supposer.

    Les faire converger serait compter deux fois la même chose : « beaucoup de
    destinations » est le comportement normal d'un navigateur, pas un indice.
    """
    detecteur = Detecteur()
    detecteur.analyser([communication()])
    # Dispersion (observation) + résolutions (observation) + connexion entrante
    # (observation : le port est sensible mais c'est un fait) : que des observations.
    detections = detecteur.analyser(
        [communication(cible=f"93.184.216.{i}", port=443) for i in range(40)]
        + [communication(cible="8.8.8.8", port=53, protocole="UDP", port_source=53000 + i)
           for i in range(60)]
    )
    assert not [d for d in detections if d.niveau == NIVEAU_ALERTE]


def test_le_faisceau_ne_compte_pas_deux_fois_la_meme_famille():
    """Deux angles sur le même phénomène ne sont pas deux phénomènes.

    « Vingt ports contactés » et « vingt connexions répétées » décrivent la même
    observation. Les compter séparément gonflerait artificiellement le faisceau.
    """
    detecteur = Detecteur()
    detecteur.analyser([communication()])
    # Un balayage produit à la fois « scan_ports » et, sur le même couple, des échecs.
    detections = detecteur.analyser(balayage(ports=25))
    familles = {d.famille for d in detections}
    assert "balayage" in familles
    # Aucune alerte : les familles présentes ne suffisent pas à elles seules.
    assert not [d for d in detections if d.niveau == NIVEAU_ALERTE]


# --------------------------------------------------------------------------- #
#  Les seuils
# --------------------------------------------------------------------------- #
def test_le_seuil_de_balayage_est_respecte():
    """Un port de moins que le seuil ne déclenche rien : les seuils comptent vraiment."""
    detecteur = Detecteur()
    detecteur.analyser([communication()])
    sous_le_seuil = detecteur.analyser(balayage(ports=SEUILS["scan_ports_distincts"] - 1))
    assert not [d for d in sous_le_seuil if d.regle == "scan_ports"]

    detecteur = Detecteur()
    detecteur.analyser([communication()])
    au_seuil = detecteur.analyser(balayage(ports=SEUILS["scan_ports_distincts"]))
    assert [d for d in au_seuil if d.regle == "scan_ports"]


def test_un_envoi_interne_n_est_pas_signale():
    """Un gros transfert entre deux machines du réseau local n'est pas un envoi externe."""
    detecteur = Detecteur()
    detecteur.analyser([communication()])
    interne = [communication(source="192.168.1.5", cible="192.168.1.42",
                             octets_a_vers_b=999_000_000, octets_b_vers_a=10,
                             octets_total=999_000_010)]
    detections = detecteur.analyser(interne)
    assert not [d for d in detections if d.regle == "volume_sortant"]


def test_une_connexion_entrante_sur_port_ordinaire_n_est_pas_signalee():
    """Seuls les ports qui ouvrent quelque chose sur une machine sont signalés."""
    detecteur = Detecteur()
    detecteur.analyser([communication()])
    detections = detecteur.analyser([communication(source="142.250.75.14",
                                                   cible="192.168.1.42", port=443,
                                                   port_source=52000)])
    assert not [d for d in detections if d.regle == "service_sensible_entrant"]


def test_les_adresses_de_service_ne_sont_pas_des_appareils():
    """Une diffusion, une multidiffusion ou une adresse locale de lien n'est pas un appareil.

    Trouvé sur trafic réel : la première version annonçait « nouvel appareil » pour
    255.255.255.255, pour 0.0.0.0 et pour des adresses fe80:: — c'est-à-dire pour tout
    sauf des machines. Quatre faux appareils signalés au démarrage, et plus personne ne
    lit les détections.
    """
    detecteur = Detecteur()
    detecteur.analyser([communication()])
    detections = detecteur.analyser([
        communication(source="192.168.1.42", cible="93.184.216.34"),
        communication(source="255.255.255.255", cible="93.184.216.34"),
        communication(source="0.0.0.0", cible="93.184.216.34"),
        communication(source="169.254.13.7", cible="93.184.216.34"),
        communication(source="fe80::1", cible="93.184.216.34"),
    ])
    annoncees = {d.cible for d in detections if d.regle == "machine_inconnue"}
    assert "255.255.255.255" not in annoncees
    assert "0.0.0.0" not in annoncees
    assert "169.254.13.7" not in annoncees
    assert "fe80::1" not in annoncees
    # Une vraie machine du réseau, elle, doit bien être signalée.
    assert "192.168.1.42" in annoncees


def test_une_machine_locale_n_est_pas_nouvelle_au_premier_lot():
    """Sinon toutes les machines seraient « nouvelles » à chaque démarrage.

    Une détection qui se déclenche systématiquement au lancement n'apprend rien et
    sature l'affichage — c'est le premier piège d'un module de détection.
    """
    detecteur = Detecteur()
    premier = detecteur.analyser([communication(), communication(source="192.168.1.42",
                                                                cible="93.184.216.34")])
    assert not [d for d in premier if d.regle == "machine_inconnue"]

    # À partir du deuxième lot, une machine réellement nouvelle est signalée.
    second = detecteur.analyser([communication(source="192.168.1.77", cible="93.184.216.34")])
    signalees = [d for d in second if d.regle == "machine_inconnue"]
    assert signalees
    assert signalees[0].cible == "192.168.1.77"


# --------------------------------------------------------------------------- #
#  Le comportement dans le temps
# --------------------------------------------------------------------------- #
def test_une_detection_ne_se_repete_pas_a_chaque_lot():
    """Le tableau de bord ne doit pas se remplir de la même phrase à chaque lot."""
    detecteur = Detecteur()
    detecteur.analyser([communication()])
    detecteur.analyser(balayage())
    detecteur.analyser(balayage())
    detecteur.analyser(balayage())

    detections = detecteur.detections()
    balayages = [d for d in detections if d["regle"] == "scan_ports"]
    assert len(balayages) == 1, "la même détection a été enregistrée plusieurs fois"
    # Mais elle doit dire qu'on l'a revue : c'est une information utile.
    assert balayages[0]["occurrences"] >= 2


def test_le_comptage_par_niveau_est_juste():
    detecteur = Detecteur()
    detecteur.analyser([communication()])
    detecteur.analyser(balayage() + repetition() + envoi_massif())
    comptes = detecteur.compter()
    assert set(comptes) == {NIVEAU_OBSERVATION, NIVEAU_HYPOTHESE, NIVEAU_ALERTE}
    assert sum(comptes.values()) == len(detecteur.detections(limite=500))


def test_le_filtre_par_niveau_fonctionne():
    detecteur = Detecteur()
    detecteur.analyser([communication()])
    detecteur.analyser(balayage() + envoi_massif())
    for detection in detecteur.detections(niveau=NIVEAU_HYPOTHESE, limite=500):
        assert detection["niveau"] == NIVEAU_HYPOTHESE


# --------------------------------------------------------------------------- #
#  La robustesse
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("lot", [
    [],
    [{}],
    [{"protocole": "TCP"}],
    [{"protocole": "TCP", "ip_a": None, "ip_b": None, "port_a": None, "port_b": None}],
    [{"protocole": "UDP", "ip_a": "192.168.1.5", "ip_b": "8.8.8.8", "port_b": "pas un port"}],
    [{"protocole": "TCP", "ip_a": "192.168.1.5", "ip_b": "93.184.216.34", "port_b": 443,
      "debut": "date invalide", "dernier_paquet": "aussi invalide", "etat": "état inventé"}],
])
def test_aucune_entree_ne_provoque_d_erreur(lot):
    """Une communication malformée vient du réseau : elle ne doit pas arrêter la détection."""
    detecteur = Detecteur()
    detecteur.analyser(lot)
    # Un lot vide produit un résultat vide, pas une exception.
    for detection in detecteur.detections(limite=10):
        assert detection["regle"]


def test_les_detections_se_lisent_du_plus_recent_au_plus_ancien():
    detecteur = Detecteur()
    detecteur.analyser([communication()])
    detecteur.analyser(balayage(debut="2026-10-05T09:00:00+00:00",
                                fin="2026-10-05T09:00:10+00:00"))
    detecteur.analyser(envoi_massif())
    detections = detecteur.detections(limite=50)
    dates = [d["dernier"] for d in detections]
    assert dates == sorted(dates, reverse=True)

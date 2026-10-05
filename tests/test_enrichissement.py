"""Tests de l'enrichissement (phase 5).

Trois propriétés comptent, et aucune ne se voit à l'œil dans le code :

    1. **Aucune adresse privée ne part sur le réseau.** L'enrichir reviendrait à publier
       la topologie du réseau local chez deux services tiers. On ne se contente pas de
       vérifier que la fonction rend `None` : on vérifie qu'aucune requête HTTP n'a été
       tentée.
    2. **Sans clé, rien ne casse.** L'enrichissement est facultatif ; tout le reste de
       l'outil doit fonctionner exactement pareil.
    3. **Le rythme est tenu.** Une offre gratuite plafonne à quelques dizaines d'appels
       par minute ; les dépasser ferait répondre une erreur qu'on prendrait pour une
       panne. Le cache et le limiteur servent la même contrainte, et sont donc éprouvés
       ensemble.

Les appels réseau sont simulés : aucun test n'interroge réellement ipinfo.io ni
AbuseIPDB. Un test qui dépendrait d'un service tiers échouerait sans réseau, et
consommerait le quota à chaque exécution.
"""

from __future__ import annotations

import pytest

from backend import enrichment as module


class FauxTransport:
    """Remplace httpx.get : note les adresses demandées, et rend une réponse choisie.

    C'est le point du test : vérifier non seulement ce que la fonction rend, mais ce
    qu'elle a **demandé**. Une fonction qui rendrait `None` après avoir tout de même
    interrogé un service pour une adresse privée passerait un test naïf, et aurait déjà
    divulgué ce qu'il fallait protéger.
    """

    def __init__(self, reponse=None, erreur=None):
        self.appels: list[str] = []
        self.reponse = reponse or {}
        self.erreur = erreur

    def __call__(self, url, **options):
        self.appels.append(url)

        class Reponse:
            def __init__(self, donnees):
                self._donnees = donnees

            def raise_for_status(self):
                return None

            def json(self):
                return self._donnees

        if self.erreur:
            raise self.erreur
        if "ipinfo" in url:
            return Reponse({"country": "IE", "city": "Dublin", "org": "AS16509 Amazon.com",
                            "network": "93.184.216.0/24"})
        return Reponse({"data": {"abuseConfidenceScore": 0, "totalReports": 0,
                                 "usageType": "Data Center/Web Hosting/Transit"}})


@pytest.fixture
def transport(monkeypatch):
    faux = FauxTransport()
    monkeypatch.setattr("httpx.get", faux)
    return faux


# --------------------------------------------------------------------------- #
#  Ce qui ne doit jamais sortir
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("adresse", [
    "192.168.1.5",      # réseau domestique
    "10.0.0.1",         # réseau d'entreprise
    "172.16.4.9",       # autre bloc privé
    "127.0.0.1",        # boucle locale
    "fe80::1",          # adresse locale de lien
    "255.255.255.255",  # diffusion
    "0.0.0.0",          # indéfinie
    "pas une adresse",  # illisible
])
def test_aucune_adresse_locale_n_est_interrogee(adresse, transport):
    """La propriété la plus importante du module : rien de local ne part à l'extérieur.

    On vérifie l'absence de **toute requête**, et pas seulement le résultat : une
    fonction qui aurait interrogé le service avant de renoncer aurait déjà divulgué
    l'information.
    """
    moteur = module.Enrichissement(cle_ipinfo="cle", cle_abuseipdb="cle")
    assert moteur.enrichir(adresse) is None
    assert transport.appels == [], f"une requête est partie pour {adresse}"


def test_une_adresse_publique_est_bien_interrogee(transport):
    """Le pendant du test précédent : une adresse publique doit, elle, être enrichie.

    Sans ce test, une fonction qui refuserait tout passerait le test de confidentialité
    avec les honneurs — et ne servirait à rien.
    """
    moteur = module.Enrichissement(cle_ipinfo="cle", cle_abuseipdb="cle")
    resultat = moteur.enrichir("93.184.216.34")
    assert resultat["ville"] == "Dublin"
    assert resultat["organisation"] == "AS16509 Amazon.com"
    assert resultat["score_abus"] == 0
    assert len(transport.appels) == 2      # les deux fournisseurs, et pas un seul


# --------------------------------------------------------------------------- #
#  Facultatif, et jamais bloquant
# --------------------------------------------------------------------------- #
def test_sans_cle_rien_ne_se_passe(transport):
    """Sans clé configurée, aucune requête et aucune erreur : l'outil reste entier."""
    moteur = module.Enrichissement()
    assert moteur.disponible() is False
    assert moteur.enrichir("93.184.216.34") is None
    assert transport.appels == []
    assert "inactif" in moteur.etat()["message"]


def test_une_panne_du_fournisseur_ne_bloque_pas(monkeypatch):
    """Service injoignable : on rend une réponse vide, sans exception qui remonte."""
    monkeypatch.setattr("httpx.get", FauxTransport(erreur=RuntimeError("injoignable")))
    moteur = module.Enrichissement(cle_ipinfo="cle")
    resultat = moteur.enrichir("93.184.216.34")
    assert resultat is not None
    assert resultat.get("echecs")


def test_un_echec_n_est_pas_memorise(monkeypatch):
    """Un incident temporaire ne doit pas être mis en cache vingt-quatre heures.

    Sinon une panne de cinq secondes priverait l'interface de contexte pour la journée.
    """
    faux = FauxTransport(erreur=RuntimeError("panne passagère"))
    monkeypatch.setattr("httpx.get", faux)
    moteur = module.Enrichissement(cle_ipinfo="cle")
    moteur.enrichir("93.184.216.34")
    premier = len(faux.appels)

    transport_ok = FauxTransport()
    monkeypatch.setattr("httpx.get", transport_ok)
    resultat = moteur.enrichir("93.184.216.34")
    assert transport_ok.appels, "l'adresse aurait dû être redemandée après l'échec"
    assert resultat.get("ville") == "Dublin"
    assert premier > 0


def test_une_reponse_est_mise_en_cache(transport):
    """La même adresse ne doit pas être redemandée à chaque affichage."""
    moteur = module.Enrichissement(cle_ipinfo="cle")
    moteur.enrichir("93.184.216.34")
    appels_apres_premier = len(transport.appels)
    moteur.enrichir("93.184.216.34")
    assert len(transport.appels) == appels_apres_premier


# --------------------------------------------------------------------------- #
#  Le rythme
# --------------------------------------------------------------------------- #
def test_le_rythme_est_tenu(monkeypatch):
    """Au-delà du quota, on ne rend pas d'erreur : on dit qu'on attend.

    Dépasser le quota d'une offre gratuite ferait répondre une erreur que l'on prendrait
    pour une panne du service — et l'interface afficherait « service en panne » alors
    qu'elle est simplement allée trop vite.
    """
    monkeypatch.setattr("httpx.get", FauxTransport())
    moteur = module.Enrichissement(cle_ipinfo="cle")

    for i in range(module.APPELS_PAR_MINUTE + 5):
        moteur.enrichir(f"93.184.216.{i + 1}")

    assert len(moteur._appels) <= module.APPELS_PAR_MINUTE
    resultat = moteur.enrichir("8.8.8.8")
    assert resultat.get("en_attente") is True


def test_les_adresses_de_documentation_sont_refusees(transport):
    """Les plages réservées à la documentation ne sont pas routables : on les écarte.

    203.0.113.0/24 et 198.51.100.0/24 existent pour écrire des exemples ; aucune machine
    réelle ne les porte. Les interroger ferait consommer du quota pour rien, et le service
    répondrait « inconnue ». Les traiter comme locales est plus juste — et c'est ce que
    fait la bibliothèque standard, sur laquelle on s'appuie plutôt que de dresser une
    liste de plages à la main.
    """
    moteur = module.Enrichissement(cle_ipinfo="cle")
    assert moteur.enrichir("203.0.113.7") is None
    assert moteur.enrichir("198.51.100.9") is None
    assert transport.appels == []


# --------------------------------------------------------------------------- #
#  La phrase affichée
# --------------------------------------------------------------------------- #
def test_le_resume_dit_seulement_ce_qu_on_sait():
    """Aucune conclusion : des faits, et rien de plus."""
    assert "inactif" in module.Enrichissement.resume(None).lower()

    resume = module.Enrichissement.resume({
        "organisation": "AS16509 Amazon.com", "ville": "Dublin", "pays": "IE",
        "score_abus": 0, "signalements": 0})
    assert "Amazon" in resume
    assert "Dublin" in resume
    assert "aucun signalement" in resume
    # Le mot « sûr », « dangereux » ou « attaque » ne doit jamais apparaître : le module
    # rapporte ce qu'un tiers dit, il ne conclut pas.
    for mot in ("dangereux", "attaque", "sûr", "suspect"):
        assert mot not in resume.lower()


def test_un_score_eleve_est_rapporte_sans_jugement():
    resume = module.Enrichissement.resume({"score_abus": 87, "signalements": 42})
    assert "87/100" in resume
    assert "42" in resume
    assert "signalement" in resume

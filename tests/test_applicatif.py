"""Tests de la lecture TLS (SNI) et HTTP — Lot B.

CE QUI COMPTE ICI
-----------------
Ces deux lectures touchent à des données sensibles : une session chiffrée, et du HTTP en
clair qui peut porter un jeton. Deux propriétés sont donc testées autant que le contenu :

1. **On ne lit que ce qui est nécessaire.** L'en-tête `Authorization` n'est pas extrait,
   donc il ne peut pas être conservé. Le test le vérifie sur un message qui en contient un.
2. **Ce qui n'est pas là ne fait pas échouer l'analyse.** Un ClientHello malformé, un
   en-tête absent : le paquet reste analysé, et l'incident est noté.

Les objets sont fabriqués ici plutôt qu'avec Scapy : la construction d'un paquet TLS par
Scapy lève une erreur interne (`NameError: name 'HMAC' is not defined` dans `h_mac.py`), et
ce sont nos règles de lecture qu'il faut éprouver, pas la bibliothèque.
"""

from __future__ import annotations

from agent import parser


class FauxServeur:
    def __init__(self, nom):
        self.servername = nom


class FausseExtension:
    def __init__(self, noms):
        self.servernames = noms


class FauxClientHello:
    def __init__(self, version=0x0303, extensions=None):
        self.version = version
        self.ext = extensions if extensions is not None else []


class FauxPaquet:
    """Un paquet qui répond à `haslayer` et `[]` comme Scapy, sur une seule couche."""

    def __init__(self, couche, contenu):
        self.couche = couche
        self.contenu = contenu

    def haslayer(self, couche):
        if couche is self.couche:
            return True
        # Dans Scapy, `HTTPRequest` et `HTTPResponse` dérivent de `HTTP` : un paquet qui
        # porte l'une porte donc aussi l'autre. L'objet de test doit le refléter, sans quoi
        # il testerait un comportement qui n'existe pas.
        from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
        return couche is HTTP and issubclass(self.couche, (HTTPRequest, HTTPResponse))

    def __getitem__(self, couche):
        if couche is not self.couche:
            raise KeyError(couche)
        return self.contenu


def fiche_vide():
    return {"protocole": "TCP", "details": {}}


def lire_tls(contenu):
    from scapy.layers.tls.handshake import TLSClientHello
    fiche = fiche_vide()
    parser._applicatif_tls(FauxPaquet(TLSClientHello, contenu), fiche)
    return fiche["details"]


def lire_http(contenu, couche):
    fiche = fiche_vide()
    parser._applicatif_http(FauxPaquet(couche, contenu), fiche)
    return fiche["details"]


# --------------------------------------------------------------------------- #
#  TLS — le nom du serveur visé, et rien d'autre
# --------------------------------------------------------------------------- #
def test_le_sni_est_extrait_du_client_hello():
    """Le nom du serveur est la seule information lisible d'une session chiffrée."""
    details = lire_tls(FauxClientHello(
        version=0x0303,
        extensions=[FausseExtension([FauxServeur(b"github.com")])],
    ))
    assert details["tls_sni"] == "github.com"
    assert "tls_version" in details


def test_le_sni_est_trouve_meme_apres_d_autres_extensions():
    details = lire_tls(FauxClientHello(extensions=[
        FausseExtension(None),
        FausseExtension([]),
        FausseExtension([FauxServeur(b"api.telegram.org")]),
    ]))
    assert details["tls_sni"] == "api.telegram.org"


def test_un_client_hello_sans_nom_ne_produit_rien():
    """Toutes les sessions n'annoncent pas de nom : certaines visent une adresse."""
    details = lire_tls(FauxClientHello(extensions=[FausseExtension([])]))
    assert "tls_sni" not in details


def test_un_client_hello_malforme_n_interrompt_pas_l_analyse():
    class Cassant:
        version = 0x0303

        @property
        def ext(self):
            raise ValueError("extension illisible")

    details = lire_tls(Cassant())
    assert details["tls_illisible"] == "ValueError"


def test_aucun_octet_chiffre_n_est_conserve():
    """Ce qui suit le handshake n'est pas lu : il n'apparaît nulle part."""
    details = lire_tls(FauxClientHello(extensions=[FausseExtension([FauxServeur(b"a.com")])]))
    assert set(details) <= {"tls_sni", "tls_version", "tls_illisible"}


# --------------------------------------------------------------------------- #
#  HTTP — la requête, sans jamais toucher aux en-têtes sensibles
# --------------------------------------------------------------------------- #
def test_un_secret_dans_les_entetes_n_est_jamais_extrait():
    """La propriété la plus importante de cette lecture.

    Le message contient un en-tête `Authorization`. Il ne doit apparaître **nulle part**
    dans ce qui est retenu : ce n'est pas masqué après coup, ce n'est pas lu du tout.
    """
    from scapy.layers.http import HTTPRequest

    requete = HTTPRequest()
    requete.Method = b"GET"
    requete.Host = b"example.com"
    requete.Path = b"/index.html"
    requete.Authorization = b"Bearer SECRET-DE-TEST"

    details = lire_http(requete, HTTPRequest)
    assert details["http_methode"] == "GET"
    assert details["http_hote"] == "example.com"
    assert details["http_chemin"] == "/index.html"
    assert "SECRET-DE-TEST" not in str(details)
    assert not any("uthoriz" in cle for cle in details)


def test_un_cookie_n_est_jamais_extrait():
    from scapy.layers.http import HTTPRequest

    requete = HTTPRequest()
    requete.Method = b"GET"
    requete.Host = b"example.com"
    requete.Path = b"/"
    requete.Cookie = b"session=JETON-DE-SESSION"

    details = lire_http(requete, HTTPRequest)
    assert "JETON-DE-SESSION" not in str(details)
    assert not any("ookie" in cle for cle in details)


def test_le_code_de_reponse_est_extrait():
    from scapy.layers.http import HTTPResponse

    reponse = HTTPResponse()
    reponse.Status_Code = b"404"
    assert lire_http(reponse, HTTPResponse)["http_code"] == 404


def test_un_chemin_tres_long_est_borne():
    """Ce qui vient du réseau ne doit pas pouvoir faire grossir la base à volonté."""
    from scapy.layers.http import HTTPRequest

    requete = HTTPRequest()
    requete.Method = b"GET"
    requete.Host = b"example.com"
    requete.Path = b"/" + b"a" * 5000

    details = lire_http(requete, HTTPRequest)
    assert len(details["http_chemin"]) <= 200

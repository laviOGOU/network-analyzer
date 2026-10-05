"""Le sous-module « expliquer » : transformer des données en phrases compréhensibles.

Deux couches, dans cet ordre :

    rules.py   le moteur déterministe — des règles écrites, sur des faits observés.
               Il fonctionne toujours, sans réseau ni clé d'API, et rend toujours les
               mêmes phrases pour les mêmes entrées. C'est lui qui porte le projet.
    llm.py     la couche IA, facultative — elle reformule ce que les règles ont produit.
               Elle n'ajoute jamais d'information. Si elle est absente, mal configurée ou
               défaillante, le moteur de règles reste seul, et le résultat est identique :
               seule la formulation change.

L'ordre compte : l'IA vient après, jamais à la place. Un outil d'analyse réseau qui ne
saurait expliquer que quand un service externe répond serait inutilisable au pire moment.
"""

from .rules import explications, expliquer, expliquer_resume, services_connus

__all__ = ["expliquer", "explications", "expliquer_resume", "services_connus"]

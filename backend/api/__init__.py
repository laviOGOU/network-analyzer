"""Routes HTTP, regroupées par usage.

  ingestion.py — écriture : l'agent dépose ses lots (jeton obligatoire)
  paquets.py   — lecture : paquets, statistiques, sessions, état du service

Chaque route délègue au stockage. Aucune ne compte, ne trie ni ne filtre elle-même :
le jour où les données viendront de PostgreSQL, seules les fonctions du stockage
changeront.
"""

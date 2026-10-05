"""Backend : reçoit les paquets de l'agent, les conserve et les présente.

  config.py    — lecture des réglages et des secrets (aucun secret dans le code)
  models.py    — schémas Pydantic : le contrat avec l'agent
  storage.py   — conservation des paquets (mémoire en phase 1, Supabase en phase 5)
  securite.py  — jeton d'agent et limitation de débit
  dependances.py — ce que les routes reçoivent, pour qu'un test puisse le remplacer
  api/         — les routes, qui ne contiennent aucune règle métier
  main.py      — assemblage, pages, traitement des erreurs

Le backend ne capture rien et ne peut rien capturer : il est en ligne, donc hors du
réseau local. C'est la contrainte qui justifie l'existence de l'agent.
"""

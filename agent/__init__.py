"""Agent de capture local : capture, analyse, et transmission au backend.

Séparation des responsabilités :
  capture.py  — parler au réseau et au pilote (Npcap)
  parser.py   — transformer un paquet en fiche structurée
  sender.py   — transmettre, avec file d'attente et réessai
  main.py     — assembler le tout et dialoguer avec l'utilisateur

Les trois premiers modules ne s'appellent pas entre eux autrement que dans ce sens :
`main` connaît les trois, `capture` connaît `parser`, et `parser` ne connaît personne.
C'est ce qui permet de tester l'analyse sans réseau, et la capture sans backend.
"""

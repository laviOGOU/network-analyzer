# FlowScope en ligne — image de production.
#
# Railway (comme tout hebergeur de conteneurs) execute un PROCESSUS, la ou Vercel execute des
# fonctions sans etat. C'est la bonne forme pour cette application : elle garde un flux SSE
# ouvert, elle pilote des sessions de capture, et elle parle a Supabase en continu.
#
# PAS DE LIBPCAP DANS L'IMAGE, ET C'EST VOLONTAIRE : en ligne, l'application ne capture rien.
# C'est l'agent, chez l'utilisateur, qui capture sur son reseau et POUSSE les paquets ici.
# Installer les outils de capture ne servirait a rien et alourdirait l'image pour rien.
FROM python:3.11-slim

WORKDIR /app

# Les dependances d'abord : cette couche ne se reconstruit que si requirements.txt change.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY agent/ ./agent/
COPY web/ ./web/

# Railway impose son port par la variable PORT ; l'application, elle, lit ANALYZER_PORT.
# On fait le pont ici plutot que de modifier le code : FlowScope continue de fonctionner
# exactement pareil en local, sans une ligne de difference.
# L'APPLICATION LIT « ANALYZER_HOST », EN ANGLAIS. Une premiere version de ce fichier
# ecrivait « ANALYZER_HOTE » : la variable n'etait jamais lue, l'application reprenait son
# defaut (127.0.0.1) et n'ecoutait que sur elle-meme. Le conteneur tournait, Railway frappait
# a la porte, personne ne repondait - un 502 sans le moindre message d'erreur.
ENV ANALYZER_HOST=0.0.0.0 \
    ANALYZER_PORT=8080 \
    PYTHONUNBUFFERED=1

EXPOSE 8080

# `${PORT:-8080}` : le port de Railway s'il existe, 8080 sinon.
CMD ["sh", "-c", "ANALYZER_PORT=${PORT:-8080} python -m backend.main"]

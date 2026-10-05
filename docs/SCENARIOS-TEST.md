# Scénarios de test manuels — phase 1

Chaque scénario se lance depuis un terminal, pendant que l'agent capture. La colonne
« attendu » décrit ce que le tableau de bord doit montrer — pas ce qu'on espère, ce qu'on
vérifie.

> **Autorisation.** Ces commandes ne produisent que du trafic sortant normal, ou visent
> votre propre machine. Le scan de port (scénario 7) ne s'exécute que sur `127.0.0.1`,
> c'est-à-dire sur vous-même.

## Préparation

Deux terminaux. Dans le premier, le backend :

```
.venv\Scripts\python.exe -m backend.main
```

Dans le second, l'agent — notez le jeton affiché au démarrage du backend :

```
.venv\Scripts\python.exe agent\main.py --interface "Wi-Fi" --backend http://127.0.0.1:8000 --jeton <JETON>
```

Puis ouvrez `http://127.0.0.1:8000` dans un navigateur.

---

## 1. Résolution de nom — DNS

```
nslookup example.com
```

**Attendu dans le tableau :** au moins deux paquets UDP avec le port de destination `53`.
La colonne *Détail* porte `requête DNS · example.com` puis `réponse DNS · example.com`.

**Ce que ça prouve :** le parseur descend jusqu'à la couche applicative et lit un nom de
domaine sans stocker le contenu du message.

---

## 2. Écho réseau — ICMP

```
ping -n 4 1.1.1.1
```

**Attendu :** quatre paquets `ICMP` dans un sens (`demande d'écho (ping)`), quatre dans
l'autre (`réponse d'écho (ping)`). Les ports sont vides — ICMP n'en a pas.

**Ce que ça prouve :** l'absence de port est traitée comme une absence, pas comme une
erreur ni comme un zéro inventé.

---

## 3. Navigation en clair — HTTP

```
curl http://neverssl.com
```

**Attendu :** des paquets TCP vers le port `80`, sans TLS (le contenu n'est pas analysé :
seules les métadonnées sont conservées).

**À comparer avec :**

```
curl https://neverssl.com
```

**Attendu :** les mêmes paquets vers le port `443`.

**Ce que ça prouve :** l'analyseur observe la différence de port, et n'affirme jamais
« c'est du HTTP » — le port 80 est un indice, pas une preuve.

---

## 4. Table ARP — réseau local

```
arp -a
ping -n 1 192.168.1.1
```

**Attendu :** des paquets `ARP` avec l'opération `demande`, puis `réponse`. Les adresses
apparaissent dans les colonnes source/destination, et les adresses matérielles aussi.

**Ce que ça prouve :** ARP n'a pas d'en-tête IP ; les adresses sont lues dans ses propres
champs. Un parseur qui ne chercherait que dans l'en-tête IP afficherait `—`.

---

## 5. Double pile — IPv6

Ouvrez un site qui expose IPv6 (`https://www.google.com` par exemple).

**Attendu :** des lignes dont les adresses contiennent `:` (IPv6), et dont le *TTL*
affiche une valeur — elle vient du champ « hop limit », qui porte un autre nom en IPv6.

**Ce que ça prouve :** le traitement d'IPv6 n'est pas un ajout tardif : la version est
détectée, et le parseur sait que le même concept porte deux noms selon la version.

---

## 6. Charge utile inconnue

```
curl -s -o NUL https://example.com/longue-chaine-de-caracteres-pour-produire-du-volume
```

**Attendu :** des paquets TCP en `PSH, ACK` de plusieurs centaines d'octets. Aucun
paquet n'est marqué « analyse partielle ».

**Ce que ça prouve :** une charge utile volumineuse ou binaire ne perturbe pas la lecture
des en-têtes — le parseur ne tente pas de l'interpréter.

---

## 7. Scan de ports — sur votre propre machine uniquement

```
nmap -sS 127.0.0.1
```

> N'exécutez cette commande que sur `127.0.0.1`. Un scan dirigé vers une autre machine
> sans autorisation écrite est illégal.

**Attendu :** de nombreux paquets TCP avec l'indicateur `SYN` seul, vers des ports
différents, depuis la même source.

**Ce que ça prouve :** le matériau de la détection de la phase 4 est déjà présent dans les
données. En phase 1 on l'observe ; on ne conclut pas encore.

---

## 8. Backend injoignable — la panne la plus intéressante

Arrêtez le backend (`Ctrl+C` dans son terminal), laissez l'agent tourner, puis provoquez
du trafic.

**Attendu côté agent :** la ligne d'avancement continue d'augmenter en capturés, la file
d'attente se remplit, puis **abandons** apparaît. Aucune erreur fatale, l'agent continue.

Relancez le backend : les paquets suivants repartent normalement.

**Ce que ça prouve :** la capture ne dépend pas du backend. C'est la contrainte
d'architecture du projet — un serveur en ligne ne peut pas écouter un réseau local, donc
l'agent doit tenir même quand le serveur est absent.

---

## 9. Jeton refusé

Relancez l'agent avec un jeton volontairement faux :

```
.venv\Scripts\python.exe agent\main.py --interface "Wi-Fi" --backend http://127.0.0.1:8000 --jeton faux-jeton
```

**Attendu :** aucune donnée n'arrive dans le tableau de bord, et le compteur **échecs**
monte côté agent. Le backend répond `401`.

**Ce que ça prouve :** l'écriture est réellement protégée, et l'agent ne fait pas passer
un refus pour un succès — sinon les paquets disparaîtraient sans un mot.

---

## 10. Sans droits de capture

Si Npcap a été installé avec l'option « restreindre aux administrateurs », lancez l'agent
sans élévation.

**Attendu :** un message qui dit quoi faire — relancer en administrateur, ou réinstaller
Npcap en décochant l'option — et non une trace technique.

**Ce que ça prouve :** l'erreur la plus probable de l'installation est expliquée au lieu
d'être subie.

---

## Récapitulatif

| Scénario | Protocole | Ce qui est vérifié |
|---|---|---|
| 1 | DNS | lecture applicative sans conservation du contenu |
| 2 | ICMP | absence de port traitée comme telle |
| 3 | HTTP / HTTPS | interprétation prudente d'un numéro de port |
| 4 | ARP | champs propres au protocole |
| 5 | IPv6 | version détectée, champ au nom différent |
| 6 | TCP + charge utile | robustesse aux données binaires |
| 7 | TCP (scan) | matière première de la détection (phase 4) |
| 8 | — | la capture survit à la perte du backend |
| 9 | — | écriture protégée, échec non dissimulé |
| 10 | — | droit de capture expliqué |

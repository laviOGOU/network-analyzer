-- =============================================================================
--  Intelligent Network Packet Analyzer — schéma de base de données
--  PostgreSQL (Supabase) — schéma dédié « analyzer »
-- =============================================================================
--
--  POURQUOI CE FICHIER EXISTE
--  --------------------------
--  La phase 1 conservait tout en mémoire : un redémarrage effaçait l'historique. Ce
--  schéma donne une mémoire au projet — et il est écrit *après* avoir observé ce qu'on
--  manipule réellement, pas avant.
--
--  PRINCIPES TENUS PAR CE SCHÉMA
--  -----------------------------
--  1. Chaque table existe pour répondre à une question précise. Une table dont on ne
--     sait pas quelle question elle sert est une table qui va grossir sans raison.
--  2. Aucune charge utile applicative n'est stockée. Seules des métadonnées. Le contenu
--     d'un message privé n'a rien à faire dans une base partagée.
--  3. La lecture publique passe par le backend, jamais par la base. Le navigateur ne
--     reçoit aucune clé Supabase. La base refuse donc tout par défaut.
--  4. Une donnée incertaine est marquée incertaine. `flows.etat_certain` et
--     `explanations.confidence` existent pour que la nuance survive jusqu'à l'écran.
--
--  À EXÉCUTER
--  ----------
--    psql « $SUPABASE_DB_URL » -f sql/schema.sql
--  ou, dans l'éditeur SQL de Supabase, coller ce fichier entier.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS analyzer;

COMMENT ON SCHEMA analyzer IS
  'Objets de l''analyseur de paquets. Schéma dédié pour ne rien mélanger avec d''autres '
  'projets hébergés sur le même projet Supabase.';

-- =============================================================================
--  1. capture_sessions — « quand et où a-t-on observé ? »
-- =============================================================================
--  POURQUOI : sans elle, les communications et les paquets seraient un tas sans repère
--  temporel ni origine. C'est la table qui répond à « montre-moi ce qui s'est passé
--  mardi entre 14 h et 15 h », et qui permet de supprimer une capture entière en une
--  seule opération — ce qui compte quand il faut effacer des données.
--
--  Elle porte le nom de l'agent : plusieurs machines peuvent alimenter le même backend,
--  et confondre leurs données rendrait toute analyse fausse.
-- =============================================================================
CREATE TABLE IF NOT EXISTS analyzer.capture_sessions (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    agent           text        NOT NULL,          -- nom de la machine qui capture
    interface       text,                          -- « Wi-Fi », « Ethernet »… (facultatif)
    filtre          text,                          -- filtre BPF appliqué, vide = tout
    debut           timestamptz NOT NULL DEFAULT now(),
    dernier_paquet  timestamptz,
    -- Compteurs dénormalisés : ils évitent de compter des millions de lignes pour
    -- afficher une page de liste. Ils sont mis à jour par le backend à chaque lot.
    paquets_vus     bigint      NOT NULL DEFAULT 0,
    octets_vus      bigint      NOT NULL DEFAULT 0,
    CONSTRAINT sessions_nom_agent_non_vide CHECK (length(trim(agent)) BETWEEN 1 AND 120)
);

COMMENT ON TABLE analyzer.capture_sessions IS
  'Une ligne par lancement d''agent. Répond à « quand et où a-t-on observé ? » et permet '
  'de supprimer une capture entière (RGPD : effacement en une opération).';
COMMENT ON COLUMN analyzer.capture_sessions.filtre IS
  'Filtre BPF appliqué pendant la capture. Le noter évite de croire à une absence de '
  'trafic là où c''est le filtre qui l''a écarté.';

CREATE INDEX IF NOT EXISTS idx_sessions_debut
    ON analyzer.capture_sessions (debut DESC);

-- =============================================================================
--  2. flows — « qui a parlé à qui, et comment cela s'est-il terminé ? »
-- =============================================================================
--  POURQUOI : c'est la table centrale. Un paquet isolé ne dit presque rien ; une
--  communication dit qui a pris l'initiative, combien de données ont circulé dans chaque
--  sens, combien de temps cela a duré, et si la conversation s'est terminée proprement.
--
--  POURQUOI `cle` EST UNIQUE : l'agent revoit la même conversation évoluer et renvoie sa
--  version mise à jour à chaque lot. Sans contrainte d'unicité, la même conversation
--  existerait en dizaines de lignes et les statistiques seraient fausses. L'écriture se
--  fait donc en « upsert » sur cette clé.
--
--  POURQUOI `etat_certain` : une capture qui commence au milieu d'une conversation ne
--  permet pas de dire si elle s'est ouverte normalement. Sans ce champ, on afficherait
--  « établie » avec une assurance non fondée.
-- =============================================================================
CREATE TABLE IF NOT EXISTS analyzer.flows (
    id                  bigserial   PRIMARY KEY,
    session_id          uuid        NOT NULL REFERENCES analyzer.capture_sessions(id)
                                    ON DELETE CASCADE,
    cle                 text        NOT NULL,      -- clé normalisée, identique dans les 2 sens
    protocole           text        NOT NULL,
    -- `inet` plutôt que `text` : PostgreSQL valide l'adresse à l'écriture et sait la
    -- comparer par sous-réseau. Une adresse impossible ne peut pas entrer.
    ip_a                inet        NOT NULL,
    ip_b                inet        NOT NULL,
    port_a              integer     CHECK (port_a BETWEEN 0 AND 65535),
    port_b              integer     CHECK (port_b BETWEEN 0 AND 65535),
    initiateur          inet,                      -- qui a parlé le premier

    debut               timestamptz NOT NULL,
    dernier_paquet      timestamptz NOT NULL,
    termine_le          timestamptz,
    duree_secondes      numeric(10,3) NOT NULL DEFAULT 0,

    paquets_a_vers_b    integer     NOT NULL DEFAULT 0 CHECK (paquets_a_vers_b >= 0),
    paquets_b_vers_a    integer     NOT NULL DEFAULT 0 CHECK (paquets_b_vers_a >= 0),
    octets_a_vers_b     bigint      NOT NULL DEFAULT 0 CHECK (octets_a_vers_b >= 0),
    octets_b_vers_a     bigint      NOT NULL DEFAULT 0 CHECK (octets_b_vers_a >= 0),

    indicateurs         text,                      -- « SYN, ACK » : indicateurs TCP vus
    etat                text        NOT NULL DEFAULT 'inconnue',
    etat_certain        boolean     NOT NULL DEFAULT false,
    note_etat           text,                      -- ce qui manque pour être sûr

    -- Ce qu'on a observé de la capture : a-t-on vu le tout premier paquet ?
    vu_depuis_le_debut  boolean     NOT NULL DEFAULT false,

    UNIQUE (session_id, cle)
);

COMMENT ON TABLE analyzer.flows IS
  'Communications regroupées par clé normalisée. Répond à « qui a parlé à qui, combien, '
  'et comment cela s''est terminé ? ».';
COMMENT ON COLUMN analyzer.flows.cle IS
  'Clé triée des deux extrémités : A→B et B→A donnent la même valeur. Sans cette '
  'normalisation, une connexion compterait deux fois.';
COMMENT ON COLUMN analyzer.flows.etat_certain IS
  'Faux quand la capture a commencé après le début de la conversation : l''état est alors '
  'une déduction, et l''interface doit le présenter comme telle.';
COMMENT ON COLUMN analyzer.flows.note_etat IS
  'Phrase expliquant ce qui manque pour être certain — affichée telle quelle, jamais perdue.';

-- Index : les trois questions posées le plus souvent par le tableau de bord.
CREATE INDEX IF NOT EXISTS idx_flows_session    ON analyzer.flows (session_id);
CREATE INDEX IF NOT EXISTS idx_flows_recentes   ON analyzer.flows (dernier_paquet DESC);
CREATE INDEX IF NOT EXISTS idx_flows_etat       ON analyzer.flows (etat, etat_certain);
-- Recherche « qu'a fait cette machine ? », dans un sens ou dans l'autre.
CREATE INDEX IF NOT EXISTS idx_flows_ip_a       ON analyzer.flows (ip_a);
CREATE INDEX IF NOT EXISTS idx_flows_ip_b       ON analyzer.flows (ip_b);
-- Ports : sert au repérage des services fréquentés, et plus tard aux ports sensibles.
CREATE INDEX IF NOT EXISTS idx_flows_ports      ON analyzer.flows (port_b);

-- =============================================================================
--  3. packets — « que contenait cette communication ? »
-- =============================================================================
--  POURQUOI UNE LIMITE : stocker tous les paquets est possible techniquement et absurde
--  en pratique. Un foyer modeste produit facilement 2 à 5 millions de paquets par jour ;
--  à 300 octets de métadonnées par ligne, cela fait plus d'un gigaoctet quotidien, pour
--  une information que personne ne relit. On conserve donc :
--    — une ligne par paquet **jusqu'à un plafond par communication** (les premiers),
--    — plus les paquets qui portent un fait notable ;
--    — et le reste est résumé dans les compteurs de `flows`.
--
--  Le choix est documenté dans le README, et le plafond est configurable.
-- =============================================================================
CREATE TABLE IF NOT EXISTS analyzer.packets (
    id                  bigserial   PRIMARY KEY,
    flow_id             bigint      REFERENCES analyzer.flows(id) ON DELETE CASCADE,
    session_id          uuid        NOT NULL REFERENCES analyzer.capture_sessions(id)
                                    ON DELETE CASCADE,

    horodatage          timestamptz NOT NULL,
    taille              integer     CHECK (taille >= 0),
    taille_capturee     integer     CHECK (taille_capturee >= 0),

    protocole           text        NOT NULL DEFAULT 'inconnu',
    couches             text[],                    -- {Ether, IP, TCP} : ce que le paquet contient
    ip_source           inet,
    ip_destination      inet,
    mac_source          text,
    mac_destination     text,
    version_ip          smallint    CHECK (version_ip IN (4, 6)),
    port_source         integer     CHECK (port_source BETWEEN 0 AND 65535),
    port_destination    integer     CHECK (port_destination BETWEEN 0 AND 65535),
    flags_tcp           text,
    ttl                 smallint    CHECK (ttl BETWEEN 0 AND 255),

    -- Faits applicatifs dérivés : nom DNS demandé, type ICMP… Jamais de contenu.
    details             jsonb       NOT NULL DEFAULT '{}'::jsonb,

    analyse_partielle   boolean     NOT NULL DEFAULT false,
    motif_partiel       text,

    -- Un paquet sans communication rattachée est un cas normal (ARP, trame tronquée) ;
    -- il n'est pas refusé, mais il est repérable.
    CONSTRAINT packets_adresses_coherentes CHECK (
        ip_source IS NULL OR ip_destination IS NULL OR ip_source <> ip_destination
    )
);

COMMENT ON TABLE analyzer.packets IS
  'Métadonnées des paquets. Volontairement plafonnée : voir le commentaire en tête de '
  'table. Aucune charge utile applicative n''est stockée.';
COMMENT ON COLUMN analyzer.packets.details IS
  'Faits dérivés (nom DNS demandé, type ICMP, troncature). Jamais le contenu transporté.';
COMMENT ON COLUMN analyzer.packets.analyse_partielle IS
  'Vrai quand le paquet n''a pas pu être analysé entièrement. Il est conservé avec son '
  'motif : un paquet incompris est une information, pas un déchet.';

CREATE INDEX IF NOT EXISTS idx_packets_flow      ON analyzer.packets (flow_id);
CREATE INDEX IF NOT EXISTS idx_packets_session   ON analyzer.packets (session_id);
CREATE INDEX IF NOT EXISTS idx_packets_temps     ON analyzer.packets (horodatage DESC);
CREATE INDEX IF NOT EXISTS idx_packets_protocole ON analyzer.packets (protocole);
-- Index partiel : ne référence que les paquets mal analysés, qui sont rares. Un index
-- complet serait presque vide et n'apporterait rien.
CREATE INDEX IF NOT EXISTS idx_packets_partiels  ON analyzer.packets (horodatage DESC)
    WHERE analyse_partielle;
-- Recherche dans les faits applicatifs (nom de domaine demandé).
CREATE INDEX IF NOT EXISTS idx_packets_details   ON analyzer.packets USING gin (details);

-- =============================================================================
--  4. alerts — « qu'est-ce qui mérite un regard ? »
-- =============================================================================
--  POURQUOI TROIS NIVEAUX SÉPARÉS : confondre un fait, une hypothèse et un dépassement de
--  seuil est la faute la plus courante de ce genre d'outil. Un « scan de ports détecté »
--  présenté comme un fait alors qu'il s'agit d'une interprétation fait perdre toute
--  confiance dans l'outil. La colonne `niveau` impose la distinction :
--     observation : un fait chiffré, sans interprétation ;
--     hypothese   : une interprétation prudente, avec sa formulation prudente ;
--     alerte      : un seuil a été dépassé, et lequel.
--
--  POURQUOI `criteres` EN JSONB : les seuils changeront. Stocker les critères qui ont
--  déclenché au moment du déclenchement permet de comprendre plus tard pourquoi une
--  alerte est apparue — même si les seuils ont été modifiés depuis.
-- =============================================================================
CREATE TABLE IF NOT EXISTS analyzer.alerts (
    id              bigserial   PRIMARY KEY,
    session_id      uuid        NOT NULL REFERENCES analyzer.capture_sessions(id)
                                ON DELETE CASCADE,
    flow_id         bigint      REFERENCES analyzer.flows(id) ON DELETE SET NULL,

    niveau          text        NOT NULL
                                CHECK (niveau IN ('observation', 'hypothese', 'alerte')),
    severite        text        NOT NULL DEFAULT 'info'
                                CHECK (severite IN ('info', 'low', 'medium', 'high')),

    regle           text        NOT NULL,          -- nom de la règle déclenchée
    titre           text        NOT NULL,
    -- Faits vérifiables, tels qu'affichés : « 42 ports distincts en 6 secondes ».
    constat         text        NOT NULL,
    -- Formulation prudente. Le texte doit dire qu'un comportement inhabituel n'est pas
    -- une attaque : c'est une exigence de l'énoncé, rappelée ici pour ne pas l'oublier.
    interpretation  text,
    criteres        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    valeur_mesuree  numeric,
    seuil           numeric,

    ip_concernee    inet,
    debut           timestamptz NOT NULL DEFAULT now(),
    dernier_vu      timestamptz,
    occurrences     integer     NOT NULL DEFAULT 1 CHECK (occurrences >= 1),

    -- La règle compose la clé d'unicité ci-dessous. Sans cette contrainte, une détection
    -- renvoyée à chaque lot créerait une ligne de plus, et le tableau de bord afficherait
    -- cent fois la même phrase — le défaut le plus courant d'un module de détection, et
    -- celui que la phase 4 avait précisément évité en mémoire. Le schéma doit porter la
    -- même garantie, sans quoi elle disparaît au moment du passage en production.
    UNIQUE (session_id, regle, ip_concernee)
);

COMMENT ON TABLE analyzer.alerts IS
  'Observations, hypothèses et alertes — trois niveaux distincts, jamais confondus. Un '
  'comportement inhabituel n''est pas une attaque : le texte le dit.';
COMMENT ON COLUMN analyzer.alerts.niveau IS
  'observation = fait chiffré · hypothese = interprétation prudente · alerte = seuil '
  'dépassé. Les mélanger ferait passer une supposition pour une certitude.';
COMMENT ON COLUMN analyzer.alerts.criteres IS
  'Seuils et mesures qui ont déclenché, figés au moment du déclenchement : les modifier '
  'plus tard ne doit pas réécrire l''histoire.';

CREATE INDEX IF NOT EXISTS idx_alerts_session  ON analyzer.alerts (session_id);
CREATE INDEX IF NOT EXISTS idx_alerts_flow     ON analyzer.alerts (flow_id);
CREATE INDEX IF NOT EXISTS idx_alerts_recentes ON analyzer.alerts (debut DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_niveau   ON analyzer.alerts (niveau, severite);
CREATE INDEX IF NOT EXISTS idx_alerts_ip       ON analyzer.alerts (ip_concernee);

-- =============================================================================
--  5. ip_enrichments — « que sait-on de cette adresse ? » (cache)
-- =============================================================================
--  POURQUOI UN CACHE EN BASE, ALORS QUE L'AGENT A DÉJÀ LE SIEN : le cache mémoire de
--  l'agent disparaît à chaque redémarrage, et le backend ne peut pas interroger l'API
--  externe depuis l'agent. Un cache partagé évite de rappeler l'API pour une adresse
--  déjà connue — ce qui compte, les offres gratuites étant limitées en nombre d'appels.
--
--  POURQUOI `expire_le` : la géolocalisation et la réputation d'une adresse changent
--  (réattribution d'une plage, nouvelle activité malveillante). Une donnée éternellement
--  valide deviendrait fausse sans que personne ne s'en aperçoive.
--
--  POURQUOI `source` : les valeurs ne se mélangent pas. Un score d'AbuseIPDB n'a pas la
--  même échelle qu'un score d'ipinfo, et l'afficher sans sa provenance serait trompeur.
-- =============================================================================
CREATE TABLE IF NOT EXISTS analyzer.ip_enrichments (
    ip              inet        PRIMARY KEY,       -- une seule ligne par adresse
    source          text        NOT NULL,          -- ipinfo | abuseipdb
    donnees         jsonb       NOT NULL DEFAULT '{}'::jsonb,

    -- Extraits prêts à afficher, pour ne pas parcourir le JSON dans les gabarits.
    pays            text,
    organisation    text,                          -- opérateur ou société (ASN)
    asn             text,
    score_abus      smallint    CHECK (score_abus BETWEEN 0 AND 100),
    signale         boolean,

    obtenu_le       timestamptz NOT NULL DEFAULT now(),
    expire_le       timestamptz NOT NULL,
    -- Une erreur mémorisée évite de rappeler l'API en boucle quand elle est en panne.
    echec           text
);

COMMENT ON TABLE analyzer.ip_enrichments IS
  'Cache des réponses des API externes. Évite de rappeler l''API pour une adresse déjà '
  'connue, ce qui compte vu les quotas des offres gratuites.';
COMMENT ON COLUMN analyzer.ip_enrichments.expire_le IS
  'Géolocalisation et réputation vieillissent : une donnée sans date de péremption '
  'deviendrait fausse sans prévenir.';
COMMENT ON COLUMN analyzer.ip_enrichments.source IS
  'Provenance de la donnée. Deux sources n''ont pas la même échelle : les mélanger sans '
  'le dire serait trompeur.';

CREATE INDEX IF NOT EXISTS idx_enrichissements_expiration ON analyzer.ip_enrichments (expire_le);

-- Les adresses privées ne doivent JAMAIS être demandées à une API externe : elles ne
-- désignent rien à l'extérieur. La contrainte le rend impossible, au lieu de compter sur
-- la vigilance du code.
ALTER TABLE analyzer.ip_enrichments DROP CONSTRAINT IF EXISTS enrichissements_adresses_publiques;
ALTER TABLE analyzer.ip_enrichments ADD CONSTRAINT enrichissements_adresses_publiques
    CHECK (
        NOT (
            ip << inet '10.0.0.0/8'      OR ip << inet '172.16.0.0/12' OR
            ip << inet '192.168.0.0/16'  OR ip << inet '127.0.0.0/8'   OR
            ip << inet '169.254.0.0/16'  OR ip << inet '::1/128'       OR
            ip << inet 'fc00::/7'        OR ip << inet 'fe80::/10'
        )
    );

COMMENT ON CONSTRAINT enrichissements_adresses_publiques ON analyzer.ip_enrichments IS
  'Interdit d''enrichir une adresse privée : elle ne désigne rien à l''extérieur, et '
  'l''envoyer serait une fuite inutile. La base refuse, plutôt que d''espérer que le '
  'code s''en souvienne.';

-- =============================================================================
--  6. explanations — « qu'est-ce que cela veut dire ? »
-- =============================================================================
--  POURQUOI CETTE TABLE EST DOUBLE : l'énoncé impose un moteur déterministe comme
--  colonne vertébrale, et une couche IA facultative qui ne fait que reformuler. Les deux
--  produisent des textes qui ne doivent jamais être confondus : la colonne `source` les
--  sépare, et l'interface les présente différemment.
--
--  POURQUOI LA STRUCTURE FIXE : une explication est découpée en cinq parties —
--  titre, faits observés, interprétation, confiance, texte simple. Cette structure oblige
--  à séparer ce qui est vérifié de ce qui est déduit. C'est précisément l'exigence de
--  l'énoncé : « ne jamais présenter une hypothèse comme une certitude ».
-- =============================================================================
CREATE TABLE IF NOT EXISTS analyzer.explanations (
    id                  bigserial   PRIMARY KEY,
    flow_id             bigint      REFERENCES analyzer.flows(id) ON DELETE CASCADE,
    alert_id            bigint      REFERENCES analyzer.alerts(id) ON DELETE CASCADE,

    source              text        NOT NULL DEFAULT 'regles'
                                    CHECK (source IN ('regles', 'ia')),

    titre               text        NOT NULL,
    -- Liste de faits tirés des données : « Port de destination = 443 ». En tableau, et
    -- non en texte libre, pour que l'interface les affiche comme des faits et non comme
    -- un paragraphe où tout se mélange.
    faits_observes      jsonb       NOT NULL DEFAULT '[]'::jsonb,
    interpretation      text,
    confiance           text        NOT NULL DEFAULT 'faible'
                                    CHECK (confiance IN ('faible', 'moyenne', 'haute')),
    explication_simple  text        NOT NULL,

    -- Traçabilité : quelle règle a produit ce texte, et avec quelles données.
    regle               text,
    cree_le             timestamptz NOT NULL DEFAULT now(),

    -- Une explication doit se rattacher à quelque chose. Sans cette contrainte, on
    -- trouverait des explications orphelines, impossibles à vérifier.
    CONSTRAINT explication_rattachee CHECK (flow_id IS NOT NULL OR alert_id IS NOT NULL)
);

COMMENT ON TABLE analyzer.explanations IS
  'Explications structurées : titre, faits observés, interprétation, confiance, texte '
  'simple. La séparation entre les faits et l''interprétation est la raison d''être de '
  'cette table.';
COMMENT ON COLUMN analyzer.explanations.source IS
  '« regles » = moteur déterministe (toujours présent) · « ia » = reformulation par un '
  'modèle. Les deux ne doivent jamais être présentés de la même façon.';
COMMENT ON COLUMN analyzer.explanations.confiance IS
  'Haute : le fait est directement observé. Faible : c''est une hypothèse. Ce champ '
  'n''est pas décoratif, il doit être affiché.';
COMMENT ON COLUMN analyzer.explanations.faits_observes IS
  'Faits vérifiables extraits des données, chacun sous forme de chaîne. En base et non '
  'dans le code, pour que l''explication reste vérifiable après coup.';

CREATE INDEX IF NOT EXISTS idx_explications_flow  ON analyzer.explanations (flow_id);
CREATE INDEX IF NOT EXISTS idx_explications_alert ON analyzer.explanations (alert_id);
CREATE INDEX IF NOT EXISTS idx_explications_source ON analyzer.explanations (source);

-- =============================================================================
--  7. Sécurité : le refus par défaut
-- =============================================================================
--  POURQUOI CE CHOIX, ET PAS UNE POLITIQUE DE LECTURE PUBLIQUE
--  ---------------------------------------------------------
--  Le tableau de bord est public, mais il ne parle pas à Supabase : il interroge le
--  backend, qui interroge Supabase avec la clé `service_role`. Le navigateur ne reçoit
--  aucune clé Supabase.
--
--  Activer la sécurité au niveau des lignes **sans créer de politique** signifie :
--  personne n'a accès, sauf la clé `service_role`, qui contourne ces règles par
--  conception. C'est le comportement voulu : la seule voie d'accès aux données est le
--  backend, où le jeton d'agent, la limitation de débit et la validation s'appliquent.
--
--  Une politique de lecture publique serait plus permissive que nécessaire : elle
--  permettrait à quiconque possédant la clé anonyme de lire directement la base, en
--  contournant tout ce que le backend vérifie.
-- =============================================================================
ALTER TABLE analyzer.capture_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE analyzer.flows            ENABLE ROW LEVEL SECURITY;
ALTER TABLE analyzer.packets          ENABLE ROW LEVEL SECURITY;
ALTER TABLE analyzer.alerts           ENABLE ROW LEVEL SECURITY;
ALTER TABLE analyzer.ip_enrichments   ENABLE ROW LEVEL SECURITY;
ALTER TABLE analyzer.explanations     ENABLE ROW LEVEL SECURITY;

-- Retrait des droits implicites : sans cela, un rôle disposant de GRANT hérités pourrait
-- lire malgré les politiques.
--
-- POURQUOI CES INSTRUCTIONS SONT CONDITIONNELLES
-- ----------------------------------------------
-- `anon`, `authenticated` et `service_role` sont des rôles créés par Supabase. Sur un
-- PostgreSQL ordinaire — celui d'un poste de travail, utilisé pour vérifier ce schéma
-- avant de le déployer — ils n'existent pas, et le script échouait sur
-- « ERROR: role "anon" does not exist ».
--
-- Les traiter comme facultatifs permet d'exécuter exactement le même fichier dans les
-- deux environnements : c'est ce qui a permis d'essayer ce schéma pour de vrai avant de
-- le confier à Supabase.
DO $$
DECLARE
    role_cible text;
BEGIN
    FOREACH role_cible IN ARRAY ARRAY['anon', 'authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_cible) THEN
            EXECUTE format('REVOKE ALL ON ALL TABLES    IN SCHEMA analyzer FROM %I', role_cible);
            EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA analyzer FROM %I', role_cible);
            EXECUTE format('REVOKE ALL ON SCHEMA analyzer FROM %I', role_cible);
            RAISE NOTICE 'Droits retirés au rôle Supabase « % »', role_cible;
        END IF;
    END LOOP;

    -- Le backend travaille avec la clé de service : il lui faut des droits explicites.
    -- La clé de service contourne les politiques, pas les privilèges.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        EXECUTE 'GRANT USAGE ON SCHEMA analyzer TO service_role';
        EXECUTE 'GRANT ALL ON ALL TABLES    IN SCHEMA analyzer TO service_role';
        EXECUTE 'GRANT ALL ON ALL SEQUENCES IN SCHEMA analyzer TO service_role';
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA analyzer GRANT ALL ON TABLES TO service_role';
        RAISE NOTICE 'Droits accordés au rôle Supabase « service_role »';
    ELSE
        RAISE NOTICE 'Rôles Supabase absents : schéma créé pour PostgreSQL seul.';
    END IF;
END $$;

-- =============================================================================
--  8. Conservation — trente jours, décision explicite
-- =============================================================================
--  Le tableau de bord est public : les données ne doivent pas s'accumuler indéfiniment.
--  Trente jours couvrent largement le besoin d'un exercice, et limitent l'exposition.
--
--  Deux façons d'appliquer la règle :
--    1. manuellement :  SELECT analyzer.purger(30);
--    2. automatiquement, si l'extension pg_cron est disponible sur le projet :
--         SELECT cron.schedule('purge-analyzer', '0 4 * * *',
--                              $$SELECT analyzer.purger(30)$$);
--
--  La fonction supprime les sessions anciennes ; les communications et les paquets
--  suivent par cascade (ON DELETE CASCADE). C'est la raison pour laquelle les clés
--  étrangères ont été déclarées ainsi : effacer une capture doit tout effacer.
-- =============================================================================
CREATE OR REPLACE FUNCTION analyzer.purger(jours integer DEFAULT 30)
RETURNS TABLE (sessions_supprimees bigint, lignes_restantes bigint)
LANGUAGE plpgsql
AS $$
DECLARE
    supprimees bigint;
BEGIN
    IF jours IS NULL OR jours < 1 THEN
        RAISE EXCEPTION 'Le nombre de jours doit être au moins 1 (reçu : %)', jours;
    END IF;

    WITH effacees AS (
        DELETE FROM analyzer.capture_sessions
        WHERE debut < now() - make_interval(days => jours)
        RETURNING 1
    )
    SELECT count(*) INTO supprimees FROM effacees;

    RETURN QUERY
        SELECT supprimees, (SELECT count(*) FROM analyzer.capture_sessions);
END;
$$;

COMMENT ON FUNCTION analyzer.purger(integer) IS
  'Supprime les captures de plus de N jours (30 par défaut). Les communications, paquets, '
  'alertes et explications suivent par cascade.';

-- =============================================================================
--  9. Vue de lecture — ce que le tableau de bord affiche
-- =============================================================================
--  POURQUOI UNE VUE : les chiffres de la page d'accueil demandent trois agrégations. Les
--  écrire dans le backend les rendrait difficiles à relire et à faire évoluer. Ici, la
--  question est écrite une fois, en SQL, et lisible par quiconque connaît le langage.
-- =============================================================================
CREATE OR REPLACE VIEW analyzer.resume_sessions AS
SELECT
    s.id,
    s.agent,
    s.debut,
    s.dernier_paquet,
    count(DISTINCT f.id)                                      AS communications,
    count(DISTINCT f.id) FILTER (WHERE NOT f.etat_certain)     AS communications_incertaines,
    count(DISTINCT f.id) FILTER (WHERE f.etat = 'échec probable') AS echecs_probables,
    coalesce(sum(f.octets_a_vers_b + f.octets_b_vers_a), 0)    AS octets_total,
    (SELECT count(*) FROM analyzer.alerts a WHERE a.session_id = s.id) AS alertes
FROM analyzer.capture_sessions s
LEFT JOIN analyzer.flows f ON f.session_id = s.id
GROUP BY s.id, s.agent, s.debut, s.dernier_paquet
ORDER BY s.debut DESC;

COMMENT ON VIEW analyzer.resume_sessions IS
  'Résumé par session : communications, dont incertaines, échecs probables, volume, '
  'alertes. C''est la vue du tableau de bord, pas une table.';

-- =============================================================================
--  Fin. Prochaine étape : alimenter ces tables depuis le backend (phase 5).
--  En attendant, la phase 2 valide le modèle de données et les communications ; la
--  conservation en mémoire permet de tout vérifier sans dépendre du réseau.
-- =============================================================================

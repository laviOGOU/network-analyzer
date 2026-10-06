CREATE SCHEMA IF NOT EXISTS analyzer;
COMMENT ON SCHEMA analyzer IS
  'Objets de l''analyseur de paquets. Schéma dédié pour ne rien mélanger avec d''autres '
  'projets hébergés sur le même projet Supabase.';
CREATE TABLE IF NOT EXISTS analyzer.capture_sessions (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    agent           text        NOT NULL,          -- nom de la machine qui capture
    interface       text,                          -- « Wi-Fi », « Ethernet »… (facultatif)
    filtre          text,                          -- filtre BPF appliqué, vide = tout
    debut           timestamptz NOT NULL DEFAULT now(),
    dernier_paquet  timestamptz,
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
CREATE TABLE IF NOT EXISTS analyzer.flows (
    id                  bigserial   PRIMARY KEY,
    session_id          uuid        NOT NULL REFERENCES analyzer.capture_sessions(id)
                                    ON DELETE CASCADE,
    cle                 text        NOT NULL,      -- clé normalisée, identique dans les 2 sens
    protocole           text        NOT NULL,
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
CREATE INDEX IF NOT EXISTS idx_flows_session    ON analyzer.flows (session_id);
CREATE INDEX IF NOT EXISTS idx_flows_recentes   ON analyzer.flows (dernier_paquet DESC);
CREATE INDEX IF NOT EXISTS idx_flows_etat       ON analyzer.flows (etat, etat_certain);
CREATE INDEX IF NOT EXISTS idx_flows_ip_a       ON analyzer.flows (ip_a);
CREATE INDEX IF NOT EXISTS idx_flows_ip_b       ON analyzer.flows (ip_b);
CREATE INDEX IF NOT EXISTS idx_flows_ports      ON analyzer.flows (port_b);
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
    details             jsonb       NOT NULL DEFAULT '{}'::jsonb,
    analyse_partielle   boolean     NOT NULL DEFAULT false,
    motif_partiel       text,
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
CREATE INDEX IF NOT EXISTS idx_packets_partiels  ON analyzer.packets (horodatage DESC)
    WHERE analyse_partielle;
CREATE INDEX IF NOT EXISTS idx_packets_details   ON analyzer.packets USING gin (details);
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
    constat         text        NOT NULL,
    interpretation  text,
    criteres        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    valeur_mesuree  numeric,
    seuil           numeric,
    ip_concernee    inet,
    debut           timestamptz NOT NULL DEFAULT now(),
    dernier_vu      timestamptz,
    occurrences     integer     NOT NULL DEFAULT 1 CHECK (occurrences >= 1),
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
CREATE TABLE IF NOT EXISTS analyzer.ip_enrichments (
    ip              inet        PRIMARY KEY,       -- une seule ligne par adresse
    source          text        NOT NULL,          -- ipinfo | abuseipdb
    donnees         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    pays            text,
    organisation    text,                          -- opérateur ou société (ASN)
    asn             text,
    score_abus      smallint    CHECK (score_abus BETWEEN 0 AND 100),
    signale         boolean,
    obtenu_le       timestamptz NOT NULL DEFAULT now(),
    expire_le       timestamptz NOT NULL,
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
CREATE TABLE IF NOT EXISTS analyzer.explanations (
    id                  bigserial   PRIMARY KEY,
    flow_id             bigint      REFERENCES analyzer.flows(id) ON DELETE CASCADE,
    alert_id            bigint      REFERENCES analyzer.alerts(id) ON DELETE CASCADE,
    source              text        NOT NULL DEFAULT 'regles'
                                    CHECK (source IN ('regles', 'ia')),
    titre               text        NOT NULL,
    faits_observes      jsonb       NOT NULL DEFAULT '[]'::jsonb,
    interpretation      text,
    confiance           text        NOT NULL DEFAULT 'faible'
                                    CHECK (confiance IN ('faible', 'moyenne', 'haute')),
    explication_simple  text        NOT NULL,
    regle               text,
    cree_le             timestamptz NOT NULL DEFAULT now(),
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
ALTER TABLE analyzer.capture_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE analyzer.flows            ENABLE ROW LEVEL SECURITY;
ALTER TABLE analyzer.packets          ENABLE ROW LEVEL SECURITY;
ALTER TABLE analyzer.alerts           ENABLE ROW LEVEL SECURITY;
ALTER TABLE analyzer.ip_enrichments   ENABLE ROW LEVEL SECURITY;
ALTER TABLE analyzer.explanations     ENABLE ROW LEVEL SECURITY;
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

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
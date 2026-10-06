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

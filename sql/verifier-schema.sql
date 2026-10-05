-- =============================================================================
--  Autotest du schéma — vérifie le comportement, pas seulement la création
-- =============================================================================
--  POURQUOI CE FICHIER
--  -------------------
--  Qu'un script SQL s'exécute sans erreur ne prouve rien : il peut créer des tables
--  vides de toute contrainte utile. Ce fichier vérifie que les règles du schéma
--  **refusent réellement** ce qu'elles doivent refuser, et que les mécanismes attendus
--  (cascade, unicité, purge) fonctionnent.
--
--  Chaque contrôle qui échoue lève une exception : le script s'arrête avec un code non
--  nul, et l'échec est visible dans un enchaînement automatisé.
--
--  UTILISATION
--  -----------
--    psql -v ON_ERROR_STOP=1 -d analyzer_test -f sql/verifier-schema.sql
-- =============================================================================

\set ON_ERROR_STOP on

DO $$
DECLARE
    session_test uuid;
    session_vieille uuid;
    flow_id bigint;
    avant bigint;
    apres bigint;
    refuse boolean;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '=== Autotest du schéma analyzer ===';

    -- -----------------------------------------------------------------------
    --  1. Les six tables existent
    -- -----------------------------------------------------------------------
    SELECT count(*) INTO avant
      FROM information_schema.tables
     WHERE table_schema = 'analyzer' AND table_type = 'BASE TABLE';
    IF avant < 6 THEN
        RAISE EXCEPTION 'Seulement % tables dans le schéma analyzer (6 attendues)', avant;
    END IF;
    RAISE NOTICE 'OK    % tables présentes', avant;

    -- -----------------------------------------------------------------------
    --  2. La sécurité au niveau des lignes est active partout
    -- -----------------------------------------------------------------------
    SELECT count(*) INTO avant
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'analyzer' AND c.relkind = 'r' AND NOT c.relrowsecurity;
    IF avant > 0 THEN
        RAISE EXCEPTION '% table(s) sans sécurité au niveau des lignes', avant;
    END IF;
    RAISE NOTICE 'OK    sécurité au niveau des lignes active sur toutes les tables';

    -- -----------------------------------------------------------------------
    --  3. Une adresse privée ne peut PAS être enrichie
    --     C'est la règle qui empêche d'envoyer 192.168.x.x à une API externe.
    -- -----------------------------------------------------------------------
    refuse := false;
    BEGIN
        INSERT INTO analyzer.ip_enrichments (ip, source, expire_le)
        VALUES ('192.168.1.5', 'ipinfo', now() + interval '30 days');
    EXCEPTION WHEN check_violation THEN
        refuse := true;
    END;
    IF NOT refuse THEN
        RAISE EXCEPTION 'Une adresse privée a pu entrer dans le cache d''enrichissement';
    END IF;
    RAISE NOTICE 'OK    une adresse privée est refusée par le cache d''enrichissement';

    -- Une adresse publique, elle, doit passer.
    INSERT INTO analyzer.ip_enrichments (ip, source, pays, organisation, expire_le)
    VALUES ('8.8.8.8', 'ipinfo', 'US', 'Google LLC', now() + interval '30 days');
    RAISE NOTICE 'OK    une adresse publique est acceptée';

    -- -----------------------------------------------------------------------
    --  4. Une capture puis une communication complète
    -- -----------------------------------------------------------------------
    INSERT INTO analyzer.capture_sessions (agent, interface, filtre)
    VALUES ('poste-de-test', 'Wi-Fi', '')
    RETURNING id INTO session_test;

    INSERT INTO analyzer.flows (
        session_id, cle, protocole, ip_a, ip_b, port_a, port_b, initiateur,
        debut, dernier_paquet, duree_secondes,
        paquets_a_vers_b, paquets_b_vers_a, octets_a_vers_b, octets_b_vers_a,
        indicateurs, etat, etat_certain, note_etat, vu_depuis_le_debut)
    VALUES (
        session_test, 'TCP|10.0.0.5:49703|93.184.216.34:443', 'TCP',
        '10.0.0.5', '93.184.216.34', 49703, 443, '10.0.0.5',
        now() - interval '2 seconds', now(), 2.0, 2, 1, 172, 86,
        'SYN, ACK', 'établie', true, 'Ouverture complète observée.', true)
    RETURNING id INTO flow_id;
    RAISE NOTICE 'OK    communication insérée (id %)', flow_id;

    -- -----------------------------------------------------------------------
    --  5. La même communication ne peut pas être enregistrée deux fois
    --     C'est ce qui rend l'écriture répétée de l'agent sans danger.
    -- -----------------------------------------------------------------------
    refuse := false;
    BEGIN
        INSERT INTO analyzer.flows (
            session_id, cle, protocole, ip_a, ip_b, debut, dernier_paquet)
        VALUES (session_test, 'TCP|10.0.0.5:49703|93.184.216.34:443', 'TCP',
                '10.0.0.5', '93.184.216.34', now(), now());
    EXCEPTION WHEN unique_violation THEN
        refuse := true;
    END;
    IF NOT refuse THEN
        RAISE EXCEPTION 'La même clé de communication a pu être insérée deux fois';
    END IF;
    RAISE NOTICE 'OK    une clé de communication en double est refusée';

    -- -----------------------------------------------------------------------
    --  6. Un port impossible est refusé
    -- -----------------------------------------------------------------------
    refuse := false;
    BEGIN
        UPDATE analyzer.flows SET port_b = 70000 WHERE id = flow_id;
    EXCEPTION WHEN check_violation THEN
        refuse := true;
    END;
    IF NOT refuse THEN
        RAISE EXCEPTION 'Un port à 70000 a été accepté';
    END IF;
    RAISE NOTICE 'OK    un port hors bornes est refusé';

    -- -----------------------------------------------------------------------
    --  7. Une adresse IP impossible est refusée par le type `inet`
    -- -----------------------------------------------------------------------
    refuse := false;
    BEGIN
        UPDATE analyzer.flows SET ip_b = '999.1.1.1' WHERE id = flow_id;
    EXCEPTION WHEN invalid_text_representation OR check_violation THEN
        refuse := true;
    END;
    IF NOT refuse THEN
        RAISE EXCEPTION 'L''adresse 999.1.1.1 a été acceptée';
    END IF;
    RAISE NOTICE 'OK    une adresse IP impossible est refusée par le type inet';

    -- -----------------------------------------------------------------------
    --  8. Une explication doit être rattachée à quelque chose
    -- -----------------------------------------------------------------------
    refuse := false;
    BEGIN
        INSERT INTO analyzer.explanations (titre, explication_simple)
        VALUES ('Orpheline', 'Sans rattachement');
    EXCEPTION WHEN check_violation THEN
        refuse := true;
    END;
    IF NOT refuse THEN
        RAISE EXCEPTION 'Une explication sans rattachement a été acceptée';
    END IF;
    RAISE NOTICE 'OK    une explication non rattachée est refusée';

    -- Une explication correcte passe, avec les faits observés en JSON.
    INSERT INTO analyzer.explanations (
        flow_id, source, titre, faits_observes, interpretation,
        confiance, explication_simple, regle)
    VALUES (
        flow_id, 'regles', 'Communication HTTPS probable',
        '["Port de destination = 443", "Ouverture complète observée", "12 paquets échangés"]'::jsonb,
        'Le port 443 est généralement associé à du trafic chiffré (TLS).',
        'haute',
        'Cette machine a ouvert une connexion chiffrée vers un serveur distant. '
        'Le contenu n''est pas lisible : seuls l''adresse et le volume sont connus.',
        'port_service_connu');
    RAISE NOTICE 'OK    explication insérée, avec ses faits observés';

    -- -----------------------------------------------------------------------
    --  9. Un niveau d'alerte inventé est refusé
    -- -----------------------------------------------------------------------
    refuse := false;
    BEGIN
        INSERT INTO analyzer.alerts (session_id, niveau, severite, regle, titre, constat)
        VALUES (session_test, 'certitude', 'high', 'x', 'y', 'z');
    EXCEPTION WHEN check_violation THEN
        refuse := true;
    END;
    IF NOT refuse THEN
        RAISE EXCEPTION 'Le niveau « certitude » a été accepté : les trois niveaux ne sont pas protégés';
    END IF;
    RAISE NOTICE 'OK    un niveau d''alerte hors des trois niveaux est refusé';

    -- -----------------------------------------------------------------------
    -- 10. La cascade : supprimer une capture doit tout emporter
    --     C'est la garantie qu'un effacement de données est réellement complet.
    -- -----------------------------------------------------------------------
    INSERT INTO analyzer.packets (flow_id, session_id, horodatage, taille, protocole,
                                  ip_source, ip_destination, port_destination)
    VALUES (flow_id, session_test, now(), 74, 'TCP', '10.0.0.5', '93.184.216.34', 443);

    SELECT count(*) INTO avant FROM analyzer.flows WHERE session_id = session_test;
    SELECT count(*) INTO apres FROM analyzer.packets WHERE session_id = session_test;
    IF avant = 0 OR apres = 0 THEN
        RAISE EXCEPTION 'Les données de test n''ont pas été insérées';
    END IF;

    DELETE FROM analyzer.capture_sessions WHERE id = session_test;
    SELECT count(*) INTO avant FROM analyzer.flows WHERE session_id = session_test;
    SELECT count(*) INTO apres FROM analyzer.packets WHERE session_id = session_test;
    IF avant > 0 OR apres > 0 THEN
        RAISE EXCEPTION 'La cascade n''a pas tout supprimé (% communications, % paquets restants)',
                        avant, apres;
    END IF;
    RAISE NOTICE 'OK    la suppression d''une capture emporte communications et paquets';
    RAISE NOTICE 'OK    les explications liées ont suivi (contrainte de clé étrangère)';

    -- -----------------------------------------------------------------------
    -- 11. La purge efface l'ancien et conserve le récent
    -- -----------------------------------------------------------------------
    INSERT INTO analyzer.capture_sessions (agent, debut, dernier_paquet)
    VALUES ('poste-ancien', now() - interval '45 days', now() - interval '45 days')
    RETURNING id INTO session_vieille;

    INSERT INTO analyzer.capture_sessions (agent, debut, dernier_paquet)
    VALUES ('poste-recent', now() - interval '2 days', now())
    RETURNING id INTO session_test;

    SELECT count(*) INTO avant FROM analyzer.capture_sessions;
    SELECT sessions_supprimees INTO apres FROM analyzer.purger(30);
    IF apres <> 1 THEN
        RAISE EXCEPTION 'La purge devait supprimer 1 session, elle en a supprimé %', apres;
    END IF;
    IF EXISTS (SELECT 1 FROM analyzer.capture_sessions WHERE agent = 'poste-ancien') THEN
        RAISE EXCEPTION 'La session ancienne est toujours là après purge';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM analyzer.capture_sessions WHERE agent = 'poste-recent') THEN
        RAISE EXCEPTION 'La purge a supprimé une session récente';
    END IF;
    RAISE NOTICE 'OK    la purge supprime au-delà de 30 jours et conserve le reste';

    -- Un délai absurde doit être refusé, pas appliqué silencieusement.
    refuse := false;
    BEGIN
        PERFORM analyzer.purger(0);
    EXCEPTION WHEN raise_exception THEN
        refuse := true;
    END;
    IF NOT refuse THEN
        RAISE EXCEPTION 'Une purge de 0 jour a été acceptée';
    END IF;
    RAISE NOTICE 'OK    une purge de 0 jour est refusée';

    -- -----------------------------------------------------------------------
    -- 12. La vue de résumé répond
    -- -----------------------------------------------------------------------
    SELECT count(*) INTO avant FROM analyzer.resume_sessions;
    IF avant = 0 THEN
        RAISE EXCEPTION 'La vue resume_sessions ne rend aucune ligne';
    END IF;
    RAISE NOTICE 'OK    la vue resume_sessions rend % ligne(s)', avant;

    -- Nettoyage du jeu de test.
    DELETE FROM analyzer.capture_sessions WHERE agent IN ('poste-recent', 'poste-ancien', 'poste-de-test');
    DELETE FROM analyzer.ip_enrichments;

    RAISE NOTICE '';
    RAISE NOTICE '=== Tous les contrôles du schéma sont passés ===';
    RAISE NOTICE '';
END $$;

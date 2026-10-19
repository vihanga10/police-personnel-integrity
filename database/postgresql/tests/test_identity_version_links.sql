-- Stop on unexpected failures.
\set ON_ERROR_STOP on

-- Keep all test records temporary.
BEGIN;

DO $$
DECLARE
    officers uuid[] := ARRAY[gen_random_uuid(), gen_random_uuid()];
    assertions uuid[] := ARRAY[gen_random_uuid(), gen_random_uuid()];
    test_source uuid := gen_random_uuid();
    first_version uuid := gen_random_uuid();
    replacement_version uuid := gen_random_uuid();
    item integer;
BEGIN
    -- Check permissions using the actual backend account.
    IF current_user <> 'police_identity_app' THEN
        RAISE EXCEPTION 'Run this test as police_identity_app.';
    END IF;

    INSERT INTO identity.source_system (
        source_system_id, source_system_code, source_name
    )
    VALUES (
        test_source,
        'TEST_' || test_source::text,
        'Temporary version-link test'
    );

    -- Create two officers with their own supporting assertions.
    FOR item IN 1..2 LOOP
        INSERT INTO identity.officer (officer_uid)
        VALUES (officers[item]);

        -- Dummy bytes exercise database rules, not encryption.
        INSERT INTO identity.source_assertion (
            source_assertion_id,
            officer_uid,
            source_system_id,
            assertion_type,
            asserted_value_ciphertext,
            encryption_key_version,
            intake_batch_id,
            import_file_id,
            raw_record_id,
            source_file_name,
            source_file_sha256,
            source_row_number,
            transaction_start
        )
        VALUES (
            assertions[item],
            officers[item],
            test_source,
            'TEST',
            decode('010203', 'hex'),
            'test-key',
            'TEST-BATCH',
            'TEST-FILE',
            'TEST-ROW-' || item,
            'temporary-test.csv',
            repeat('a', 64),
            item,
            TIMESTAMPTZ '2026-01-01 00:00:00+00'
        );
    END LOOP;

    -- Create Officer A's first name version.
    INSERT INTO identity.officer_name_version (
        name_version_id, officer_uid, source_assertion_id,
        version_number, full_name, transaction_start
    )
    VALUES (
        first_version, officers[1], assertions[1],
        1, 'Test Officer A',
        TIMESTAMPTZ '2026-01-01 00:00:00+00'
    );

    -- Test 1: reject another officer's supporting assertion.
    BEGIN
        INSERT INTO identity.officer_name_version (
            name_version_id, officer_uid, source_assertion_id,
            version_number, full_name
        )
        VALUES (
            gen_random_uuid(), officers[2], assertions[1],
            1, 'Test Officer B'
        );

        RAISE EXCEPTION 'FAIL: wrong assertion owner accepted.'
            USING ERRCODE = 'check_violation';
    EXCEPTION
        WHEN raise_exception THEN
            IF SQLERRM <>
                'Supporting assertion belongs to another officer.' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'PASS: wrong assertion owner rejected.';
    END;

    -- Test 2: reject a replacement belonging to another officer.
    BEGIN
        INSERT INTO identity.officer_name_version (
            name_version_id, officer_uid, source_assertion_id,
            supersedes_name_version_id,
            version_number, full_name, transaction_start
        )
        VALUES (
            gen_random_uuid(), officers[2], assertions[2],
            first_version, 2, 'Test Officer B',
            TIMESTAMPTZ '2026-01-02 00:00:00+00'
        );

        RAISE EXCEPTION 'FAIL: cross-officer replacement accepted.'
            USING ERRCODE = 'check_violation';
    EXCEPTION
        WHEN raise_exception THEN
            IF SQLERRM <>
                'Previous version belongs to another officer or chain.' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'PASS: cross-officer replacement rejected.';
    END;

    -- Test 3: reject skipped version numbers.
    BEGIN
        INSERT INTO identity.officer_name_version (
            name_version_id, officer_uid, source_assertion_id,
            supersedes_name_version_id,
            version_number, full_name, transaction_start
        )
        VALUES (
            gen_random_uuid(), officers[1], assertions[1],
            first_version, 3, 'Corrected Test Name',
            TIMESTAMPTZ '2026-01-02 00:00:00+00'
        );

        RAISE EXCEPTION 'FAIL: skipped version accepted.'
            USING ERRCODE = 'check_violation';
    EXCEPTION
        WHEN raise_exception THEN
            IF SQLERRM <>
                'New version must immediately follow its predecessor.' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'PASS: skipped version rejected.';
    END;

    -- Test 4: reject replacement of a predecessor that is still open.
    BEGIN
        INSERT INTO identity.officer_name_version (
            name_version_id, officer_uid, source_assertion_id,
            supersedes_name_version_id,
            version_number, full_name, transaction_start
        )
        VALUES (
            gen_random_uuid(), officers[1], assertions[1],
            first_version, 2, 'Corrected Test Name',
            TIMESTAMPTZ '2026-01-02 00:00:00+00'
        );

        RAISE EXCEPTION 'FAIL: open predecessor accepted.'
            USING ERRCODE = 'check_violation';
    EXCEPTION
        WHEN raise_exception THEN
            IF SQLERRM <>
                'Previous version must be closed as SUPERSEDED.' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'PASS: open predecessor rejected.';
    END;

    -- Test 5: close version 1 and insert its valid replacement.
    UPDATE identity.officer_name_version
    SET record_state = 'SUPERSEDED',
        transaction_end = TIMESTAMPTZ '2026-01-02 00:00:00+00'
    WHERE name_version_id = first_version;

    INSERT INTO identity.officer_name_version (
        name_version_id, officer_uid, source_assertion_id,
        supersedes_name_version_id,
        version_number, full_name, transaction_start
    )
    VALUES (
        replacement_version, officers[1], assertions[1],
        first_version, 2, 'Corrected Test Name',
        TIMESTAMPTZ '2026-01-02 00:00:00+00'
    );

    RAISE NOTICE 'PASS: valid replacement inserted.';
END;
$$;

-- Discard every temporary record.
ROLLBACK;
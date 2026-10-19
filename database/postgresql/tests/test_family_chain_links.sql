-- Stop on unexpected failures.
\set ON_ERROR_STOP on

-- Keep all test records temporary.
BEGIN;

DO $$
DECLARE
    test_officer uuid := gen_random_uuid();
    test_source uuid := gen_random_uuid();
    test_assertion uuid := gen_random_uuid();
    child_chain uuid := gen_random_uuid();
    first_version uuid := gen_random_uuid();
BEGIN
    -- Check using the restricted backend account.
    IF current_user <> 'police_identity_app' THEN
        RAISE EXCEPTION 'Run this test as police_identity_app.';
    END IF;

    INSERT INTO identity.officer (officer_uid)
    VALUES (test_officer);

    INSERT INTO identity.source_system (
        source_system_id, source_system_code, source_name
    )
    VALUES (
        test_source,
        'TEST_' || test_source::text,
        'Temporary family-chain test'
    );

    -- Dummy bytes exercise database rules, not encryption.
    INSERT INTO identity.source_assertion (
        source_assertion_id, officer_uid, source_system_id,
        assertion_type, asserted_value_ciphertext,
        encryption_key_version, intake_batch_id, import_file_id,
        raw_record_id, source_file_name, source_file_sha256,
        source_row_number, transaction_start
    )
    VALUES (
        test_assertion, test_officer, test_source,
        'TEST', decode('010203', 'hex'),
        'test-key', 'TEST-BATCH', 'TEST-FILE',
        'TEST-ROW', 'temporary-test.csv', repeat('a', 64),
        1, TIMESTAMPTZ '2026-01-01 00:00:00+00'
    );

    -- Create the first version for one child.
    INSERT INTO identity.officer_family_relation (
        family_relation_version_id, relation_chain_uid,
        officer_uid, source_assertion_id, relationship_type,
        related_person_name, version_number, transaction_start
    )
    VALUES (
        first_version, child_chain,
        test_officer, test_assertion, 'CHILD',
        'Test Child', 1,
        TIMESTAMPTZ '2026-01-01 00:00:00+00'
    );

    -- Close the original version before testing replacements.
    UPDATE identity.officer_family_relation
    SET record_state = 'SUPERSEDED',
        transaction_end = TIMESTAMPTZ '2026-01-02 00:00:00+00'
    WHERE family_relation_version_id = first_version;

    -- Test 1: reject a replacement from another child's chain.
    BEGIN
        INSERT INTO identity.officer_family_relation (
            family_relation_version_id, relation_chain_uid,
            officer_uid, source_assertion_id,
            supersedes_family_relation_version_id,
            relationship_type, related_person_name,
            version_number, transaction_start
        )
        VALUES (
            gen_random_uuid(), gen_random_uuid(),
            test_officer, test_assertion, first_version,
            'CHILD', 'Different Test Child', 2,
            TIMESTAMPTZ '2026-01-02 00:00:00+00'
        );

        RAISE EXCEPTION 'FAIL: different chain accepted.'
            USING ERRCODE = 'check_violation';
    EXCEPTION
        WHEN raise_exception THEN
            IF SQLERRM <>
                'Previous version belongs to another officer or chain.' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'PASS: different child chain rejected.';
    END;

    -- Test 2: accept a replacement in the original child's chain.
    INSERT INTO identity.officer_family_relation (
        family_relation_version_id, relation_chain_uid,
        officer_uid, source_assertion_id,
        supersedes_family_relation_version_id,
        relationship_type, related_person_name,
        version_number, transaction_start
    )
    VALUES (
        gen_random_uuid(), child_chain,
        test_officer, test_assertion, first_version,
        'CHILD', 'Corrected Test Child', 2,
        TIMESTAMPTZ '2026-01-02 00:00:00+00'
    );

    RAISE NOTICE 'PASS: same child chain replacement accepted.';
END;
$$;

-- Discard every temporary record.
ROLLBACK;
-- Stop execution if an unexpected failure occurs.
\set ON_ERROR_STOP on

-- Keep all temporary records inside a transaction.
BEGIN;

DO $$
DECLARE
    test_officer uuid := gen_random_uuid();
    test_source uuid := gen_random_uuid();
    test_assertion uuid := gen_random_uuid();
BEGIN
    -- Test with the restricted backend account.
    IF current_user <> 'police_identity_app' THEN
        RAISE EXCEPTION 'Run this test as police_identity_app.';
    END IF;

    -- Create temporary identity and source records.
    INSERT INTO identity.officer (officer_uid)
    VALUES (test_officer);

    INSERT INTO identity.source_system (
        source_system_id,
        source_system_code,
        source_name
    )
    VALUES (
        test_source,
        'TEST_' || test_source::text,
        'Temporary protection test'
    );

    -- Dummy bytes test database protection, not encryption.
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
        test_assertion,
        test_officer,
        test_source,
        'TEST',
        decode('010203', 'hex'),
        'test-key',
        'TEST-BATCH',
        'TEST-FILE',
        'TEST-ROW',
        'temporary-test.csv',
        repeat('a', 64),
        1,
        TIMESTAMPTZ '2026-01-01 00:00:00+00'
    );

    -- Test 1: reject changes to the evidence content.
    BEGIN
        UPDATE identity.source_assertion
        SET asserted_value_ciphertext = decode('040506', 'hex')
        WHERE source_assertion_id = test_assertion;

        RAISE EXCEPTION 'FAIL: evidence update was allowed.'
            USING ERRCODE = 'check_violation';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'PASS: evidence update rejected.';
    END;

    -- Test 2: reject a state change without version closure.
    BEGIN
        UPDATE identity.source_assertion
        SET assertion_state = 'SUPERSEDED'
        WHERE source_assertion_id = test_assertion;

        RAISE EXCEPTION 'FAIL: state-only update was allowed.'
            USING ERRCODE = 'check_violation';
    EXCEPTION
        WHEN raise_exception THEN
            IF SQLERRM <>
                'Version closure requires a valid transaction_end.' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'PASS: state-only update rejected.';
    END;

    -- Test 3: permit an open version to be closed.
    UPDATE identity.source_assertion
    SET transaction_end = TIMESTAMPTZ '2026-01-02 00:00:00+00',
        assertion_state = 'SUPERSEDED'
    WHERE source_assertion_id = test_assertion;

    IF NOT EXISTS (
        SELECT 1
        FROM identity.source_assertion
        WHERE source_assertion_id = test_assertion
          AND assertion_state = 'SUPERSEDED'
          AND transaction_end =
              TIMESTAMPTZ '2026-01-02 00:00:00+00'
    ) THEN
        RAISE EXCEPTION 'FAIL: version closure did not succeed.';
    END IF;

    RAISE NOTICE 'PASS: open version closed successfully.';

    -- Test 4: reject reopening a closed version.
    BEGIN
        UPDATE identity.source_assertion
        SET transaction_end = NULL,
            assertion_state = 'ACTIVE'
        WHERE source_assertion_id = test_assertion;

        RAISE EXCEPTION 'FAIL: closed version was reopened.'
            USING ERRCODE = 'check_violation';
    EXCEPTION
        WHEN raise_exception THEN
            IF SQLERRM <>
                'A closed evidence version cannot be changed.' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'PASS: reopening rejected.';
    END;

    -- Test 5: reject changing the recorded closing time.
    BEGIN
        UPDATE identity.source_assertion
        SET transaction_end = TIMESTAMPTZ '2026-01-03 00:00:00+00'
        WHERE source_assertion_id = test_assertion;

        RAISE EXCEPTION 'FAIL: closing timestamp was changed.'
            USING ERRCODE = 'check_violation';
    EXCEPTION
        WHEN raise_exception THEN
            IF SQLERRM <>
                'A closed evidence version cannot be changed.' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'PASS: closing timestamp change rejected.';
    END;
END;
$$;

-- Remove every temporary record and test change.
ROLLBACK;
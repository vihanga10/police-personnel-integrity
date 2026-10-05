-- Stop on unexpected errors; test records remain inside one transaction.
\set ON_ERROR_STOP on

BEGIN;

DO $$
DECLARE
    test_batch text := 'TEST-' || gen_random_uuid()::text;
    test_file uuid := gen_random_uuid();
    test_path text := 'test/original/example.csv';
    failed_constraint text;
BEGIN
    -- Exercise the permissions actually used by the backend.
    IF current_user <> 'police_identity_app' THEN
        RAISE EXCEPTION 'Run this test as police_identity_app.';
    END IF;

    INSERT INTO staging.intake_batch (
        batch_id, archive_sha256, archive_size_bytes,
        expected_file_count, registration_receipt_id,
        registration_receipt_sha256, schema_version
    )
    VALUES (
        test_batch, repeat('a', 64), 100,
        1, gen_random_uuid(), repeat('b', 64), '1.0'
    );

    INSERT INTO staging.intake_file (
        import_file_id, batch_id, archive_path, source_file_sha256,
        size_bytes, expected_row_count, column_count, columns,
        declared_encoding, delimiter
    )
    VALUES (
        test_file, test_batch, test_path, repeat('c', 64),
        20, 1, 2, '["id", "value"]'::jsonb,
        'UTF-8', ','
    );

    -- Dummy bytes exercise database constraints, not encryption correctness.
    INSERT INTO staging.raw_record (
        raw_record_id, import_file_id, batch_id, archive_path,
        source_file_sha256, source_row_number, schema_version,
        payload_ciphertext, encryption_key_version
    )
    VALUES (
        repeat('d', 64), test_file, test_batch, test_path,
        repeat('c', 64), 1, '1.0',
        decode(repeat('01', 40), 'hex'), 'test-key'
    );

    RAISE NOTICE 'PASS: valid batch, file and row inserted.';

    -- A new file ID must not bypass uniqueness of the batch/file path.
    BEGIN
        INSERT INTO staging.intake_file (
            import_file_id, batch_id, archive_path, source_file_sha256,
            size_bytes, expected_row_count, column_count, columns,
            declared_encoding, delimiter
        )
        VALUES (
            gen_random_uuid(), test_batch, test_path, repeat('c', 64),
            20, 1, 2, '["id", "value"]'::jsonb,
            'UTF-8', ','
        );

        RAISE EXCEPTION 'FAIL: duplicate file registration accepted.';
    EXCEPTION
        WHEN unique_violation THEN
            GET STACKED DIAGNOSTICS failed_constraint = CONSTRAINT_NAME;
            IF failed_constraint <> 'uq_intake_file_batch_path' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'PASS: duplicate file registration rejected.';
    END;

    -- A different record ID must not bypass the file/row uniqueness rule.
    BEGIN
        INSERT INTO staging.raw_record (
            raw_record_id, import_file_id, batch_id, archive_path,
            source_file_sha256, source_row_number, schema_version,
            payload_ciphertext, encryption_key_version
        )
        VALUES (
            repeat('e', 64), test_file, test_batch, test_path,
            repeat('c', 64), 1, '1.0',
            decode(repeat('01', 40), 'hex'), 'test-key'
        );

        RAISE EXCEPTION 'FAIL: duplicate source row accepted.';
    EXCEPTION
        WHEN unique_violation THEN
            GET STACKED DIAGNOSTICS failed_constraint = CONSTRAINT_NAME;
            IF failed_constraint <> 'uq_raw_record_file_row' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'PASS: duplicate source row rejected.';
    END;

    -- Valid-looking metadata must still match the registered source file.
    BEGIN
        INSERT INTO staging.raw_record (
            raw_record_id, import_file_id, batch_id, archive_path,
            source_file_sha256, source_row_number, schema_version,
            payload_ciphertext, encryption_key_version
        )
        VALUES (
            repeat('f', 64), test_file, test_batch, test_path,
            repeat('0', 64), 2, '1.0',
            decode(repeat('01', 40), 'hex'), 'test-key'
        );

        RAISE EXCEPTION 'FAIL: mismatched source fingerprint accepted.';
    EXCEPTION
        WHEN foreign_key_violation THEN
            GET STACKED DIAGNOSTICS failed_constraint = CONSTRAINT_NAME;
            IF failed_constraint <> 'fk_raw_record_registered_source' THEN
                RAISE;
            END IF;
            RAISE NOTICE 'PASS: mismatched source fingerprint rejected.';
    END;

    -- The application must not overwrite staged evidence.
    BEGIN
        UPDATE staging.raw_record
        SET payload_ciphertext = decode(repeat('02', 40), 'hex')
        WHERE import_file_id = test_file;

        RAISE EXCEPTION 'FAIL: staged evidence update accepted.';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'PASS: staged evidence update rejected.';
    END;

    -- The application must not delete staged evidence.
    BEGIN
        DELETE FROM staging.raw_record
        WHERE import_file_id = test_file;

        RAISE EXCEPTION 'FAIL: staged evidence deletion accepted.';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'PASS: staged evidence deletion rejected.';
    END;

    -- Confirm failed operations did not alter the successful test insertion.
    IF (
        SELECT count(*)
        FROM staging.raw_record
        WHERE import_file_id = test_file
    ) <> 1 THEN
        RAISE EXCEPTION 'FAIL: unexpected surviving test-row count.';
    END IF;
END;
$$;

-- Discard all temporary registrations and encrypted test bytes.
ROLLBACK;
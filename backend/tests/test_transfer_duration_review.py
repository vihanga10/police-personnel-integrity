"""Diagnostic labels must neither disclose source text nor invent a duration."""
import unittest
from app.identity.inspect_transfer_durations import duration_shape, reported_date_pair, flag_shape


class TransferDurationReviewTests(unittest.TestCase):
    def test_formats_distinguish_policy_failures(self):
        cases = {'': 'MISSING', ' 00012 ': 'ACCEPTED_NONNEGATIVE_INTEGER', '-12': 'NEGATIVE_INTEGER',
                 '-0': 'SIGNED_ZERO', '+12': 'EXPLICIT_PLUS_INTEGER', '12.00': 'NONNEGATIVE_INTEGRAL_DECIMAL',
                 '12.25': 'NONNEGATIVE_FRACTIONAL_DECIMAL', '-12.25': 'NEGATIVE_FRACTIONAL_DECIMAL',
                 '-12.00': 'NEGATIVE_INTEGRAL_DECIMAL', '1234567890123': 'DIGIT_COUNT_EXCEEDS_POLICY'}
        for value, expected in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(duration_shape(value), expected)

    def test_untrusted_text_is_never_an_output_label(self):
        for value in ('PRIVATE NIC', 'NaN', 'Infinity', '1e3', '1,000', '12\x00'):
            self.assertEqual(duration_shape(value), 'OTHER_TEXT')
            self.assertEqual(flag_shape(value), 'UNMAPPED')

    def test_date_pair_observations_preserve_unknown_meaning(self):
        for departure, arrival, label in (
            ('2020-01-02', '2020-01-01', 'ARRIVAL_BEFORE_DEPARTURE'),
            ('2020-01-01', '2020-01-01', 'ARRIVAL_EQUALS_DEPARTURE'),
            ('2020-01-01', '2020-01-02', 'ARRIVAL_AFTER_DEPARTURE'),
            ('', '2020-01-02', 'DATE_PAIR_INCOMPLETE'),
            ('2001-02-29', '2020-01-02', 'DATE_PAIR_UNPARSEABLE'),
            ('20200101', '2020-01-02', 'DATE_PAIR_UNPARSEABLE')):
            with self.subTest(label=label):
                self.assertEqual(reported_date_pair(dict(departure_date=departure, arrival_date=arrival)), label)

    def test_flags_use_fixed_observed_vocabulary_only(self):
        self.assertEqual(flag_shape(' TRUE '), 'TRUE')
        self.assertEqual(flag_shape('FALSE'), 'FALSE')
        self.assertEqual(flag_shape(''), 'MISSING')
        self.assertEqual(flag_shape('true'), 'UNMAPPED')

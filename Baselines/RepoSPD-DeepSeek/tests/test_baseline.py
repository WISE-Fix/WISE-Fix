import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import repospd_deepseek as baseline


def response(prediction=1):
    body = {'choices': [{'finish_reason': 'stop', 'message': {
        'content': json.dumps({'prediction': prediction})}}],
        'usage': {'prompt_tokens': 10, 'completion_tokens': 5}}
    return io.BytesIO(json.dumps(body).encode())


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / 'dataset'
        self.folder.mkdir()
        self.output = Path(self.temp.name) / 'output'
        self.args = SimpleNamespace(model='mock-model', endpoint='https://example.invalid/v1',
                                    max_tokens=128, retries=0, timeout=1)
        self.context = dict(id='a', **{field: field + ' code' for field in baseline.FIELDS})
        self.test = [{'id': 'a', 'label': 1}, {'id': 'b', 'label': 0}]
        self.contexts = [self.context, dict(self.context, id='b')]
        self.save_inputs()

    def save_inputs(self):
        for name, values in [('test.jsonl', self.test), ('repospd_context.jsonl', self.contexts)]:
            (self.folder / name).write_text(''.join(json.dumps(x) + '\n' for x in values))
        manifest = dict(producer='RepoSPD', implementation_revision='mock-revision',
                        configuration={'budget': 5}, serialization='mock', annotation_filtering='mock')
        (self.folder / 'context_manifest.json').write_text(json.dumps(manifest))

    def test_prompt_allowlist(self):
        context = dict(self.context, label=1, cwes=['CWE-119'], cve='SECRET_METADATA')
        with patch.object(baseline.urllib.request, 'urlopen', return_value=response()) as call:
            result = baseline.classify(context, self.args, 'test-key')
        payload = json.loads(call.call_args.args[0].data)
        supplied = json.loads(payload['messages'][1]['content'])
        self.assertEqual(set(supplied), set(baseline.FIELDS))
        self.assertNotIn('SECRET_METADATA', payload['messages'][1]['content'])
        self.assertEqual(result['prediction'], 1)

    def test_strict_binary_parser(self):
        for content in ['{"prediction": true}', '{"prediction": "1"}',
                        '{"prediction": 2}', '{"prediction": 1, "label": 1}',
                        '```json\n{"prediction":1}\n```']:
            with self.assertRaises(ValueError):
                baseline.parse_prediction(content)

    def test_exact_membership_and_duplicate_validation(self):
        self.contexts.pop()
        self.save_inputs()
        with self.assertRaises(ValueError):
            baseline.load_input(self.folder)
        self.contexts = [self.context, self.context]
        self.save_inputs()
        with self.assertRaises(ValueError):
            baseline.load_input(self.folder)

    def test_metrics(self):
        records = [dict(label=y, prediction=p, status='ok')
                   for y, p in [(1, 1), (1, 0), (0, 1), (0, 0)]]
        report = baseline.metrics(records)['metrics']
        for metric in ('accuracy', 'precision', 'recall', 'f1', 'fpr'):
            self.assertEqual(report[metric], .5)
        self.assertEqual(report['mcc'], 0)
        for key in ('TP', 'FP', 'TN', 'FN'):
            self.assertEqual(report[key], 1)

    def test_failure_is_not_negative_or_partial_metrics(self):
        with patch.object(baseline.urllib.request, 'urlopen', return_value=io.BytesIO(b'{}')):
            result = baseline.classify(self.context, self.args, 'test-key')
        self.assertEqual(result['status'], 'error')
        self.assertIsNone(result['prediction'])
        self.assertIsNone(baseline.metrics([dict(result, label=1)])['metrics'])

    def test_complete_run_resume_and_manifest_guard(self):
        with patch.object(baseline.urllib.request, 'urlopen', side_effect=[response(1), response(0)]) as call:
            self.assertTrue(baseline.run_dataset(self.folder, self.output, self.args, 'test-key'))
            self.assertEqual(call.call_count, 2)
        with patch.object(baseline.urllib.request, 'urlopen') as call:
            self.assertTrue(baseline.run_dataset(self.folder, self.output, self.args, 'test-key'))
            call.assert_not_called()
        report = json.loads((self.output / 'metrics.json').read_text())
        self.assertEqual(report['instances'], 2)
        self.assertEqual(report['metrics']['accuracy'], 1)
        self.args.model = 'different-model'
        with self.assertRaises(ValueError):
            baseline.run_dataset(self.folder, self.output, self.args, 'test-key')

    def test_failed_instance_retried_without_recalling_success(self):
        with patch.object(baseline.urllib.request, 'urlopen', side_effect=[response(1), io.BytesIO(b'{}')]):
            self.assertFalse(baseline.run_dataset(self.folder, self.output, self.args, 'test-key'))
        report = json.loads((self.output / 'metrics.json').read_text())
        self.assertEqual(report['errors'], 1)
        self.assertIsNone(report['metrics'])
        with patch.object(baseline.urllib.request, 'urlopen', return_value=response(0)) as call:
            self.assertTrue(baseline.run_dataset(self.folder, self.output, self.args, 'test-key'))
            self.assertEqual(call.call_count, 1)
        records = json.loads((self.output / 'results.json').read_text())
        self.assertTrue(any('error' in attempt for attempt in records[1]['attempts']))

    def test_incomplete_response_rejected(self):
        body = {'choices': [{'finish_reason': 'length',
                            'message': {'content': '{"prediction":1}'}}]}
        with patch.object(baseline.urllib.request, 'urlopen', return_value=io.BytesIO(json.dumps(body).encode())):
            result = baseline.classify(self.context, self.args, 'test-key')
        self.assertEqual(result['status'], 'error')
        self.assertIsNone(result['prediction'])


if __name__ == '__main__':
    unittest.main()

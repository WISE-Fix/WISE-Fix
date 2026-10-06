import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wise_fix_reference_verifiers as runner
from fixture_code import PRE119, POST119, diff


ROOT = Path(__file__).resolve().parents[1]
ENGINE = Path(os.environ.get('WISE_FIX_ENGINE', str(runner.DEFAULT_ENGINE)))


class RunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = runner.load_engine(ENGINE)

    def example(self):
        return json.loads((ROOT / 'examples' / 'CWE-119.json').read_text())

    def artifact(self):
        def row(split, label):
            after = POST119 if label else PRE119
            return {'id': split + str(label), 'label': label,
                    'cwes': ['CWE-119'] if label else [], 'file': 'image.c',
                    'before': PRE119, 'after': after, 'diff': diff(PRE119, after, 'image.c')}
        return self.engine.offline('CWE-119', 'Synthetic fixture only',
                                   [row('train', 1), row('train', 0)],
                                   [row('dev', 1), row('dev', 0)], self.engine.Config(),
                                   runner.load_candidate(self.engine, 'CWE-119'))

    def test_candidate_check_does_not_claim_frozen_or_score(self):
        result = runner.check_patch(self.engine, 'CWE-119', self.example())
        self.assertEqual(result['verdict'], 'Verified')
        self.assertEqual(result['suite_status'], 'UnvalidatedCandidate')
        self.assertNotIn('score', result)

    def test_nested_legacy_input_adapter(self):
        example = self.example()
        nested = {'commit_id': 'example', 'file': example['file'], 'before': {'code_before': example['before']},
                  'after': {'code_after': example['after']}, 'diff': {'code_change': example['diff']},
                  'CWE_ID': '999', 'category': 'non-security'}
        result = runner.check_patch(self.engine, 'CWE-119', nested)
        self.assertEqual(result['verdict'], 'Verified')

    def test_original_fragments_preserve_uncertainty(self):
        for cwe, filename in [('CWE-119', 'CVE-2017-5511.json'), ('CWE-125', 'CVE-2016-6905.json')]:
            data = json.loads((ROOT / 'examples' / 'original' / filename).read_text())
            result = runner.check_patch(self.engine, cwe, data)
            self.assertEqual(result['verdict'], 'Inconclusive')

    def test_frozen_check_and_tampered_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'artifact.json'
            artifact = self.artifact()
            self.engine.dump(path, artifact)
            result = runner.check_patch(self.engine, 'CWE-119', self.example(), artifact_path=path)
            self.assertEqual(result['suite_status'], 'Frozen')
            self.assertIn('score', result)
            artifact['sha256'] = 'forged'
            self.engine.dump(path, artifact)
            with self.assertRaisesRegex(ValueError, 'integrity'):
                runner.check_patch(self.engine, 'CWE-119', self.example(), artifact_path=path)

    def test_frozen_configuration_cannot_be_replaced(self):
        with self.assertRaisesRegex(ValueError, 'replacement'):
            runner.check_patch(self.engine, 'CWE-119', self.example(),
                               artifact_path='artifact.json', config_path='config.json')

    def test_invalid_input_and_cwe_mismatch(self):
        with self.assertRaises(ValueError):
            runner.check_patch(self.engine, 'CWE-119', {})
        with self.assertRaisesRegex(ValueError, 'do not match'):
            runner.load_candidate(self.engine, 'CWE-125', ROOT / 'suites' / 'CWE-119.json')

    def test_bundled_suite_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            shutil.copytree(ROOT / 'suites', target / 'suites')
            shutil.copyfile(ROOT / 'manifest.json', target / 'manifest.json')
            (target / 'suites' / 'CWE-119.json').write_text('{}')
            with patch.object(runner, 'ROOT', target):
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    runner.load_candidate(self.engine, 'CWE-119')

    def test_cli_input_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            for cwe in ('CWE-119', 'CWE-125'):
                output = Path(directory) / (cwe + '.json')
                result = subprocess.run(
                    [sys.executable, str(ROOT / 'wise_fix_reference_verifiers.py'),
                     '--engine', str(ENGINE), '--cwe', cwe,
                     '--input', str(ROOT / 'examples' / (cwe + '.json')),
                     '--output', str(output)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(output.read_text())['verdict'], 'Verified')


if __name__ == '__main__':
    unittest.main()

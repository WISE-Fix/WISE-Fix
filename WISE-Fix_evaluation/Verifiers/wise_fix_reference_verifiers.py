import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
DEFAULT_ENGINE = ROOT.parent / 'wise-fix.py'
_engines = {}


def load_engine(path):
    path = Path(path).resolve()
    if not path.is_file():
        raise ValueError(f'Engine not found: {path}; provide --engine /path/to/wise-fix.py')
    if path not in _engines:
        spec = importlib.util.spec_from_file_location('wise_fix_verifier_runtime', path)
        if spec is None or spec.loader is None:
            raise ValueError('Cannot load the selected Python engine')
        engine = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = engine
        spec.loader.exec_module(engine)
        manifest = json.loads((ROOT / 'manifest.json').read_text(encoding='utf-8'))
        if engine.VERSION != manifest['engine_version']:
            raise ValueError('Engine version does not match this verifier package')
        for field, contracts in [('semantic_contracts_sha256', engine.MANUSCRIPT_CONTRACTS),
                                 ('operator_contracts_sha256', engine.OPS)]:
            if engine.digest(contracts) != manifest[field]:
                raise ValueError('Engine operator contracts do not match this verifier package')
        _engines[path] = engine
    return _engines[path]


def load_candidate(engine, cwe, path=None):
    if path is None:
        manifest = json.loads((ROOT / 'manifest.json').read_text(encoding='utf-8'))
        if cwe not in manifest['suites']:
            raise ValueError(f'No bundled candidate for {cwe}; provide --suite')
        record = manifest['suites'][cwe]
        path = ROOT / record['file']
        if hashlib.sha256(path.read_bytes()).hexdigest() != record['sha256']:
            raise ValueError('Bundled candidate suite digest mismatch')
    suite = engine.load(path)
    engine.validate_suite(suite)
    if suite['cwe'] != cwe:
        raise ValueError('Selected CWE and suite do not match')
    return suite


def transition(data):
    if not isinstance(data, dict):
        raise ValueError('Input must contain one patch JSON object')

    def value(key, alias, nested):
        result = data.get(key, data.get(alias))
        if isinstance(result, dict):
            result = result.get(nested)
        if not isinstance(result, str):
            raise ValueError(f'Input requires a {key} source string')
        return result

    return {'id': str(data.get('id', data.get('patch_id', data.get('commit_id', 'patch')))),
            'file': data.get('file', 'example.c'),
            'before': value('before', 's_minus', 'code_before'),
            'after': value('after', 's_plus', 'code_after'),
            'diff': value('diff', 'delta', 'code_change')}


def check_patch(engine, cwe, data, suite_path=None, artifact_path=None, config_path=None):
    if artifact_path is not None and (suite_path is not None or config_path is not None):
        raise ValueError('Frozen artifacts cannot be combined with replacement suites/configuration')
    if artifact_path is not None:
        artifact = engine.load(artifact_path)
        cfg = engine.check_artifact(artifact)
        if artifact['cwe'] != cwe:
            raise ValueError('Selected CWE and frozen artifact do not match')
        suite, status = artifact['suite'], 'Frozen'
    else:
        suite = load_candidate(engine, cwe, suite_path)
        cfg = engine.Config.from_dict(engine.load(config_path)) if config_path else engine.Config()
        status = 'UnvalidatedCandidate'
    row = transition(data)
    if not isinstance(row['file'], str) or not row['file']:
        raise ValueError('Input file must be a nonempty source path string')
    unit = engine.unit_from_text(row['before'], row['after'], row['diff'], cfg,
                                unit_id=row['id'], file=row['file'])
    result = engine.verify_unit(suite, unit, cfg)
    result.update({'engine_version': engine.VERSION, 'suite_status': status,
                   'verification_mode': 'singleton',
                   'suite_sha256': engine.digest(suite)})
    if artifact_path is not None:
        result['artifact_sha256'] = artifact['sha256']
        if result['verdict'] == engine.VER:
            result['score'] = engine.score(artifact['scorer'], result['features'])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', type=Path, default=DEFAULT_ENGINE)
    parser.add_argument('--cwe', required=True)
    parser.add_argument('--input', type=Path, required=True, help='Patch JSON file')
    parser.add_argument('--output', type=Path, required=True, help='Output JSON file')
    parser.add_argument('--suite', type=Path, help='Optional candidate suite JSON')
    parser.add_argument('--artifact', type=Path, help='Optional accepted frozen artifact')
    parser.add_argument('--config', type=Path, help='Optional candidate configuration')
    args = parser.parse_args()
    try:
        engine = load_engine(args.engine)
        result = check_patch(engine, args.cwe, engine.load(args.input), args.suite,
                             args.artifact, args.config)
        engine.dump(args.output, result)
        print(f'{args.cwe}: {result["verdict"]} ({result["suite_status"]}) -> {args.output}')
        return 0
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as error:
        print(f'WISE-Fix verifiers: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

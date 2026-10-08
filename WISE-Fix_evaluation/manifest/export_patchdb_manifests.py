import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

GROUPS = ['Memory Safety', 'Pointer Dereference', 'Input & Lifecycle', 'Long-tail CWEs']
CWE_GROUP = {119: GROUPS[0], 125: GROUPS[0], 787: GROUPS[0], 476: GROUPS[1],
             20: GROUPS[2], 190: GROUPS[2], 416: GROUPS[2]}
SOURCE_EXTENSIONS = {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.java',
                     '.py', '.js', '.ts', '.go', '.rs', '.cs', '.m', '.mm', '.swift',
                     '.kt', '.scala', '.rb', '.php'}


def read_jsonl(path):
    if not path:
        return []
    result = []
    with Path(path).open(encoding='utf-8-sig') as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f'{path}, line {number}: {exc}') from exc
            if not isinstance(value, dict):
                raise ValueError(f'{path}, line {number}: expected JSON object')
            result.append(value)
    return result


def write_jsonl(path, records):
    with Path(path).open('w', encoding='utf-8', newline='\n') as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + '\n')


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def cwes(raw):
    values = raw if isinstance(raw, list) else [raw]
    result = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        # Only explicit CWE IDs or bare numerical IDs, not numbers in prose/CVEs.
        found = re.findall(r'(?i)\bCWE[-_ ](\d+)\b', text)
        if not found and re.fullmatch(r'\d+(?:\s*[,;|/]\s*\d+)*', text):
            found = re.findall(r'\d+', text)
        result.update(int(x) for x in found if int(x) > 0)
    return sorted(result)


def timestamp(record):
    raw = record.get('author_timestamp')
    if raw is None:
        match = re.search(r'^Date:\s*(.+)$', record.get('commit_message', ''), re.M)
        raw = match.group(1).strip().replace('\u00a0', ' ') if match else None
    if raw is None:
        return 0, 'MISSING'
    try:
        if isinstance(raw, (int, float)) or re.fullmatch(r'-?\d+', str(raw)):
            return int(raw), 'PARSED'
        try:
            date = parsedate_to_datetime(str(raw))
        except (ValueError, TypeError):
            try:
                date = datetime.strptime(str(raw).strip(), '%a %b %d %H:%M:%S %Y %z')
            except ValueError:
                date = datetime.fromisoformat(str(raw).replace('Z', '+00:00'))
        if date.tzinfo is None:
            return 0, 'MISSING_TIMEZONE'
        return int(date.astimezone(timezone.utc).timestamp()), 'PARSED'
    except (ValueError, TypeError, OverflowError):
        return 0, 'UNPARSEABLE'


def identity(record):
    return f"{record['repository']}@{record['commit_hash']}"


def sidecar(path):
    result = {}
    for value in read_jsonl(path):
        key = value.get('seed_id')
        if not key:
            repo = value.get('repository')
            commit = value.get('commit_hash')
            if not repo or not commit:
                raise ValueError(f'{path}: supply seed_id or repository + commit_hash')
            key = f'{repo}@{commit}'
        if key in result:
            raise ValueError(f'{path}: duplicate identifier {key}')
        result[key] = value
    return result


def normalize(raw, split, line):
    category = str(raw.get('category', '')).lower().strip()
    if category not in {'security', 'non-security'}:
        raise ValueError(f'{split}, record {line}: unknown category {category!r}')
    commit = str(raw.get('commit_id', '')).lower()
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError(f'{split}, record {line}: expected full SHA-1 commit_id')
    owner, repo = raw.get('owner'), raw.get('repo')
    if not owner or not repo:
        raise ValueError(f'{split}, record {line}: owner/repo missing')
    date, date_status = timestamp(raw)
    paths = re.findall(r'^\+\+\+ b/(.+)$', raw.get('diff_code', ''), re.M)
    paths += re.findall(r'^--- a/(.+)$', raw.get('diff_code', ''), re.M)
    paths = sorted(set(paths))
    value = dict(dataset='PatchDB*', split=split, repository=f'{owner}/{repo}',
                 repository_url=f'https://github.com/{owner}/{repo}', commit_hash=commit,
                 parent_hash=raw.get('parent_hash') or raw.get('parent_id'),
                 label=int(category == 'security'), cwe_ids=cwes(raw.get('CWE_ID')),
                 raw_cwe_annotation=raw.get('CWE_ID'), cve_id=raw.get('CVE_ID'),
                 author_timestamp=date, timestamp_status=date_status, modified_files=paths,
                 diff_code=raw.get('diff_code', ''), record_origin='RECONSTRUCTED_FROM_DATASET')
    value['seed_id'] = identity(value)
    return value


def base(record):
    return {k: record[k] for k in ['seed_id', 'dataset', 'split', 'repository',
            'repository_url', 'commit_hash', 'parent_hash', 'author_timestamp',
            'timestamp_status', 'label', 'record_origin']}


def order(record):
    return record['author_timestamp'], record['commit_hash'], record['repository']


def run(args):
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    names = ['unmapped', 'selected_examples', 'suite_counts', 'development_membership',
             'development_processing', 'rq5_robustness_slices']
    targets = [out / f'manifest_{name}.jsonl' for name in names]
    if not args.overwrite and any(p.exists() for p in targets):
        raise ValueError('Output manifests already exist; choose another folder or use --overwrite')
    eligibility = sidecar(args.eligibility)
    processing = sidecar(args.processing)
    ratings = sidecar(args.difficulty)
    domain_records = read_jsonl(args.domains)
    domains = {}
    for value in domain_records:
        repo = value['repository']
        if repo in domains:
            raise ValueError(f'Duplicate repository domain: {repo}')
        if value['repository_domain'] not in ['OS & Hypervisors', 'Multimedia', 'Networking', 'unassigned']:
            raise ValueError(f'Unknown domain for {repo}')
        domains[repo] = value
    splits = {}
    seen = {}
    for split in ['train', 'dev', 'test']:
        splits[split] = []
        for line, raw in enumerate(read_jsonl(getattr(args, split)), 1):
            record = normalize(raw, split, line)
            key = record['seed_id']
            if key in seen:
                raise ValueError(f'Duplicate commit {key} in {seen[key]} and {split}; no silent deduplication')
            seen[key] = split
            supplied = eligibility.get(key)
            if supplied:
                if not isinstance(supplied.get('eligible'), bool):
                    raise ValueError(f'Eligibility must be boolean: {key}')
                record['eligible'] = supplied['eligible']
                record['eligibility_reason'] = supplied.get('reason', 'SUPPLIED_ELIGIBILITY')
                record['eligibility_origin'] = 'SUPPLIED_RECORD'
            else:
                record['eligible'] = bool(record['diff_code'].strip()) and any(
                    Path(p).suffix.lower() in SOURCE_EXTENSIONS for p in record['modified_files'])
                record['eligibility_reason'] = ('SUPPORTED_SOURCE_DIFF' if record['eligible'] else
                                                'NO_SUPPORTED_SOURCE_DIFF')
                record['eligibility_origin'] = 'PROVISIONAL_EXTENSION_FILTER'
            splits[split].append(record)
    for title, mapping in [('eligibility', eligibility), ('processing', processing), ('difficulty', ratings)]:
        unknown = set(mapping) - set(seen)
        if unknown:
            raise ValueError(f'{title}: identifiers absent from dataset: {sorted(unknown)[:3]}')
    suites = sorted(set(args.cwes or [w for r in splits['train'] + splits['dev'] for w in r['cwe_ids']]))
    unmapped = [dict(base(r), raw_annotation=r['raw_cwe_annotation'], cve_id=r['cve_id'],
                     reason='NO_USABLE_CWE_ID', excluded_from='WEAKNESS_SPECIFIC_POSITIVES',
                     retained_in_test=(r['split'] == 'test'))
                for rows in splits.values() for r in rows if r['label'] == 1 and not r['cwe_ids']]
    selected, memberships, counts = [], [], []
    selected_dev = set()
    for w in suites:
        train_pos = sorted([r for r in splits['train'] if r['eligible'] and r['label'] and w in r['cwe_ids']], key=order)
        train_neg = sorted([r for r in splits['train'] if r['eligible'] and not r['label']], key=order)
        dev_pos = sorted([r for r in splits['dev'] if r['eligible'] and r['label'] and w in r['cwe_ids']], key=order)
        dev_neg = sorted([r for r in splits['dev'] if r['eligible'] and not r['label']], key=order)
        pos_ids = {r['seed_id'] for r in dev_pos}
        neg_ids = {r['seed_id'] for r in dev_neg[:len(dev_pos)]}
        for role, pool in [('positive', train_pos), ('negative', train_neg)]:
            for rank, r in enumerate(pool[:args.cap], 1):
                selected.append(dict(base(r), weakness_id=f'CWE-{w}', role=role, rank=rank,
                                     eligibility_origin=r['eligibility_origin'], policy_version=args.policy_version))
        for r in sorted(splits['dev'], key=order):
            chosen = r['seed_id'] in pos_ids | neg_ids
            reason = None if chosen else (r['eligibility_reason'] if not r['eligible'] else
                'NO_USABLE_CWE_ID' if r['label'] and not r['cwe_ids'] else
                'NON_TARGET_CWE' if r['label'] else 'BALANCING_QUOTA_EXHAUSTED')
            memberships.append(dict(base(r), weakness_id=f'CWE-{w}', role='positive' if r['label'] else 'negative',
                eligible=bool(r['eligible'] and (not r['label'] or w in r['cwe_ids'])), selected=chosen,
                exclusion_reason=reason, eligibility_origin=r['eligibility_origin'], policy_version=args.policy_version))
        selected_dev |= pos_ids | neg_ids
        counts.append(dict(dataset='PatchDB*', weakness_id=f'CWE-{w}', eligible_train_pos=len(train_pos),
            eligible_train_neg=len(train_neg), synthesis_pos=min(len(train_pos), args.cap),
            synthesis_neg=min(len(train_neg), args.cap), eligible_dev_pos=len(dev_pos),
            eligible_dev_neg=len(dev_neg), dev_pos=len(dev_pos), dev_neg=min(len(dev_neg), len(dev_pos)),
            policy_version=args.policy_version, counts_origin='COMPUTED_FROM_RECONSTRUCTED_MEMBERSHIP'))
    diagnostics = []
    for r in splits['dev']:
        supplied = processing.get(r['seed_id'])
        value = dict(base(r), selected_for_any_suite=r['seed_id'] in selected_dev,
                     dataset_diff_code_points=len(r['diff_code']), policy_version=args.policy_version,
                     processing_status='MISSING_PROCESSING_LOG', original_pre_code_points=None,
                     retained_pre_code_points=None, original_post_code_points=None,
                     retained_post_code_points=None, original_diff_code_points=None,
                     retained_diff_code_points=None, truncated_context=None, truncated_diff=None,
                     ast_nodes_pre=None, ast_nodes_post=None, parse_diagnostic='NOT_RUN', configuration_version=None)
        if supplied:
            for key in ['original_pre_code_points', 'retained_pre_code_points', 'original_post_code_points',
                        'retained_post_code_points', 'original_diff_code_points', 'retained_diff_code_points',
                        'truncated_context', 'truncated_diff', 'ast_nodes_pre', 'ast_nodes_post',
                        'parse_diagnostic', 'configuration_version']:
                value[key] = supplied.get(key)
            value['processing_status'] = 'SUPPLIED_PROCESSING_LOG'
            for raw, retained, cap in [('original_pre_code_points', 'retained_pre_code_points', 8000),
                                      ('original_post_code_points', 'retained_post_code_points', 8000),
                                      ('original_diff_code_points', 'retained_diff_code_points', 16000)]:
                a, b = value[raw], value[retained]
                if b is not None and (not isinstance(b, int) or b < 0 or b > cap or (a is not None and b > a)):
                    raise ValueError(f'Invalid retained length {retained}: {r["seed_id"]}')
            for field in ['ast_nodes_pre', 'ast_nodes_post']:
                if value[field] is not None and not 0 <= value[field] <= 10000:
                    raise ValueError(f'AST budget exceeded: {r["seed_id"]}')
        diagnostics.append(value)
    negatives = sorted([r for r in splits['test'] if not r['label']], key=order)
    assignments = {}
    if args.negative_quotas:
        if sum(args.negative_quotas) != len(negatives) or any(n < 0 for n in args.negative_quotas):
            raise ValueError('Negative quotas must be nonnegative and sum to the actual test-negative count')
        start = 0
        for group, quota in zip(GROUPS, args.negative_quotas):
            for r in negatives[start:start + quota]:
                assignments[r['seed_id']] = group
            start += quota
    slices = []
    for r in splits['test']:
        domain = domains.get(r['repository'])
        rating = ratings.get(r['seed_id'])
        difficulty = None if r['label'] else (rating.get('negative_difficulty') if rating else 'pending_annotation')
        if not r['label'] and difficulty not in ['standard', 'hard', 'pending_annotation']:
            raise ValueError(f'Invalid difficulty: {r["seed_id"]}')
        group = (CWE_GROUP.get(min(r['cwe_ids']), GROUPS[3]) if r['cwe_ids'] else GROUPS[3]) if r['label'] else assignments.get(r['seed_id'], 'pending_quota_policy')
        slices.append(dict(base(r), cwe_ids=[f'CWE-{w}' for w in r['cwe_ids']], weakness_group=group,
            repository_domain=domain['repository_domain'] if domain else 'pending_domain_assignment',
            negative_difficulty=difficulty, assignment_reasons={
                'weakness_group': 'SMALLEST_CWE_ID' if r['label'] and r['cwe_ids'] else
                    'UNMAPPED_POSITIVE' if r['label'] else 'FIXED_SORTED_QUOTA' if args.negative_quotas else 'MISSING_QUOTA_POLICY',
                'repository_domain': domain.get('reason') if domain else 'MISSING_DOMAIN_RECORD',
                'negative_difficulty': 'NOT_APPLICABLE' if r['label'] else rating.get('reason') if rating else 'MISSING_ANNOTATION'},
            policy_version=args.policy_version))
    outputs = [unmapped, selected, counts, memberships, diagnostics, slices]
    for path, rows in zip(targets, outputs):
        write_jsonl(path, rows)
    summary = dict(exported_at_utc=datetime.now(timezone.utc).isoformat(), policy_version=args.policy_version,
        record_origin='RECONSTRUCTED_EXPORT_NOT_HISTORICAL_FREEZE', synthesis_cap=args.cap,
        splits={s: dict(total=len(rows), positive=sum(r['label'] for r in rows), negative=sum(not r['label'] for r in rows)) for s, rows in splits.items()},
        input_sha256={s: digest(getattr(args, s)) for s in splits}, output_sha256={p.name: digest(p) for p in targets},
        eligible_policy='Supplied eligibility where available; otherwise provisional source-extension filter',
        provisional_eligibility_records=sum(r['eligibility_origin'] != 'SUPPLIED_RECORD' for rows in splits.values() for r in rows),
        missing_parent_hashes=sum(not r['parent_hash'] for rows in splits.values() for r in rows),
        missing_development_processing_logs=sum(r['processing_status'] == 'MISSING_PROCESSING_LOG' for r in diagnostics),
        pending_rq5_domains=sum(r['repository_domain'] == 'pending_domain_assignment' for r in slices),
        pending_rq5_difficulty=sum(r['negative_difficulty'] == 'pending_annotation' for r in slices),
        pending_negative_group_assignments=sum(r['weakness_group'] == 'pending_quota_policy' for r in slices),
        rq5_group_counts=dict(Counter(r['weakness_group'] for r in slices)),
        sidecar_sha256={name: digest(path) for name, path in [('eligibility', args.eligibility), ('processing', args.processing), ('domains', args.domains), ('difficulty', args.difficulty)] if path})
    (out / 'export_summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f'Exported six manifests to: {out.resolve()}')
    print('Review pending/provisional fields before claiming experimental reproducibility.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default = Path(r'C:\Users\TAHIR\WISE-Fix Dataset\patch_db')
    for split in ['train', 'dev', 'test']:
        parser.add_argument('--' + split, default=str(default / (split + '.jsonl')))
    parser.add_argument('--output', default=str(default / 'manifests'))
    parser.add_argument('--cap', type=int, default=20)
    parser.add_argument('--cwes', nargs='+', type=int, help='Explicit target CWE numbers; default: IDs observed in train/dev')
    parser.add_argument('--negative-quotas', nargs=4, type=int, help='Reviewed RQ5 group quotas in listed group order')
    for name in ['eligibility', 'processing', 'domains', 'difficulty']:
        parser.add_argument('--' + name, help='Optional JSONL sidecar; see README')
    parser.add_argument('--policy-version', default='patchdb-reconstructed-v1')
    parser.add_argument('--overwrite', action='store_true')
    args = parser.parse_args()
    if args.cap < 1:
        parser.error('--cap must be positive')
    try:
        run(args)
    except (ValueError, OSError, KeyError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

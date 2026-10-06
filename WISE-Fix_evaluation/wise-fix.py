from __future__ import annotations
import argparse
import copy
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass, field
from typing import Any
try:
    import pycparser
    from pycparser import c_ast, c_generator, c_parser
except ImportError:
    raise SystemExit('Install dependencies: python -m pip install -r requirements.txt')

VERSION = 'wise-fix-reference-3.1'
SAT, VIO, UNR = 'Satisfied', 'Violated', 'Unresolved'
VER, REJ, INC = 'Verified', 'Rejected', 'Inconclusive'
STAGES = ('pre', 'repair', 'safety')
FEATURES = ('s_pre', 's_repair', 's_safety', 'c_corr', 'c_prox', 'c_ctx', 'c_contra')
OPS = {
    'AST_KIND': ('node',), 'AST_REFERENCE': ('node',),
    'AST_OPERATOR': ('node',), 'AST_CALL': ('node',),
    'AST_CONTAINS': ('outer', 'inner'), 'AST_SAME_FUNCTION': ('left', 'right'),
    'CFG_DOMINATES': ('guard', 'sink'), 'CFG_TRUE_BRANCH_EXITS': ('guard',),
    'CORRESPONDS': ('before', 'after'), 'EDIT_CHANGES': ('before', 'after'),
    'EDIT_INTRODUCES': ('after',),
    'BUFFER_GUARD': ('guard', 'sink'),
    'BUFFER_GUARD_MISMATCH': ('guard', 'sink'),
    'EDIT_GUARD_STRENGTHENS': ('before', 'after', 'sink_before', 'sink_after'),
    'DESTINATION_GUARD_MISMATCH': ('guard', 'write'),
    'DESTINATION_COPY_GUARDED': ('guard', 'write'),
    'DESTINATION_REPAIR_LINK': ('before', 'after', 'old_write', 'new_write'),
    'EDIT_DESTINATION_GUARD': ('before', 'after', 'new_write'),
    'DIRECT_LENGTH_CONVERSION': ('assignment',),
    'DIRECT_LENGTH_FLOW': ('assignment', 'arithmetic', 'sink'),
    'NORMALIZED_LENGTH_FLOW': ('assignment', 'arithmetic', 'sink'),
    'EDIT_LENGTH_NORMALIZES': ('before', 'after'),
}
EDIT_OPS = {'EDIT_CHANGES', 'EDIT_INTRODUCES', 'EDIT_GUARD_STRENGTHENS','EDIT_DESTINATION_GUARD','EDIT_LENGTH_NORMALIZES'}
MITIGATION_OPS = {'EDIT_GUARD_STRENGTHENS','EDIT_DESTINATION_GUARD','EDIT_LENGTH_NORMALIZES'}
CORRESPONDENCE_OPS = {'CORRESPONDS','DESTINATION_REPAIR_LINK','EDIT_LENGTH_NORMALIZES'}
DEST_PARAMS = ('position','source_position','count','width','capacity','destination','source','iterator','inner_iterator')
LENGTH_PARAMS = ('variable','accumulator','image','producer','consumer','outer_type','normalization_type','size_type')
MANUSCRIPT_CONTRACTS = {
    'DESTINATION_GUARD_MISMATCH': {'parameters':DEST_PARAMS,'types':{'guard':'If','write':'Assignment'},'contract':'Source-position bound precedes the selected destination byte write; this establishes only the encoded mismatch.'},
    'DESTINATION_COPY_GUARDED': {'parameters':DEST_PARAMS,'types':{'guard':'If','write':'FuncCall'},'contract':'Destination-total bound with exiting true branch dominates a counted memcpy loop and matching destination increment.'},
    'DESTINATION_REPAIR_LINK': {'parameters':DEST_PARAMS,'types':{'before':'If','after':'If','old_write':'Assignment','new_write':'FuncCall'},'contract':'Same-file/function witnesses link the mismatching pre guard/write to the guarded post copy.'},
    'EDIT_DESTINATION_GUARD': {'parameters':DEST_PARAMS,'types':{'before':'If','after':'If','new_write':'FuncCall'},'contract':'Actual edits replace the source-position bound with the destination-position mitigation linked to the post write.'},
    'DIRECT_LENGTH_CONVERSION': {'parameters':LENGTH_PARAMS,'types':{'assignment':'Assignment'},'contract':'Selected local value is assigned an outer size cast of the declared byte-producing call without unsigned-char normalization.'},
    'DIRECT_LENGTH_FLOW': {'parameters':LENGTH_PARAMS,'types':{'assignment':'Assignment','arithmetic':'Assignment','sink':'FuncCall'},'contract':'The direct producer-to-size conversion reaches the selected arithmetic update and ReadBlob size through the same unambiguous local definition.'},
    'NORMALIZED_LENGTH_FLOW': {'parameters':LENGTH_PARAMS,'types':{'assignment':'Assignment','arithmetic':'Assignment','sink':'FuncCall'},'contract':'Same local unsigned-char-normalized value dominates its accumulator use and postincrement ReadBlob size use; ambiguous writes/aliasing abstain.'},
    'EDIT_LENGTH_NORMALIZES': {'parameters':LENGTH_PARAMS,'types':{'before':'Assignment','after':'Assignment'},'contract':'Source-located actual edit inserts unsigned-char normalization for the same scoped assigned length.'},
}
GEN = c_generator.CGenerator()


def canonical(x: Any) -> bytes:
    return json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def digest(x: Any) -> str:
    return hashlib.sha256(canonical(x)).hexdigest()


def runtime_digest() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def dump(path: str | Path, x: Any) -> None:
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(x, indent=2, ensure_ascii=False, allow_nan=False) + '\n')


def load(path: str | Path) -> Any:
    return json.loads(Path(path).read_text())


def conjunction(xs: list[str]) -> str:
    return VIO if VIO in xs else SAT if xs and all(x == SAT for x in xs) else UNR


def existential(xs: list[str], complete: bool) -> str:
    if SAT in xs: return SAT
    if complete and all(x == VIO for x in xs): return VIO
    return UNR


def aggregate_verdicts(xs: list[str]) -> str:
    return VER if VER in xs else INC if not xs or INC in xs else REJ


def sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x)) if x >= 0 else math.exp(x) / (1 + math.exp(x))


def score(model: dict, phi: list[float]) -> float:
    return sigmoid(model['intercept'] + sum(a*b for a, b in zip(model['weights'], phi)))


@dataclass(frozen=True)
class Config:
    chars_per_state: int = 8000
    max_diff_chars: int = 16000
    node_budget: int = 10000
    witness_budget: int = 1000
    max_files: int = 100
    dependency_files: tuple[str, ...] = ()
    upfront_commit_budget: int = 3
    language_suffixes: tuple[str, ...] = ('.c',)
    path_prefixes: tuple[str, ...] = ('',)
    history_limit: int = 5000
    history_start: int | None = None
    history_end: int | None = None
    include_merges: bool = False
    max_group_size: int = 3
    max_history_distance: int = 50
    composite_budget: int = 20
    temporal_seconds: int = 14 * 86400
    min_precision: float = 0.80
    min_recall: float = 0.80
    max_fpr: float = 0.10
    max_revisions: int = 3
    max_examples_per_class: int = 20
    regularizations: tuple[float, ...] = (0.0, 0.01, 0.1)
    stopping_points: tuple[int, ...] = (100, 300)
    learning_rate: float = 0.1
    rank_bounds: tuple[float, ...] = (10., 10., 10., 10.)
    max_line_distance: float = 50.
    schema_version: str = 'obligations-1.0'

    def validate(self):
        for k in ('chars_per_state','max_diff_chars','node_budget','witness_budget',
                  'max_files','history_limit','max_group_size','max_history_distance',
                  'max_examples_per_class','max_line_distance'):
            if getattr(self, k) <= 0: raise ValueError(f'{k} must be positive')
        if self.composite_budget < 0 or not 0 <= self.max_revisions <= 3:
            raise ValueError('Invalid budget: max_revisions must be in 0..3')
        if self.max_examples_per_class > 20: raise ValueError('At most 20 examples/class')
        if self.chars_per_state > 8000: raise ValueError('Context cap must be <=8000')
        if self.temporal_seconds < 0: raise ValueError('Invalid temporal bound')
        if self.upfront_commit_budget < 0: raise ValueError('Invalid upfront context budget')
        if len(self.rank_bounds) != 4 or any(x <= 0 for x in self.rank_bounds):
            raise ValueError('Four positive evidence normalization bounds required')
        if not self.regularizations or any(x < 0 for x in self.regularizations):
            raise ValueError('Invalid L2 candidates')
        if not self.stopping_points or any(x < 1 for x in self.stopping_points):
            raise ValueError('Invalid stopping points')
        for k in ('min_precision','min_recall','max_fpr'):
            if not 0 <= getattr(self,k) <= 1: raise ValueError(f'Invalid {k}')

    @classmethod
    def from_dict(cls, x):
        c = cls(**x); c.validate(); return c


def clean_comments(s: str) -> str:
    # Preserve strings, line numbers, and columns.
    p = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/'
    return re.sub(p, lambda m: re.sub(r'[^\n]', ' ', m[0]) if m[0].startswith(('/',)) else m[0], s)


def norm_node(n) -> str:
    try: return GEN.visit(n)
    except Exception: return ''


def ids(n) -> set[str]:
    out = set()
    def walk(a):
        if isinstance(a, c_ast.ID): out.add(a.name)
        for _, child in a.children(): walk(child)
    if n is not None: walk(n)
    return out


def name(n) -> str:
    if isinstance(n, c_ast.FuncCall): return norm_node(n.name)
    if isinstance(n, (c_ast.Decl, c_ast.ID)): return n.name or ''
    if isinstance(n, c_ast.FuncDef): return n.decl.name
    return ''


def node_span(text: str, n) -> tuple[int, int]:
    lines = [n.coord.line] if n.coord and n.coord.line>0 else []
    def walk(a):
        if a.coord and a.coord.line>0: lines.append(a.coord.line)
        for _, ch in a.children(): walk(ch)
    walk(n)
    if not lines: return (0,0)
    lo, hi = min(lines), max(lines)
    if isinstance(n, c_ast.If):
        return lo, hi
    return lo, hi


@dataclass
class Ref:
    doc: 'Document'
    node: Any
    path: str
    function: str
    ordinal: int
    start: int
    end: int
    cfg_node: int | None = None

    def fact(self) -> dict:
        return {'role': self.doc.role, 'file': self.doc.file,
                'state': self.doc.state, 'blob_sha256': self.doc.blob_hash,
                'ast_path': self.path, 'kind': type(self.node).__name__,
                'function': self.function, 'start_line': self.start, 'end_line': self.end,
                'normalized': norm_node(self.node), 'ordinal': self.ordinal}

    def stable(self):
        f = self.fact()
        return {k:f[k] for k in ('file','kind','function','normalized','ordinal')}


class CFG:
    """Structured C CFG with explicit completeness; unsupported transfers abstain."""
    def __init__(self, fn, refs):
        self.edges = {}; self.mapping = {}; self.complete = True
        self.exit = self.new(); self.entry = self.new()
        entry = self.build(fn.body, self.exit)
        self.edges[self.entry].add(entry)
        for r in refs:
            n = r.node
            if id(n) in self.mapping: r.cfg_node = self.mapping[id(n)]
        reachable = {self.entry}; changed=True
        while changed:
            changed=False
            for a in list(reachable):
                for b in self.edges.get(a,set()):
                    if b not in reachable: reachable.add(b); changed=True
        self.dom={a:({a} if a==self.entry else set(reachable)) for a in reachable}
        changed=True
        while changed:
            changed=False
            for a in sorted(reachable-{self.entry}):
                preds=[b for b in reachable if a in self.edges.get(b,set())]
                v={a}|(set.intersection(*(self.dom[b] for b in preds)) if preds else set())
                if v != self.dom[a]: self.dom[a]=v; changed=True

    def new(self):
        k=len(self.edges); self.edges[k]=set(); return k

    def map_expr(self,n,k):
        self.mapping[id(n)]=k
        for _,ch in n.children(): self.map_expr(ch,k)

    def build(self,n,nxt):
        if n is None: return nxt
        if isinstance(n,c_ast.Compound):
            cur=nxt
            for st in reversed(n.block_items or []): cur=self.build(st,cur)
            self.mapping[id(n)]=cur
            return cur
        k=self.new(); self.mapping[id(n)]=k
        if isinstance(n,c_ast.If):
            self.map_expr(n.cond,k)
            self.edges[k].update((self.build(n.iftrue,nxt),self.build(n.iffalse,nxt)))
        elif isinstance(n,c_ast.Return):
            self.map_expr(n,k); self.edges[k].add(self.exit)
        elif isinstance(n,(c_ast.For,c_ast.While,c_ast.DoWhile,c_ast.Switch,
                           c_ast.Goto,c_ast.Label,c_ast.Break,c_ast.Continue)):
            self.complete=False; self.map_expr(n,k); self.edges[k].add(nxt)
        else:
            self.map_expr(n,k); self.edges[k].add(nxt)
        return k

    def dominates(self,a,b):
        if not self.complete or a is None or b is None or b not in self.dom: return UNR
        return SAT if a in self.dom[b] else VIO


def always_exits(n):
    if isinstance(n,c_ast.Return): return True
    if isinstance(n,c_ast.Compound):
        return any(always_exits(x) for x in (n.block_items or []))
    if isinstance(n,c_ast.If): return always_exits(n.iftrue) and always_exits(n.iffalse)
    return False


class Document:
    def __init__(self,role,file,state,text,cfg):
        self.role,self.file,self.state,self.text=role,file,state,text
        self.blob_hash=hashlib.sha256(text.encode()).hexdigest()
        self.refs=[]; self.cfgs={}; self.complete=True; self.error=''
        if len(text)>cfg.chars_per_state:
            self.complete=False; self.error='context character budget exceeded'; return
        if re.search(r'^\s*#',clean_comments(text),re.M):
            self.complete=False; self.error='preprocessing/build context unavailable'; return
        try: tree=c_parser.CParser().parse(clean_comments(text),filename=file)
        except Exception as e:
            self.complete=False; self.error='C parsing unavailable: '+str(e); return
        counts={}
        def walk(n,path,fn):
            if len(self.refs)>=cfg.node_budget:
                self.complete=False; self.error='node traversal budget exceeded'; return
            if isinstance(n,c_ast.FuncDef): fn=n.decl.name
            key=(fn,type(n).__name__,norm_node(n)); ordinal=counts.get(key,0);counts[key]=ordinal+1
            lo,hi=node_span(text,n)
            self.refs.append(Ref(self,n,path,fn,ordinal,lo,hi))
            for fld,ch in n.children(): walk(ch,path+'/'+fld,fn)
        walk(tree,'root','')
        for r in self.refs:
            if isinstance(r.node,c_ast.FuncDef):
                self.cfgs[r.function]=CFG(r.node,[x for x in self.refs if x.function==r.function])


@dataclass
class Unit:
    id: str
    components: list[str]
    docs: list[Document]
    diff: str
    edits: list[dict]
    complete: bool
    metadata: dict = field(default_factory=dict)

    def select(self,s):
        docs=[d for d in self.docs if d.role==s['role'] and (not s.get('file') or d.file==s['file'])]
        complete=self.complete and bool(docs) and all(d.complete for d in docs)
        refs=[]
        for d in docs:
            for r in d.refs:
                if type(r.node).__name__!=s['kind']:continue
                if s.get('function') and r.function!=s['function']:continue
                if s.get('name') and name(r.node)!=s['name']:continue
                refs.append(r)
        refs.sort(key=lambda r:(r.doc.file,r.function,r.start,r.path))
        return refs,complete

    def touches(self,r):
        return any(e['file']==r.doc.file and e['role']==r.doc.role and
                   e['start']<=r.end and r.start<=e['end'] for e in self.edits)

    def missing(self):
        return [d.error for d in self.docs if d.error]+([] if self.complete else ['extraction incomplete'])


def parse_edits(diff):
    edits=[]; oldfile=newfile=''; old=new=0
    for line in diff.splitlines():
        if line.startswith('--- '): oldfile=line[4:].removeprefix('a/');continue
        if line.startswith('+++ '): newfile=line[4:].removeprefix('b/');continue
        m=re.match(r'@@ -(\d+)(?:,\d+)? \+(\d+)',line)
        if m: old,new=map(int,m.groups());continue
        if line.startswith('-'):
            edits.append({'file':oldfile,'role':'pre','start':old,'end':old});old+=1
        elif line.startswith('+'):
            edits.append({'file':newfile,'role':'post','start':new,'end':new});new+=1
        elif line.startswith(' '):old+=1;new+=1
    return edits


def unit_from_text(before,after,diff,cfg,unit_id='example',file='example.c'):
    docs=[Document('pre',file,'before',before,cfg),Document('post',file,'after',after,cfg)]
    return Unit(unit_id,[unit_id],docs,diff,parse_edits(diff),len(diff)<=cfg.max_diff_chars and inline_diff_matches(before,after,diff,file))


def inline_diff_matches(before,after,diff,file):
    """Check the full supplied inline transition, rather than trusting '+' tokens."""
    if not diff.strip():return before.splitlines()==after.splitlines()
    lines=diff.splitlines();old=before.splitlines();result=[];cursor=0;i=0;hunks=0
    if '--- a/'+file not in lines or '+++ b/'+file not in lines:return False
    try:
        while i<len(lines):
            line=lines[i];m=re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*',line)
            if not m:i+=1;continue
            old_start,old_count,new_start,new_count=int(m[1]),int(m[2] or 1),int(m[3]),int(m[4] or 1)
            start=old_start-1 if old_count else old_start
            if start<cursor:return False
            result.extend(old[cursor:start]);cursor=start;i+=1;removed=added=0;hunks+=1
            expected_new=new_start-1 if new_count else new_start
            if len(result)!=expected_new:return False
            while i<len(lines) and not lines[i].startswith('@@ '):
                token=lines[i];i+=1
                if token.startswith('\\ No newline'):continue
                if not token or token[0] not in (' ','-','+'):return False
                if token[0] in (' ','-'):
                    if cursor>=len(old) or old[cursor]!=token[1:]:return False
                    cursor+=1;removed+=1
                if token[0] in (' ','+'):result.append(token[1:]);added+=1
            if removed!=old_count or added!=new_count:return False
        result.extend(old[cursor:])
        return bool(hunks) and result==after.splitlines()
    except (IndexError,ValueError):return False


def validate_suite(s):
    if s.get('schema')!='obligations-1.0' or not (s.get('cwe')=='AGNOSTIC' or re.fullmatch(r'CWE-\d+',s.get('cwe',''))):
        raise ValueError('Invalid suite schema/CWE')
    if not s.get('alternatives'):raise ValueError('No repair alternatives')
    seen=set()
    for alt in s['alternatives']:
        if alt['id'] in seen:raise ValueError('Duplicate alternative')
        seen.add(alt['id']); selectors=alt['selectors']
        for key,sel in selectors.items():
            cls=getattr(c_ast,sel['kind'],None)
            if sel['role'] not in ('pre','post') or not isinstance(cls,type) or not issubclass(cls,c_ast.Node):
                raise ValueError(f'Invalid typed selector {key}')
        pids=set(); refs_by_stage={}
        for stage in STAGES:
            ps=alt['stages'].get(stage,[])
            if not ps:raise ValueError('Each stage needs mandatory predicates')
            refs_by_stage[stage]=set()
            for p in ps:
                if p['id'] in pids or p['op'] not in OPS:raise ValueError('Invalid/duplicate predicate')
                pids.add(p['id'])
                for arg in OPS[p['op']]:
                    if p.get(arg) not in selectors:raise ValueError('Unbound predicate argument')
                    refs_by_stage[stage].add(p[arg])
                if p['op'] in MANUSCRIPT_CONTRACTS:
                    contract=MANUSCRIPT_CONTRACTS[p['op']]
                    if any(not isinstance(p.get(k),str) or not p[k] or len(p[k])>100 for k in contract['parameters']):
                        raise ValueError('Missing typed manuscript-operator parameter')
                    if any(selectors[p[arg]]['kind']!=kind for arg,kind in contract['types'].items()):
                        raise ValueError('Operator/selector node type mismatch')
                    if p['op'] in ('DESTINATION_REPAIR_LINK','EDIT_DESTINATION_GUARD','EDIT_LENGTH_NORMALIZES'):
                        for arg in OPS[p['op']]:
                            role='pre' if arg in ('before','old_write') else 'post'
                            if selectors[p[arg]]['role']!=role:raise ValueError('Manuscript repair role mismatch')
                    if p['op'] in ('DIRECT_LENGTH_CONVERSION','DIRECT_LENGTH_FLOW','NORMALIZED_LENGTH_FLOW','EDIT_LENGTH_NORMALIZES') and p['normalization_type']!='unsigned char':
                        raise ValueError('This normalization contract requires unsigned char')
                if p.get('attribution') and (stage!='repair' or p['op'] not in EDIT_OPS):
                    raise ValueError('Attribution must reference an explicit edit predicate')
                if p['op'] in ('AST_REFERENCE','AST_OPERATOR','AST_CALL','AST_KIND') and not isinstance(p.get('value'),str):
                    raise ValueError('Predicate value required')
                if p['op'] in ('CORRESPONDS','EDIT_CHANGES','EDIT_GUARD_STRENGTHENS','DESTINATION_REPAIR_LINK','EDIT_DESTINATION_GUARD','EDIT_LENGTH_NORMALIZES'):
                    if selectors[p['before']]['role']!='pre' or selectors[p['after']]['role']!='post':
                        raise ValueError('Cross-state predicate role mismatch')
                if p['op'] in ('BUFFER_GUARD','BUFFER_GUARD_MISMATCH','EDIT_GUARD_STRENGTHENS'):
                    if any(not isinstance(p.get(k),str) or not re.fullmatch(r'[A-Za-z_]\w*',p[k]) for k in ('position','length','capacity','destination')):
                        raise ValueError('Guard contracts require four identifier parameters')
                if p['op']=='EDIT_GUARD_STRENGTHENS':
                    if selectors[p['sink_before']]['role']!='pre' or selectors[p['sink_after']]['role']!='post':
                        raise ValueError('Sink role mismatch')
                if p.get('attribution') and p['op'] not in MITIGATION_OPS:
                    raise ValueError('Attribution requires a mitigation operator, not edit overlap alone')
        if any(selectors[k]['role']!='pre' for k in refs_by_stage['pre']):
            raise ValueError('Precondition requires pre-state evidence')
        if any(selectors[k]['role']!='post' for k in refs_by_stage['safety']):
            raise ValueError('Safety requires post-state evidence')
        if not any(p['op'] in EDIT_OPS for p in alt['stages']['repair']):
            raise ValueError('Repair must require an explicit edit')
        if not any(p.get('attribution') for p in alt['stages']['repair']):
            raise ValueError('Composite attribution contract required')
    rules=s.get('rejection_rules',[])
    if not isinstance(rules,list):raise ValueError('Rejection rules must be a list')
    rule_ids=set()
    for rule in rules:
        if set(rule)!={'id','alternative','when'} or not isinstance(rule['id'],str) or not rule['id'] or rule['id'] in rule_ids:
            raise ValueError('Invalid/duplicate rejection rule')
        rule_ids.add(rule['id'])
        alt=next((a for a in s['alternatives'] if a['id']==rule['alternative']),None)
        if alt is None or not isinstance(rule['when'],list) or not rule['when']:
            raise ValueError('Rejection rule requires an alternative and conditions')
        seen_conditions=set()
        for condition in rule['when']:
            if set(condition)!={'stage','predicate','status'} or condition['stage'] not in STAGES or condition['status'] not in (SAT,VIO):
                raise ValueError('Rejection rules require decisive predicate outcomes')
            key=(condition['stage'],condition['predicate'])
            if key in seen_conditions or not any(p['id']==condition['predicate'] for p in alt['stages'][condition['stage']]):
                raise ValueError('Invalid/duplicate rejection predicate reference')
            seen_conditions.add(key)
        if not any(c['status']==VIO for c in rule['when']):
            raise ValueError('A rejection rule requires contradictory code evidence')
    return s


def buffer_guard(p,guard,sink):
    """Exact scoped memcpy guard relation, not an overflow/alias safety proof.

    Establishes the encoded AST bound and control-flow relation. Arithmetic
    domains, object sizes and alias assumptions require additional obligations.
    """
    if guard.doc is not sink.doc or guard.function!=sink.function:return VIO
    g,z=guard.node,sink.node
    if not isinstance(g,c_ast.If) or not isinstance(z,c_ast.FuncCall) or name(z)!='memcpy':return VIO
    args=z.args.exprs if isinstance(z.args,c_ast.ExprList) else []
    if len(args)!=3:return VIO
    dst,size=args[0],args[2]
    if not (isinstance(dst,c_ast.BinaryOp) and dst.op=='+' and
            norm_node(dst.left)==p['destination'] and norm_node(dst.right)==p['position'] and
            norm_node(size)==p['length']):return VIO
    cond=g.cond
    if not (isinstance(cond,c_ast.BinaryOp) and cond.op in ('>','>=') and
            norm_node(cond.right)==p['capacity'] and isinstance(cond.left,c_ast.BinaryOp) and
            cond.left.op=='+' and sorted((norm_node(cond.left.left),norm_node(cond.left.right)))==
            sorted((p['position'],p['length']))):return VIO
    cfg=guard.doc.cfgs.get(guard.function)
    if not cfg or not cfg.complete:return UNR
    dom=cfg.dominates(guard.cfg_node,sink.cfg_node)
    if dom!=SAT:return dom
    return SAT if always_exits(g.iftrue) else VIO


def guard_mismatch(p,g,z):
    if g.doc is not z.doc or not g.function or g.function!=z.function:return VIO
    if not isinstance(g.node,c_ast.If) or not isinstance(z.node,c_ast.FuncCall) or name(z.node)!='memcpy':return VIO
    args=z.node.args.exprs if isinstance(z.node.args,c_ast.ExprList) else []
    if len(args)!=3:return VIO
    dst=args[0];cond=g.node.cond
    if not (isinstance(dst,c_ast.BinaryOp) and dst.op=='+' and norm_node(dst.left)==p['destination'] and
            norm_node(dst.right)==p['position'] and norm_node(args[2])==p['length']):return VIO
    if not (isinstance(cond,c_ast.BinaryOp) and cond.op in ('>','>=') and norm_node(cond.right)==p['capacity'] and
            isinstance(cond.left,c_ast.BinaryOp) and cond.left.op=='+'):return UNR
    operands=[norm_node(cond.left.left),norm_node(cond.left.right)]
    if p['length'] not in operands:return UNR
    cfg=g.doc.cfgs.get(g.function)
    if not cfg or not cfg.complete:return UNR
    domination=cfg.dominates(g.cfg_node,z.cfg_node)
    if domination!=SAT:return domination
    if not always_exits(g.node.iftrue):return VIO
    return SAT if p['position'] not in operands else VIO


class StructuredForCFG(CFG):
    """Separate, conservative CFG profile for structured for loops.

    Does not mutate the default CFG or its reference mappings. Break, continue,
    goto, labels, while, switch and do/while remain unsupported in this profile.
    """
    def build(self,n,nxt):
        if isinstance(n,c_ast.For):
            k=self.new();self.mapping[id(n)]=k
            if n.cond is not None:self.map_expr(n.cond,k)
            increment=self.build(n.next,k) if n.next is not None else k
            body=self.build(n.stmt,increment)
            self.edges[k].add(body)
            if n.cond is not None:self.edges[k].add(nxt)
            return self.build(n.init,k) if n.init is not None else k
        return super().build(n,nxt)


def scoped_dominates(a,z):
    if a.doc is not z.doc or not a.function or a.function!=z.function:return VIO
    functions=[r for r in a.doc.refs if isinstance(r.node,c_ast.FuncDef) and r.function==a.function]
    if len(functions)!=1 or not a.doc.complete:return UNR
    graph=StructuredForCFG(functions[0].node,[])
    return graph.dominates(graph.mapping.get(id(a.node)),graph.mapping.get(id(z.node)))


def expression(n,text):return norm_node(n)==text


def counted_loop(n,index,bound):
    return (isinstance(n,c_ast.For) and isinstance(n.init,c_ast.Assignment) and n.init.op=='=' and
            expression(n.init.lvalue,index) and expression(n.init.rvalue,'0') and
            isinstance(n.cond,c_ast.BinaryOp) and n.cond.op=='<' and expression(n.cond.left,index) and
            expression(n.cond.right,bound) and isinstance(n.next,c_ast.UnaryOp) and
            n.next.op in ('p++','++') and expression(n.next.expr,index))


def destination_guard(p,g,z,post):
    if g.doc is not z.doc or not g.function or g.function!=z.function:return VIO
    cond=g.node.cond if isinstance(g.node,c_ast.If) else None
    if not post:
        if not isinstance(cond,c_ast.UnaryOp) or cond.op!='!':return VIO
        cond=cond.expr
    if not (isinstance(cond,c_ast.BinaryOp) and cond.op in (('>=','>') if post else ('<',)) and
            expression(cond.right,p['capacity']) and isinstance(cond.left,c_ast.BinaryOp) and cond.left.op=='+' and
            expression(cond.left.left,p['position'] if post else p['source_position']) and
            isinstance(cond.left.right,c_ast.BinaryOp) and cond.left.right.op=='*' and
            expression(cond.left.right.left,p['count']) and expression(cond.left.right.right,p['width'])):return VIO
    if not always_exits(g.node.iftrue):return VIO
    dominance=scoped_dominates(g,z)
    if dominance!=SAT:return dominance
    if not post:
        n=z.node
        if not (isinstance(n,c_ast.Assignment) and n.op=='=' and isinstance(n.lvalue,c_ast.ArrayRef) and
                expression(n.lvalue.name,p['destination']) and expression(n.lvalue.subscript,p['position']) and
                isinstance(n.rvalue,c_ast.ArrayRef) and expression(n.rvalue.name,p['source']) and
                isinstance(n.rvalue.subscript,c_ast.BinaryOp) and n.rvalue.subscript.op=='+' and
                expression(n.rvalue.subscript.left,p['source_position']) and expression(n.rvalue.subscript.right,p['inner_iterator'])):return VIO
        for candidate in g.doc.refs:
            if candidate.node is g.node or candidate.function!=g.function or not isinstance(candidate.node,c_ast.If):continue
            c=candidate.node.cond
            if p['position'] not in ids(c) or p['capacity'] not in ids(c):continue
            protected=scoped_dominates(candidate,z)
            if protected==UNR:return UNR
            if protected!=SAT:continue
            if (isinstance(c,c_ast.BinaryOp) and c.op in ('>=','>') and expression(c.right,p['capacity']) and
                isinstance(c.left,c_ast.BinaryOp) and c.left.op=='+' and expression(c.left.left,p['position']) and
                isinstance(c.left.right,c_ast.BinaryOp) and c.left.right.op=='*' and
                expression(c.left.right.left,p['count']) and expression(c.left.right.right,p['width']) and always_exits(candidate.node.iftrue)):
                return VIO
            return UNR
        return SAT
    n=z.node;args=n.args.exprs if isinstance(n,c_ast.FuncCall) and isinstance(n.args,c_ast.ExprList) else []
    if not (isinstance(n,c_ast.FuncCall) and name(n)=='memcpy' and len(args)==3 and
            isinstance(args[0],c_ast.BinaryOp) and args[0].op=='+' and expression(args[0].left,p['destination']) and
            expression(args[0].right,p['position']) and isinstance(args[1],c_ast.BinaryOp) and args[1].op=='+' and
            expression(args[1].left,p['source']) and expression(args[1].right,p['source_position']) and expression(args[2],p['width'])):return VIO
    loops=[r for r in z.doc.refs if r.function==z.function and isinstance(r.node,c_ast.For) and
           z.path.startswith(r.path+'/stmt')]
    if len(loops)!=1:return UNR
    loop=loops[0].node
    if not counted_loop(loop,p['iterator'],p['count']):return VIO
    body=loop.stmt.block_items if isinstance(loop.stmt,c_ast.Compound) else []
    if len(body)!=2 or body[0] is not n:return UNR
    step=body[1]
    if not (isinstance(step,c_ast.Assignment) and step.op=='+=' and expression(step.lvalue,p['position']) and
            expression(step.rvalue,p['width'])):return VIO
    return SAT


def cast_type(n):return norm_node(n.to_type) if isinstance(n,c_ast.Cast) else None


def length_conversion(p,assignment,normalized):
    n=assignment.node
    if not isinstance(n,c_ast.Assignment) or n.op!='=' or not expression(n.lvalue,p['variable']):return VIO
    value=n.rvalue
    if cast_type(value)!=p['outer_type']:return VIO
    value=value.expr
    if normalized:
        if cast_type(value)!=p['normalization_type']:return VIO
        value=value.expr
    if not (isinstance(value,c_ast.FuncCall) and name(value)==p['producer'] and
            isinstance(value.args,c_ast.ExprList) and len(value.args.exprs)==1 and expression(value.args.exprs[0],p['image'])):return VIO
    return SAT


def normalized_length_flow(p,a,arithmetic,sink,normalized=True):
    status=length_conversion(p,a,normalized)
    if status!=SAT:return status
    if a.doc is not arithmetic.doc or a.doc is not sink.doc or not a.function or not a.function==arithmetic.function==sink.function:return VIO
    n=arithmetic.node
    if not (isinstance(n,c_ast.Assignment) and n.op=='+=' and expression(n.lvalue,p['accumulator']) and
            isinstance(n.rvalue,c_ast.BinaryOp) and n.rvalue.op=='+' and
            expression(n.rvalue.left,p['variable']) and expression(n.rvalue.right,'1')):return VIO
    n=sink.node;args=n.args.exprs if isinstance(n,c_ast.FuncCall) and isinstance(n.args,c_ast.ExprList) else []
    if name(n)!=p['consumer'] or len(args)!=3 or not expression(args[0],p['image']):return VIO
    size=args[1]
    if cast_type(size)!=p['size_type']:return VIO
    size=size.expr
    if not (isinstance(size,c_ast.UnaryOp) and size.op=='p++' and expression(size.expr,p['variable'])):return VIO
    for left,right in ((a,arithmetic),(arithmetic,sink)):
        status=scoped_dominates(left,right)
        if status!=SAT:return status
    # Straight scoped def-use chain. Unknown aliasing/side effects abstain;
    # any additional assignment to the required local value rejects this witness.
    locals_=[r for r in a.doc.refs if r.function==a.function and isinstance(r.node,c_ast.Decl) and r.node.name==p['variable']]
    if len(locals_)!=1:return UNR
    for r in a.doc.refs:
        if r.function!=a.function or r.node is a.node:continue
        if isinstance(r.node,c_ast.Assignment) and expression(r.node.lvalue,p['variable']):return UNR
        if isinstance(r.node,c_ast.UnaryOp) and expression(r.node.expr,p['variable']):
            if r.node.op=='&':return UNR
            if r.node.op in ('p++','++','p--','--') and not r.path.startswith(sink.path+'/'):return UNR
    return SAT


def predicate(p,b,u):
    op=p['op']; rs=[b.get(p[k]) for k in OPS[op]]
    if any(r is None for r in rs):return UNR,'binding unavailable'
    r=rs[0]; n=r.node
    if op=='AST_KIND':ok=type(n).__name__==p['value']
    elif op=='AST_REFERENCE':ok=p['value'] in ids(n)
    elif op=='AST_OPERATOR':ok=getattr(n,'op',None)==p['value']
    elif op=='AST_CALL':ok=isinstance(n,c_ast.FuncCall) and name(n)==p['value']
    elif op=='AST_CONTAINS':ok=rs[0].doc is rs[1].doc and rs[1].path.startswith(rs[0].path+'/')
    elif op=='AST_SAME_FUNCTION':ok=rs[0].doc is rs[1].doc and bool(r.function) and r.function==rs[1].function
    elif op=='CFG_DOMINATES':
        a,z=rs
        if a.doc is not z.doc or not a.function or a.function!=z.function:return VIO,'different function/state'
        cfg=a.doc.cfgs.get(a.function)
        return (cfg.dominates(a.cfg_node,z.cfg_node),'scoped structured CFG') if cfg else (UNR,'CFG unavailable')
    elif op=='CFG_TRUE_BRANCH_EXITS':
        cfg=r.doc.cfgs.get(r.function)
        if not cfg or not cfg.complete:return UNR,'CFG unavailable/incomplete'
        ok=isinstance(n,c_ast.If) and always_exits(n.iftrue)
    elif op=='CORRESPONDS':
        a,z=rs
        ok=a.doc.file==z.doc.file and bool(a.function) and a.function==z.function and type(a.node)==type(z.node)
        # Exact call identifier / declaration correspondence; ambiguity is retained
        # in witness selection and checked by compatibility, never guessed.
        if isinstance(a.node,(c_ast.FuncCall,c_ast.Decl,c_ast.ID)):
            ok=ok and name(a.node)==name(z.node)
        elif ok:
            left=[x for x in a.doc.refs if x.function==a.function and type(x.node)==type(a.node)]
            right=[x for x in z.doc.refs if x.function==z.function and type(x.node)==type(z.node)]
            if len(left)!=1 or len(right)!=1:
                return UNR,'ambiguous structural correspondence'
    elif op=='EDIT_CHANGES':
        a,z=rs
        if not u.complete:return UNR,'diff extraction incomplete'
        ok=(a.doc.file==z.doc.file and a.function==z.function and type(a.node)==type(z.node)
            and norm_node(a.node)!=norm_node(z.node) and u.touches(z))
    elif op=='EDIT_INTRODUCES':
        if not u.complete:return UNR,'diff extraction incomplete'
        pre=[d for d in u.docs if d.role=='pre' and d.file==r.doc.file]
        if not pre or not all(d.complete for d in pre):return UNR,'pre-state enumeration incomplete'
        ok=u.touches(r) and not any(type(x.node)==type(n) and x.function==r.function and norm_node(x.node)==norm_node(n)
                                   for d in pre for x in d.refs)
    elif op=='BUFFER_GUARD':return buffer_guard(p,rs[0],rs[1]),'encoded destination bound and control-flow relation'
    elif op=='BUFFER_GUARD_MISMATCH':
        return guard_mismatch(p,*rs),'encoded guard/write mismatch, not proof of unrestricted vulnerability'
    elif op=='EDIT_GUARD_STRENGTHENS':
        a,z,old_sink,new_sink=rs
        if not u.complete:return UNR,'diff extraction incomplete'
        if not (a.doc.file==z.doc.file and a.function==z.function and
                old_sink.doc.file==new_sink.doc.file and old_sink.function==new_sink.function and
                norm_node(old_sink.node)==norm_node(new_sink.node) and u.touches(z)):
            return VIO,'no qualifying guard edit linked to the preserved write'
        post=buffer_guard(p,z,new_sink)
        if post!=SAT:return post,'post guard does not establish encoded mitigation'
        pre=guard_mismatch(p,a,old_sink)
        return pre,'changed mismatching guard into destination bound'
    elif op=='DESTINATION_GUARD_MISMATCH':return destination_guard(p,*rs,False),'source-position guard paired with destination-position write'
    elif op=='DESTINATION_COPY_GUARDED':return destination_guard(p,*rs,True),'destination guard dominates the counted memcpy loop'
    elif op=='DESTINATION_REPAIR_LINK':
        a,z,old,new=rs
        if not (a.doc.file==z.doc.file==old.doc.file==new.doc.file and a.function==z.function==old.function==new.function):return VIO,'incompatible repair scope'
        return conjunction([destination_guard(p,a,old,False),destination_guard(p,z,new,True)]),'linked source-check to destination-check/write transformation'
    elif op=='EDIT_DESTINATION_GUARD':
        a,z,new=rs
        if not u.complete:return UNR,'diff extraction incomplete'
        if not (a.doc.file==z.doc.file and a.function==z.function and u.touches(a) and u.touches(z) and norm_node(a.node)!=norm_node(z.node)):
            return VIO,'no actual seed guard transformation'
        cond=a.node.cond if isinstance(a.node,c_ast.If) else None
        if not (isinstance(cond,c_ast.UnaryOp) and cond.op=='!' and isinstance(cond.expr,c_ast.BinaryOp) and
                cond.expr.op=='<' and expression(cond.expr.right,p['capacity']) and isinstance(cond.expr.left,c_ast.BinaryOp) and
                cond.expr.left.op=='+' and expression(cond.expr.left.left,p['source_position']) and
                isinstance(cond.expr.left.right,c_ast.BinaryOp) and cond.expr.left.right.op=='*' and
                expression(cond.expr.left.right.left,p['count']) and expression(cond.expr.left.right.right,p['width']) and always_exits(a.node.iftrue)):
            return VIO,'pre guard is not the selected source-position bound'
        return destination_guard(p,z,new,True),'seed replaces source-position bound with destination mitigation'
    elif op=='DIRECT_LENGTH_CONVERSION':return length_conversion(p,rs[0],False),'selected length has direct producer-to-size conversion'
    elif op=='DIRECT_LENGTH_FLOW':return normalized_length_flow(p,*rs,False),'direct converted length reaches arithmetic and ReadBlob size'
    elif op=='NORMALIZED_LENGTH_FLOW':return normalized_length_flow(p,*rs),'normalized local length reaches arithmetic and ReadBlob size'
    elif op=='EDIT_LENGTH_NORMALIZES':
        a,z=rs
        if not u.complete:return UNR,'diff extraction incomplete'
        if not (a.doc.file==z.doc.file and a.function==z.function and u.touches(a) and u.touches(z)):return VIO,'no corresponding actual length edit'
        return conjunction([length_conversion(p,a,False),length_conversion(p,z,True)]),'actual seed inserts unsigned-char conversion for the same length'
    else:raise ValueError(op)
    return (SAT if ok else VIO),'typed predicate evaluated'


def atom(p,stage,alt,b,u,status,reason):
    facts=[b[p[k]].fact() for k in OPS[p['op']] if b.get(p[k]) is not None]
    stable=[b[p[k]].stable() for k in OPS[p['op']] if b.get(p[k]) is not None]
    # IDs exclude raw line numbers and replay commit labels.
    key=digest({'alternative':alt,'stage':stage,'predicate':p['id'],'op':p['op'],
                'roles':[f['role'] for f in facts],'facts':stable,'status':status})
    return {'key':key,'alternative':alt,'stage':stage,'predicate':p['id'],'op':p['op'],
            'status':status,'polarity':'support' if status==SAT else 'contradiction' if status==VIO else 'missing',
            'facts':facts,'arguments':{k:(b[p[k]].fact() if b.get(p[k]) is not None else None) for k in OPS[p['op']]},'reason':reason}


def execute(s,u,cfg):
    alternatives=[]; all_complete=True
    for alt in s['alternatives']:
        sels=alt['selectors']; keys=sorted(sels); pools=[]; completeness={}
        for k in keys:
            values,done=u.select(sels[k]);pools.append(values or [None]);completeness[k]=done
        complete=all(completeness.values());ws=[]; exhausted=False
        for idx,values in enumerate(itertools.product(*pools)):
            if idx>=cfg.witness_budget:exhausted=True;break
            b=dict(zip(keys,values));stage_records={}
            for stage in STAGES:
                aa=[];ss=[]
                for p in alt['stages'][stage]:
                    missing=[p[k] for k in OPS[p['op']] if b[p[k]] is None]
                    if missing:
                        st=VIO if any(completeness[k] for k in missing) else UNR
                        reason='complete selector enumeration has no match' if st==VIO else 'selector enumeration incomplete'
                    else:st,reason=predicate(p,b,u)
                    aa.append(atom(p,stage,alt['id'],b,u,st,reason));ss.append(st)
                stage_records[stage]={'status':conjunction(ss),'atoms':aa}
            ws.append({'bindings':{k:(v.fact() if v else None) for k,v in b.items()},'stages':stage_records,
                       'compatible':conjunction([stage_records[k]['status'] for k in STAGES])==SAT})
        complete=complete and not exhausted;all_complete=all_complete and complete
        stages={k:existential([w['stages'][k]['status'] for w in ws],complete) for k in STAGES}
        alternatives.append({'id':alt['id'],'complete':complete,'selectors_complete':completeness,
                             'witnesses':ws,'statuses':stages})
    statuses={k:existential([a['statuses'][k] for a in alternatives],all_complete) for k in STAGES}
    unresolved=sorted({a['id']+':'+st+':'+p['predicate'] for a in alternatives for w in a['witnesses'] for st in STAGES
                       for p in w['stages'][st]['atoms'] if statuses[st]==UNR and p['status']==UNR})
    # Stage-level uncertainty with no atom (e.g. traversal budget) remains explicit.
    unresolved+=['stage:'+k for k,v in statuses.items() if v==UNR and not any(':'+k+':' in x for x in unresolved)]
    return {'unit':u.id,'statuses':statuses,'alternatives':alternatives,
            'unresolved':sorted(set(unresolved)),'complete':all_complete}


def compatible_witness(output,required_stages=STAGES):
    for alt in output['alternatives']:
        for w in alt['witnesses']:
            if all(w['stages'][k]['status']==SAT for k in required_stages) and all(w['stages'][k]['status']!=VIO for k in STAGES):
                return alt['id'],w
    return None,None


def all_atoms(output):
    return [a for alt in output['alternatives'] for w in alt['witnesses']
            for st in STAGES for a in w['stages'][st]['atoms']]


def support_keys(output):
    return {a['key'] for a in all_atoms(output) if a['status']==SAT}


def bind_fact(f,u):
    if f is None:return None
    matches=[r for d in u.docs if d.role==f['role'] and d.file==f['file'] for r in d.refs
             if type(r.node).__name__==f['kind'] and r.function==f['function'] and norm_node(r.node)==f['normalized']]
    return matches[0] if len(matches)==1 else None


def confirm_and_attribute(s,output,seed,group,cfg):
    aid,w=compatible_witness(output)
    if not w:return {'confirmation':UNR,'attribution':UNR,'alternative':None,'atoms':[], 'missing':['no compatible group witness']}
    alt=next(a for a in s['alternatives'] if a['id']==aid)
    b={k:bind_fact(f,seed) for k,f in w['bindings'].items()}
    aa=[];cs=[]
    for p in alt['stages']['safety']:
        st,reason=predicate(p,b,seed);cs.append(st);aa.append(atom(p,'safety',aid,b,seed,st,reason))
    ab=dict(b)
    for p in alt['stages']['repair']:
        if p.get('attribution') and p['op'] in ('EDIT_CHANGES','EDIT_GUARD_STRENGTHENS') and ab.get(p['before']) is None and ab.get(p['after']) is not None:
            z=ab[p['after']];sel=alt['selectors'][p['before']]
            matches,done=seed.select(sel)
            matches=[r for r in matches if r.doc.file==z.doc.file and r.function==z.function]
            ab[p['before']]=matches[0] if done and len(matches)==1 else None
    ats=[]
    for p in alt['stages']['repair']:
        if p.get('attribution'):
            st,reason=predicate(p,ab,seed);ats.append(st);aa.append(atom(p,'repair',aid,ab,seed,st,reason))
    return {'confirmation':conjunction(cs),'attribution':conjunction(ats),'alternative':aid,'atoms':aa,
            'missing':[a['reason'] for a in aa if a['status']==UNR]}


def validate_evidence(s,u,output,seed=None,records=None,required_stages=STAGES):
    """Contract validation only: no weakness predicates are reexecuted here."""
    docs=u.docs+(seed.docs if seed else [])
    refs={(d.role,d.file,d.state,r.path):r.fact() for d in docs for r in d.refs}
    predicates={(a['id'],st,p['id']):p for a in s['alternatives'] for st in STAGES for p in a['stages'][st]}
    valid={};failed=[]
    def check(a):
        p=predicates.get((a['alternative'],a['stage'],a['predicate']))
        ok=p is not None and a['op']==p['op'] and a['status'] in (SAT,VIO,UNR)
        expected='support' if a['status']==SAT else 'contradiction' if a['status']==VIO else 'missing'
        ok=ok and a['polarity']==expected
        for f in a['facts']:
            actual=refs.get((f['role'],f['file'],f['state'],f['ast_path']))
            ok=ok and actual==f and f['start_line']>0
        if p is not None:
            selectors=next(x for x in s['alternatives'] if x['id']==a['alternative'])['selectors']
            arguments=a.get('arguments',{})
            ok=ok and set(arguments)==set(OPS[a['op']])
            facts=[arguments.get(k) for k in OPS[a['op']] if arguments.get(k) is not None]
            ok=ok and facts==a['facts']
            for arg,f in arguments.items():
                if f is not None:
                    sel=selectors[p[arg]]
                    ok=ok and f['role']==sel['role'] and f['kind']==sel['kind']
                    ok=ok and (not sel.get('file') or f['file']==sel['file']) and (not sel.get('function') or f['function']==sel['function'])
            stable=[{k:f[k] for k in ('file','kind','function','normalized','ordinal')} for f in facts]
            expected_key=digest({'alternative':a['alternative'],'stage':a['stage'],'predicate':a['predicate'],'op':a['op'],
                                 'roles':[f['role'] for f in facts],'facts':stable,'status':a['status']})
            ok=ok and a['key']==expected_key
        if a['status']==SAT:ok=ok and len(a['facts'])==len(OPS[a['op']])
        if ok:valid[a['key']]=a
        else:failed.append(a['key'])
        return ok
    for a in all_atoms(output):check(a)
    seed_refs={(d.role,d.file,d.state,r.path):r.fact() for d in (seed.docs if seed else []) for r in d.refs}
    for a in (records or {}).get('atoms',[]):
        check(a)
        if any(seed_refs.get((f['role'],f['file'],f['state'],f['ast_path']))!=f for f in a['facts']):
            failed.append('actual_state:'+a['key'])
    for alt in output['alternatives']:
        suite_alt=next(x for x in s['alternatives'] if x['id']==alt['id'])
        selector_checks={k:u.select(sel) for k,sel in suite_alt['selectors'].items()}
        expected_completeness={k:v[1] for k,v in selector_checks.items()}
        total=math.prod(max(1,len(v[0])) for v in selector_checks.values())
        if alt['selectors_complete']!=expected_completeness or alt['complete']!=(all(expected_completeness.values()) and len(alt['witnesses'])==total):
            failed.append('enumeration:'+alt['id'])
        for w in alt['witnesses']:
            for st,rec in w['stages'].items():
                expected=[p['id'] for p in next(x for x in s['alternatives'] if x['id']==alt['id'])['stages'][st]]
                for a in rec['atoms']:
                    p=predicates[(a['alternative'],a['stage'],a['predicate'])]
                    if a.get('arguments')!={k:w['bindings'].get(p[k]) for k in OPS[p['op']]}:
                        failed.append('binding:'+a['key'])
                if [a['predicate'] for a in rec['atoms']]!=expected or conjunction([a['status'] for a in rec['atoms']])!=rec['status']:
                    failed.append('reporting:'+alt['id']+':'+st)
            if w['compatible']!=(conjunction([w['stages'][k]['status'] for k in STAGES])==SAT):failed.append('compatibility:'+alt['id'])
        for st in STAGES:
            expected=existential([w['stages'][st]['status'] for w in alt['witnesses']],alt['complete'])
            if alt['statuses'][st]!=expected:failed.append('aggregation:'+alt['id']+':'+st)
    for st in STAGES:
        expected=existential([a['statuses'][st] for a in output['alternatives']],output['complete'])
        if output['statuses'][st]!=expected:failed.append('stage:'+st)
    aid,w=compatible_witness(output,required_stages)
    positive=bool(w) and not failed and all(a['key'] in valid for st in STAGES for a in w['stages'][st]['atoms'])
    def exclusion_valid(st):
        if output['statuses'][st]!=VIO or not output['complete']:return False
        for alt in output['alternatives']:
            if not alt['complete'] or 'enumeration:'+alt['id'] in failed:return False
            for ww in alt['witnesses']:
                aa=ww['stages'][st]['atoms']
                if ww['stages'][st]['status']!=VIO:return False
                if not any(a['status']==VIO and a['key'] in valid and 'binding:'+a['key'] not in failed for a in aa):return False
        return True
    negative=any(exclusion_valid(st) for st in STAGES)
    if records:
        selected_alt=next((x for x in s['alternatives'] if x['id']==records.get('alternative')),None)
        if not selected_alt:failed.append('confirmation_alternative')
        else:
            ca=[a for a in records['atoms'] if a['stage']=='safety']
            at=[a for a in records['atoms'] if a['stage']=='repair']
            expected_c=[p['id'] for p in selected_alt['stages']['safety']]
            expected_a=[p['id'] for p in selected_alt['stages']['repair'] if p.get('attribution')]
            if [a['predicate'] for a in ca]!=expected_c or conjunction([a['status'] for a in ca])!=records['confirmation']:failed.append('confirmation_reporting')
            if [a['predicate'] for a in at]!=expected_a or conjunction([a['status'] for a in at])!=records['attribution']:failed.append('attribution_reporting')
        if failed:positive=False
    triggered=[]
    for rule in s.get('rejection_rules',[]):
        alt=next(a for a in output['alternatives'] if a['id']==rule['alternative'])
        for witness in alt['witnesses']:
            selected=[]
            for condition in rule['when']:
                record=witness['stages'][condition['stage']]
                aa=[a for a in record['atoms'] if a['predicate']==condition['predicate']]
                if len(aa)!=1:break
                a=aa[0]
                reporting='reporting:'+alt['id']+':'+condition['stage']
                if (a['status']!=condition['status'] or a['key'] not in valid
                    or 'binding:'+a['key'] in failed or reporting in failed
                    or not a['facts'] or any(f is None for f in a['arguments'].values())):break
                selected.append(a['key'])
            if len(selected)==len(rule['when']):
                triggered.append({'id':rule['id'],'alternative':alt['id'],'atom_keys':selected})
                break
    return {'acceptance_valid':positive,'rejection_valid':negative or bool(triggered),
            'rejection_rule_valid':bool(triggered),'rejection_rules':triggered,
            'atoms':list(valid.values()),'failed':sorted(set(failed)),
            'missing':u.missing()+output['unresolved']+(records or {}).get('missing',[])}


def assign_verdict(output,validation,composite=False,records=None,seed_rejection=False,required_stages=STAGES):
    a=seed_rejection if composite else VIO in output['statuses'].values() or validation.get('rejection_rule_valid',False)
    if validation['rejection_valid'] and a:return REJ
    compatible=compatible_witness(output,required_stages)[1] is not None
    if composite:compatible=compatible and records is not None and records['confirmation']==SAT and records['attribution']==SAT
    if validation['acceptance_valid'] and all(output['statuses'][k]==SAT for k in required_stages) and compatible and not a:return VER
    return INC


def features(s,u,output,validation,cfg):
    transition_keys={a['key'] for a in all_atoms(output)}
    atoms={a['key']:a for a in validation['atoms'] if a['key'] in transition_keys}
    aid,w=compatible_witness(output)
    support=[a for a in atoms.values() if a['status']==SAT]
    stages=[min(sum(a['stage']==st for a in support)/cfg.rank_bounds[i],1.) for i,st in enumerate(STAGES)]
    if w is None:
        first=next(((a['id'],ww) for a in output['alternatives'] for ww in a['witnesses']),None)
        aid,w=first if first else (None,None)
    required=[a for st in STAGES for a in w['stages'][st]['atoms']] if w else []
    corr=[a for a in required if a['op'] in CORRESPONDENCE_OPS]
    c_corr=sum(a['key'] in atoms and atoms[a['key']]['status']==SAT for a in corr)/len(corr) if corr else 0.
    selected_alt=next((a for a in s['alternatives'] if a['id']==aid),None)
    required_keys={p[arg] for st in STAGES for p in selected_alt['stages'][st] for arg in OPS[p['op']]} if selected_alt else set()
    references={k:f for k,f in w['bindings'].items() if k in required_keys} if w else {}
    validated_facts=[f for a in atoms.values() for f in a['facts']]
    c_ctx=sum(f is not None and f in validated_facts for f in references.values())/len(references) if references else 0.
    distances=[]
    for a in support:
        for f in a['facts']:
            for e in u.edits:
                if e['file']==f['file'] and e['role']==f['role']:
                    distances.append(max(0,e['start']-f['end_line'],f['start_line']-e['end']))
    c_prox=1-min(min(distances)/cfg.max_line_distance,1.) if distances else 0.
    rejection_keys={k for rule in validation.get('rejection_rules',[]) for k in rule['atom_keys']}
    contra=[a for a in atoms.values() if a['status']==VIO and a['key'] not in rejection_keys] if VIO not in output['statuses'].values() else []
    return stages+[c_corr,c_prox,c_ctx,min(len(contra)/cfg.rank_bounds[3],1.)]

class Repository:
    def __init__(self,path,cfg):
        self.path=Path(path).resolve();self.cfg=cfg;self.cache={};self.tree_cache={};self.graph_cache={}
        self.git('rev-parse','--git-dir')

    def git(self,*args,check=True,env=None):
        p=subprocess.run(['git','-C',str(self.path),*map(str,args)],capture_output=True,text=True,
                         env=env,timeout=60)
        if check and p.returncode:raise ValueError('Git operation failed: '+p.stderr.strip())
        return p.stdout

    def allowed(self,path):
        return any(path.endswith(s) for s in self.cfg.language_suffixes) and any(path.startswith(p) for p in self.cfg.path_prefixes)

    def candidates(self):
        if hasattr(self,'_candidate_cache'):return self._candidate_cache
        raw=self.git('log','--format=%H%x09%P%x09%ct','-n',str(self.cfg.history_limit))
        out=[]
        for line in raw.splitlines():
            cid,parents,stamp=line.split('\t');parents=parents.split();stamp=int(stamp)
            if not parents:continue
            if len(parents)>1 and not self.cfg.include_merges:continue
            if self.cfg.history_start is not None and stamp<self.cfg.history_start:continue
            if self.cfg.history_end is not None and stamp>self.cfg.history_end:continue
            for parent in parents if self.cfg.include_merges else parents[:1]:
                files=self.git('diff','--name-only',parent,cid,'--').splitlines()
                if any(self.allowed(f) for f in files):out.append({'commit':cid,'parent':parent,'time':stamp,'files':files})
        self._candidate_cache=sorted(out,key=lambda x:(x['time'],x['commit'],x['parent']))
        return self._candidate_cache

    @staticmethod
    def identity(item):return item['commit']+':'+item['parent']

    def ancestor(self,a,b):
        p=subprocess.run(['git','-C',str(self.path),'merge-base','--is-ancestor',a,b],capture_output=True,timeout=30)
        if p.returncode not in (0,1):raise ValueError('Cannot determine ancestry')
        return p.returncode==0

    def state_source(self,state,file):
        p=subprocess.run(['git','-C',str(self.path),'show',state+':'+file],capture_output=True,timeout=30)
        if p.returncode:return ''
        return p.stdout.decode('utf-8',errors='replace')

    def extract(self,base,end,unitid,components,metadata,auxiliary_files=()):
        diff=self.git('diff','--no-ext-diff','--no-textconv','--binary',base,end,'--')
        changed=sorted(f for f in self.git('diff','--name-only',base,end,'--').splitlines() if self.allowed(f))
        files=changed+sorted((set(self.cfg.dependency_files)|set(auxiliary_files))-set(changed))
        complete=len(files)<=self.cfg.max_files and len(diff)<=self.cfg.max_diff_chars
        docs=[]
        for role,state in (('pre',base),('post',end)):
            remaining=self.cfg.chars_per_state
            for f in files[:self.cfg.max_files]:
                text=self.state_source(state,f)
                if len(text)>remaining:
                    d=Document(role,f,state,'',self.cfg);d.complete=False;d.error='aggregate source-state budget exceeded'
                    d.blob_hash=hashlib.sha256(text.encode()).hexdigest();docs.append(d);complete=False
                else:
                    docs.append(Document(role,f,state,text,self.cfg));remaining-=len(text)
        return Unit(unitid,components,docs,diff[:self.cfg.max_diff_chars],parse_edits(diff[:self.cfg.max_diff_chars]),complete,metadata)

    def singleton(self,item,multi_context=True):
        key=(self.identity(item),multi_context)
        if key not in self.cache:
            seedid=self.identity(item)
            metadata=dict(item)
            auxiliary=[];provenance=[]
            if multi_context and self.cfg.upfront_commit_budget:
                dist=self.history_distances(item)
                candidates=[a for a in self.admitted(item,self.candidates()) if self.identity(a)!=seedid and
                            dist.get(a['commit'],10**9)<=self.cfg.max_history_distance and
                            (set(a['files'])&set(item['files']) or abs(a['time']-item['time'])<=self.cfg.temporal_seconds)]
                candidates.sort(key=lambda a:(-a['time'],self.identity(a)))
                for a in candidates[:self.cfg.upfront_commit_budget]:
                    fs=[f for f in a['files'] if self.allowed(f)]
                    auxiliary.extend(fs);provenance.append({'commit_parent':self.identity(a),'files':fs,
                        'pre_state':item['parent'],'post_state':item['commit']})
            metadata['upfront_context']=provenance
            self.cache[key]=self.extract(item['parent'],item['commit'],seedid,[seedid],metadata,auxiliary)
        return self.cache[key]

    def admitted(self,seed,allitems):
        return [a for a in allitems if a['time']<=seed['time'] and
                (a==seed or self.ancestor(a['commit'],seed['parent']))]

    def relations(self,a,b):
        types=[]
        if set(a['files'])&set(b['files']):types.append('shared_file')
        def symbols(x):
            u=self.singleton(x)
            mods={r.function for d in u.docs for r in d.refs if r.function and u.touches(r)}
            calls={name(r.node) for d in u.docs for r in d.refs if isinstance(r.node,c_ast.FuncCall)}
            deps={d.file for d in u.docs if d.file in self.cfg.dependency_files}
            return mods,calls,deps
        am,ac,ad=symbols(a);bm,bc,bd=symbols(b)
        if am&bm:types.append('shared_symbol')
        if am&bc or bm&ac:types.append('caller_callee')
        if ad&bd:types.append('shared_dependency')
        if abs(a['time']-b['time'])<=self.cfg.temporal_seconds:types.append('time')
        return types

    def history_distances(self,seed):
        raw=self.git('rev-list','--parents','-n',str(self.cfg.history_limit),seed['commit'])
        graph={}
        lines=[line.split() for line in raw.splitlines()];known={x[0] for x in lines}
        for row in lines:
            for p in row[1:]:
                if p in known:
                    graph.setdefault(row[0],set()).add(p);graph.setdefault(p,set()).add(row[0])
        dist={seed['commit']:0};queue=[seed['commit']]
        for cur in queue:
            for nxt in sorted(graph.get(cur,set())):
                if nxt not in dist:dist[nxt]=dist[cur]+1;queue.append(nxt)
        return dist

    def compose(self,group):
        ids_=[self.identity(a) for a in group];unitid='group:'+digest(ids_)
        with tempfile.TemporaryDirectory(prefix='wise-fix-replay-') as td:
            p=subprocess.run(['git','clone','--shared','--no-checkout','--quiet',str(self.path),td],capture_output=True,text=True,timeout=60)
            if p.returncode:raise ValueError('Isolated replay clone failed: '+p.stderr)
            clone=Repository(td,self.cfg);clone.git('read-tree',group[0]['parent'])
            for a in group:
                patch=self.git('diff','--binary','--no-ext-diff','--no-textconv',a['parent'],a['commit'],'--')
                if not patch.strip():continue
                p=subprocess.run(['git','-C',td,'apply','--cached','--whitespace=nowarn','-'],input=patch,
                                 capture_output=True,text=True,timeout=60)
                if p.returncode:return None
            end=clone.git('write-tree').strip()
            u=clone.extract(group[0]['parent'],end,unitid,ids_,{'component_diffs':[
                {'id':self.identity(a),'diff_sha256':hashlib.sha256(self.git('diff','--binary',a['parent'],a['commit'],'--').encode()).hexdigest()} for a in group]})
        return u


def search(s,repo,seed,items,cfg,singleton_output):
    seedunit=repo.singleton(seed);dist=repo.history_distances(seed)
    admitted=[a for a in repo.admitted(seed,items) if dist.get(a['commit'],10**9)<=cfg.max_history_distance]
    index={repo.identity(a):a for a in admitted}
    seedid=repo.identity(seed)
    edges={k:set() for k in index};types=[]
    for a,b in itertools.combinations(sorted(index),2):
        ts=repo.relations(index[a],index[b])
        if ts:edges[a].add(b);edges[b].add(a);types.append({'a':a,'b':b,'types':ts})
    graphdist={seedid:0};q=[seedid]
    for k in q:
        for v in sorted(edges[k]):
            if v not in graphdist:graphdist[v]=graphdist[k]+1;q.append(v)
    baseline=support_keys(singleton_output)
    def priority(group,out):
        return (len(out['unresolved']),-len(support_keys(out)-baseline),len(group),
                max(graphdist.get(k,10**9) for k in group),
                max(abs(index[k]['time']-seed['time']) for k in group),tuple(group))
    g0=[seedid];records=[(priority(g0,singleton_output),g0,seedunit,singleton_output)]
    queue=list(records);seen={tuple(g0)};trace=[];evaluations=0;chosen=None
    while queue and evaluations<cfg.composite_budget:
        queue.sort(key=lambda r:r[0]);_,g,u,out=queue.pop(0)
        adjacent=sorted(set().union(*(edges[k] for k in g))-set(g))
        for k in adjacent:
            if evaluations>=cfg.composite_budget:break
            members=sorted([index[x] for x in g+[k]],key=lambda a:(a['time'],a['commit'],a['parent']))
            from functools import cmp_to_key
            def ancestry_order(a,b):
                if a['commit']==b['commit']:return -1 if a['parent']<b['parent'] else 1 if a['parent']>b['parent'] else 0
                if repo.ancestor(a['commit'],b['commit']):return -1
                if repo.ancestor(b['commit'],a['commit']):return 1
                return -1 if repo.identity(a)<repo.identity(b) else 1
            members.sort(key=cmp_to_key(ancestry_order))
            ng=[repo.identity(a) for a in members]
            if tuple(ng) in seen:continue
            seen.add(tuple(ng))
            if len(ng)>cfg.max_group_size or max(dist.get(a['commit'],10**9) for a in members)>cfg.max_history_distance:continue
            if ng[-1]!=seedid or not all(repo.ancestor(a['commit'],b['parent']) for a,b in zip(members,members[1:])):continue
            evaluations+=1;nu=repo.compose(members)
            if nu is None:trace.append({'group':ng,'termination':'replay_conflict'});continue
            no=execute(s,nu,cfg);trace.append({'group':ng,'statuses':no['statuses']})
            if VIO in no['statuses'].values():continue
            rec=(priority(ng,no),ng,nu,no);records.append(rec)
            if all(no['statuses'][st]==SAT for st in STAGES):chosen=rec;break
            queue.append(rec)
        if chosen:break
    if chosen:reason='three_stages_satisfied'
    else:
        chosen=min(records,key=lambda r:r[0]);reason='budget_exhausted' if evaluations>=cfg.composite_budget else 'queue_empty'
    return chosen[2],chosen[3],{'reason':reason,'evaluations':evaluations,'trace':trace,'relations':types,
                               'selected_group':chosen[1],'priority':chosen[0]}


def verify_unit(s,u,cfg,required_stages=STAGES):
    out=execute(s,u,cfg);v=validate_evidence(s,u,out,required_stages=required_stages)
    verdict=assign_verdict(out,v,required_stages=required_stages)
    return {'seed':u.id,'cwe':s['cwe'],'verdict':verdict,'output':out,'validation':v,
            'features':features(s,u,out,v,cfg),'selected_unit':u.id,
            'termination':'singleton','components':u.components}


def detect_seed(s,repo,seed,items,cfg,required_stages=STAGES,multi_commit=True):
    u=repo.singleton(seed,multi_context=multi_commit);out=execute(s,u,cfg)
    chosen=u;selected=out;records=None;search_record={'reason':'not_triggered','evaluations':0}
    if multi_commit and UNR in out['statuses'].values() and VIO not in out['statuses'].values():
        chosen,selected,search_record=search(s,repo,seed,items,cfg,out)
        if len(chosen.components)>1 and all(selected['statuses'][st]==SAT for st in STAGES):
            records=confirm_and_attribute(s,selected,u,chosen,cfg)
    composite=len(chosen.components)>1
    v=validate_evidence(s,chosen,selected,u if composite else None,records,required_stages)
    seedval=validate_evidence(s,u,out)
    seedrej=seedval['rejection_valid'] and (VIO in out['statuses'].values() or seedval.get('rejection_rule_valid',False))
    if composite:
        v['rejection_valid']=seedval['rejection_valid']
        v['rejection_rule_valid']=seedval['rejection_rule_valid']
        v['rejection_rules']=seedval['rejection_rules']
    verdict=assign_verdict(selected,v,composite,records,seedrej,required_stages)
    return {'seed':u.id,'commit':seed['commit'],'parent':seed['parent'],'cwe':s['cwe'],
            'verdict':verdict,'output':selected,'singleton_output':out,'validation':v,
            'confirmation_attribution':records,'search':search_record,
            'features':features(s,chosen,selected,v,cfg),'selected_unit':chosen.id,'components':chosen.components,
            'upfront_context':u.metadata.get('upfront_context',[])}


def binary_metrics(rows):
    counts={'tp':0,'fp':0,'tn':0,'fn':0}
    for y,v in rows:
        if y not in (0,1):raise ValueError('Binary labels must be 0/1')
        pos=v==VER;counts['tp' if y and pos else 'fn' if y else 'fp' if pos else 'tn']+=1
    tp,fp,tn,fn=(counts[k] for k in ('tp','fp','tn','fn'))
    div=lambda a,b:a/b if b else 0.
    p=div(tp,tp+fp);r=div(tp,tp+fn)
    return {**counts,'precision':p,'recall':r,'fpr':div(fp,fp+tn),
            'accuracy':div(tp+tn,tp+fp+tn+fn),'f1':div(2*p*r,p+r),
            'mcc':div(tp*tn-fp*fn,math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)))}


def fit_scorer(train,dev,cfg):
    if not train or not dev:raise ValueError('Training and development evidence required')
    ys=[y for _,y in train];n=len(ys);np=sum(ys);nn=n-np
    if not np or not nn:raise ValueError('Scorer training requires both classes')
    weights={1:n/(2*np),0:n/(2*nn)}
    trials=[]
    for l2 in cfg.regularizations:
        b=0.;w=[0.]*7
        for step in range(1,max(cfg.stopping_points)+1):
            gw=[0.]*7;gb=0.
            for phi,y in train:
                err=weights[y]*(sigmoid(b+sum(a*z for a,z in zip(w,phi)))-y)
                gb+=err
                for j in range(7):gw[j]+=err*phi[j]
            b-=cfg.learning_rate*gb/n
            w=[a-cfg.learning_rate*(g/n+l2*a) for a,g in zip(w,gw)]
            if step in cfg.stopping_points:
                loss=0.
                for phi,y in dev:
                    z=b+sum(a*x for a,x in zip(w,phi))
                    loss+=weights[y]*(max(z,0)-z*y+math.log1p(math.exp(-abs(z))))
                trials.append((loss/len(dev),l2,step,b,list(w)))
    best=min(trials,key=lambda t:(t[0],t[1],t[2]))
    return {'intercept':best[3],'weights':best[4],'feature_names':list(FEATURES),
            'l2':best[1],'steps':best[2],'development_loss':best[0],
            'class_weights':weights,'trials':[{'development_loss':t[0],'l2':t[1],'steps':t[2]} for t in trials]}


def check_artifact(a):
    if a.get('status')!='Frozen':raise ValueError('Unsupported artifact cannot run online')
    payload={k:v for k,v in a.items() if k!='sha256'}
    if a.get('sha256')!=digest(payload):raise ValueError('Artifact integrity check failed')
    if a['runtime']['version']!=VERSION or a['runtime']['code_sha256']!=runtime_digest():
        raise ValueError('Frozen runtime compatibility check failed')
    if a['runtime']['pycparser']!=pycparser.__version__:raise ValueError('Parser version mismatch')
    cfg=Config.from_dict(a['config']);validate_suite(a['suite'])
    if canonical(a['operator_contracts'])!=canonical(OPS):raise ValueError('Operator contract mismatch')
    if canonical(a.get('semantic_contracts'))!=canonical(MANUSCRIPT_CONTRACTS):raise ValueError('Semantic contract mismatch')
    return cfg


def read_jsonl(path):
    rows=[]
    for i,line in enumerate(Path(path).read_text().splitlines(),1):
        if line.strip():
            r=json.loads(line)
            if r.get('label') not in (0,1):raise ValueError(f'{path}:{i}: label must be 0/1')
            if not r.get('id'):raise ValueError('Dataset instance needs a stable id')
            rows.append(r)
    if len({r['id'] for r in rows})!=len(rows):raise ValueError('Duplicate dataset instance ids')
    validate_rows(rows)
    return rows


def row_identity(row):
    if row.get('repository') and row.get('commit') and row.get('parent'):
        return row['commit']+':'+row['parent']
    return row['id']


def validate_rows(rows):
    if any(not isinstance(r.get('id'),str) or not r['id'] for r in rows):raise ValueError('Stable nonempty string id required')
    if len({r['id'] for r in rows})!=len(rows):raise ValueError('Duplicate dataset instance ids')
    identities=[row_identity(r) for r in rows]
    if len(set(identities))!=len(identities):raise ValueError('Duplicate commit-parent seed identities')
    for r in rows:
        if r.get('label') not in (0,1):raise ValueError('Binary label required')
        if r.get('repository'):
            if not all(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}',str(r.get(k,''))) for k in ('commit','parent')):
                raise ValueError('Repository rows require full commit/parent hashes')
        elif not all(isinstance(r.get(k),str) for k in ('before','after','diff')):
            raise ValueError('Inline rows require before/after/diff strings')
    return identities


def validate_splits(train,dev,test=None):
    splits={'train':train,'dev':dev}
    if test is not None:splits['test']=test
    memberships={k:set(validate_rows(v)) for k,v in splits.items()}
    for a,b in itertools.combinations(splits,2):
        if memberships[a]&memberships[b] or {r['id'] for r in splits[a]}&{r['id'] for r in splits[b]}:
            raise ValueError(f'{a}/{b} overlap by id or commit-parent identity')
    return {k:{'count':len(v),'positive':sum(r['label']==1 for r in v),'negative':sum(r['label']==0 for r in v),
               'sha256':digest(v)} for k,v in splits.items()}


def corpus_for_cwe(rows,cwe):
    if cwe=='AGNOSTIC':return rows
    return [r for r in rows if r['label']==0 or cwe in r.get('cwes',[])]


def row_unit(row,cfg):
    if row.get('repository') and row.get('commit') and row.get('parent'):
        repo=Repository(row['repository'],cfg)
        parents=repo.git('rev-list','--parents','-n','1',row['commit']).split()[1:]
        if row['parent'] not in parents:raise ValueError('Selected parent is not an actual commit parent')
        return repo.singleton({'commit':row['commit'],'parent':row['parent'],
                               'time':int(repo.git('show','-s','--format=%ct',row['commit']).strip()),
                               'files':repo.git('diff','--name-only',row['parent'],row['commit'],'--').splitlines()})
    if not all(k in row for k in ('before','after','diff')):
        raise ValueError('Rows require before/after/diff, or repository/commit/parent')
    return unit_from_text(row['before'],row['after'],row['diff'],cfg,row['id'],row.get('file','example.c'))


def llm_generate(cwe,specification,examples,diagnostics,previous,endpoint,model,key,accounting):
    system=('Synthesize a CWE-specific executable suite using ONLY the fixed operators supplied. '
            'Return one JSON object conforming to the schema example. Mandatory predicates are conjoined '
            'within a witness, alternatives are existential, and bindings must remain compatible. '
            'No arbitrary code, literals from identifying metadata, new operators, or runtime LLM calls. '
            'Each repair alternative must include an explicit edit predicate marked attribution=true.')
    prompt={'examples':examples,'operators':OPS,'semantic_contracts':MANUSCRIPT_CONTRACTS,'schema':synthesis_schema(),
            'diagnostics':diagnostics,'previous':previous}
    if cwe=='AGNOSTIC':
        system+=' Synthesize one generic suite without CWE specifications or CWE-based grouping. Set cwe to AGNOSTIC.'
    else:prompt.update({'cwe':cwe,'cwe_specification':specification})
    request={'model':model,'temperature':0,'messages':[{'role':'system','content':system},
             {'role':'user','content':json.dumps(prompt)}],'response_format':{'type':'json_object'}}
    import time
    t=time.perf_counter();rec={'kind':'revision' if previous else 'initial','model':model,'request':request}
    accounting.append(rec)
    try:
        req=urllib.request.Request(endpoint.rstrip('/')+'/chat/completions',data=canonical(request),
                                   headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=90) as response:data=json.load(response)
        rec['response']=data;rec['success']=True;rec['usage']=data.get('usage',{})
        text=data['choices'][0]['message']['content'];suite=json.loads(text)
        if suite.get('cwe')!=cwe:raise ValueError('LLM returned another CWE')
        return suite
    except Exception as e:
        rec['success']=False;rec['error']=str(e);raise
    finally:rec['seconds']=time.perf_counter()-t


def synthesis_schema():
    return {'schema':'obligations-1.0','cwe':'target CWE or AGNOSTIC',
            'alternatives':[{'id':'unique string','selectors':{'binding':{
                'role':'pre or post','kind':'pycparser AST node class','file':'optional exact path',
                'function':'optional exact function','name':'optional exact node name'}},
                'stages':{k:[{'id':'unique predicate id','op':'one fixed operator',
                              'arguments':'operator argument names reference selector bindings',
                              'value':'required for AST_KIND/REFERENCE/OPERATOR/CALL',
                              'position/length/capacity/destination':'identifier parameters for buffer operators',
                              'attribution':'true only for a qualifying mitigation operator in Repair'}] for k in STAGES}}],
            'rejection_rules':[{'id':'unique rule id','alternative':'existing alternative id',
                'when':[{'stage':'pre, repair or safety','predicate':'existing predicate id',
                         'status':'Satisfied or Violated'}]}],
            'constraints':'Every stage nonempty. Precondition uses pre state; Safety post state. Repair requires an explicit edit and a qualifying mitigation predicate. Optional rejection_rules consume decisive validated conditions in one witness and must include a Violated condition with code facts. No arbitrary executable code.'}


def training_selection(rows,cwe,cfg):
    selected=corpus_for_cwe(rows,cwe)
    if cwe=='AGNOSTIC':return sorted(selected,key=lambda r:(r.get('timestamp',0),r['id']))
    return [r for label in (1,0) for r in sorted([x for x in selected if x['label']==label],
            key=lambda x:(x.get('timestamp',0),x['id']))[:cfg.max_examples_per_class]]


def synthesis_examples(rows,cfg):
    examples=[]
    for r in rows:
        u=row_unit(r,cfg)
        examples.append({'role':'positive' if r['label'] else 'negative',
                         'pre':[{'file_role':'source','text':d.text[:cfg.chars_per_state]} for d in u.docs if d.role=='pre'],
                         'diff':u.diff[:cfg.max_diff_chars],
                         'post':[{'file_role':'source','text':d.text[:cfg.chars_per_state]} for d in u.docs if d.role=='post']})
    return examples


def llm_generate_batch(requests,endpoint,model,key,accounting):
    import time
    body={'model':model,'temperature':0,'response_format':{'type':'json_object'},'messages':[
        {'role':'system','content':'Synthesize fixed executable JSON obligations for each requested CWE. Use only supplied operators and schema. No arbitrary code or metadata predicates. Return {"suites": {"CWE-id": suite}}. Each suite has Precondition/Repair/Safety with linked witnesses and qualifying mitigation attribution.'},
        {'role':'user','content':json.dumps({'requests':requests,'operators':OPS,'semantic_contracts':MANUSCRIPT_CONTRACTS,'schema':synthesis_schema()})}]}
    rec={'kind':'initial_batch','model':model,'request':body};accounting.append(rec);started=time.perf_counter()
    try:
        req=urllib.request.Request(endpoint.rstrip('/')+'/chat/completions',data=canonical(body),
                                  headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=90) as response:data=json.load(response)
        rec.update({'success':True,'response':data,'usage':data.get('usage',{})})
        suites=json.loads(data['choices'][0]['message']['content'])['suites']
        if set(suites)!={r['cwe'] for r in requests}:raise ValueError('Batch CWE membership mismatch')
        return suites
    except Exception as e:rec.update({'success':False,'error':str(e)});raise
    finally:rec['seconds']=time.perf_counter()-started


def offline(cwe,specification,train,dev,cfg,initial=None,generator=None,provenance=None):
    cfg.validate()
    if cwe!='AGNOSTIC' and not specification.strip():raise ValueError('A CWE specification is required')
    validate_splits(train,dev)
    construction_ids=[r['id'] for r in train+dev]
    construction_seeds=[row_identity(r) for r in train+dev]
    train=corpus_for_cwe(train,cwe);dev=corpus_for_cwe(dev,cwe)
    synthesis_train=training_selection(train,cwe,cfg)
    if not train or not dev or {r['label'] for r in train}!={0,1} or {r['label'] for r in dev}!={0,1}:
        raise ValueError('Each CWE training/development corpus must contain both classes')
    tu=[(r,row_unit(r,cfg)) for r in train];du=[(r,row_unit(r,cfg)) for r in dev]
    synthesis_ids={r['id'] for r in synthesis_train}
    examples=[]
    for label in (1,0):
        selected=sorted([(r,u) for r,u in tu if r['label']==label and r['id'] in synthesis_ids],key=lambda x:(x[0].get('timestamp',0),x[0]['id']))
        for r,u in selected:
            examples.append({'role':'positive' if label else 'negative',
                             'pre':[{ 'file_role':'source','text':d.text[:cfg.chars_per_state]} for d in u.docs if d.role=='pre'],
                             'diff':u.diff[:cfg.max_diff_chars],
                             'post':[{'file_role':'source','text':d.text[:cfg.chars_per_state]} for d in u.docs if d.role=='post']})
    if initial is None and generator is None:raise ValueError('Provide a candidate suite or LLM adapter')
    try:candidate=copy.deepcopy(initial) if initial else generator(examples,[],None)
    except Exception as e:return {'status':'Unsupported','reason':'synthesis_failed','error':str(e),'traces':[]}
    traces=[];accepted=False
    repositories={}
    def evaluate_row(suite,row,unit):
        if not row.get('repository'):return verify_unit(suite,unit,cfg)
        key=str(Path(row['repository']).resolve())
        if key not in repositories:
            repo=Repository(key,cfg)
            repositories[key]=(repo,repo.candidates())
        repo,items=repositories[key]
        seed={'commit':row['commit'],'parent':row['parent'],
              'time':int(repo.git('show','-s','--format=%ct',row['commit']).strip()),
              'files':repo.git('diff','--name-only',row['parent'],row['commit'],'--').splitlines()}
        if not any(repo.identity(x)==repo.identity(seed) for x in items):items.append(seed)
        return detect_seed(suite,repo,seed,items,cfg)
    for revision in range(cfg.max_revisions+1):
        try:
            validate_suite(candidate)
            if candidate['cwe']!=cwe:raise ValueError('CWE mismatch')
            smoke=verify_unit(candidate,tu[0][1],cfg)
            if smoke['validation']['failed']:raise ValueError('Evidence smoke test failed')
        except Exception as e:
            return {'status':'Unsupported','reason':'suite_checks_failed','error':str(e),'traces':traces}
        evaluated=[(r,evaluate_row(candidate,r,u)) for r,u in du]
        m=binary_metrics([(r['label'],out['verdict']) for r,out in evaluated])
        diagnostics=[{'role':'positive' if r['label'] else 'negative','verdict':out['verdict'],
                      'statuses':out['output']['statuses'],'missing':out['validation']['missing'],
                      'pre':[d.text for d in u.docs if d.role=='pre'],
                      'post':[d.text for d in u.docs if d.role=='post'],'diff':u.diff}
                     for (r,u),(_,out) in zip(du,evaluated) if (out['verdict']==VER)!=bool(r['label'])]
        traces.append({'revision':revision,'metrics':m,'outputs':[out for _,out in evaluated]})
        accepted=m['precision']>=cfg.min_precision and m['recall']>=cfg.min_recall and m['fpr']<=cfg.max_fpr
        if accepted:break
        if revision==cfg.max_revisions or generator is None:
            return {'status':'Unsupported','reason':'acceptance_not_met','traces':traces}
        try:candidate=generator(examples,diagnostics,candidate)
        except Exception as e:return {'status':'Unsupported','reason':'revision_request_failed','error':str(e),'traces':traces}
    train_features=[(evaluate_row(candidate,r,u)['features'],r['label']) for r,u in tu]
    dev_features=[(out['features'],r['label']) for r,out in evaluated]
    model=fit_scorer(train_features,dev_features,cfg)
    a={'status':'Frozen','schema':'wise-fix-artifact-1.0','cwe':cwe,'suite':candidate,
       'scorer':model,'config':cfg.__dict__,'operator_contracts':OPS,'semantic_contracts':MANUSCRIPT_CONTRACTS,
       'runtime':{'version':VERSION,'code_sha256':runtime_digest(),'pycparser':pycparser.__version__},
       'manifest':{'cwe_specification':specification,'accepted_revision':revision,
                   'synthesis_provenance':provenance or {'mode':'supplied-suite','suite_sha256':digest(initial)},
                   'train_ids':[r['id'] for r in train],'dev_ids':[r['id'] for r in dev],
                   'synthesis_train_ids':[r['id'] for r in synthesis_train],
                   'scorer_train_ids':[r['id'] for r in train],
                   'scorer_dev_ids':[r['id'] for r in dev],
                   'synthesis_train_digest':digest(synthesis_train),
                   'construction_ids':construction_ids,'construction_seeds':construction_seeds,
                   'train_digest':digest(train),'dev_digest':digest(dev),
                   'feature_names':list(FEATURES),'validation_metrics':m,
                   'canonicalization':'sha256-canonical-json; source provenance without raw line numbers',
                   'profile':'self-contained C99; scoped structured intra-function CFG'},
       'validation_traces':traces}
    a['sha256']=digest(a)
    return a


def online_repository(path,artifacts,cwes,output):
    a_by={a['cwe']:a for a in artifacts};results={};ranked={};retrieval={}
    import time
    timing={'retrieval_seconds':0.,'post_retrieval_seconds':0.,'per_seed_suite_seconds':[]}
    if not cwes:raise ValueError('Configure at least one target CWE')
    for cwe in sorted(set(cwes)):
        if cwe not in a_by:continue
        a=a_by[cwe];cfg=check_artifact(a);repo=Repository(path,cfg)
        started=time.perf_counter();items=repo.candidates();timing['retrieval_seconds']+=time.perf_counter()-started
        retrieval[cwe]=[repo.identity(i) for i in items];records=[]
        for seed in items:
            started=time.perf_counter()
            r=detect_seed(a['suite'],repo,seed,items,cfg);r['artifact_sha256']=a['sha256']
            if r['verdict']==VER:r['score']=score(a['scorer'],r['features'])
            records.append(r);results.setdefault(r['seed'],[]).append(r)
            elapsed=time.perf_counter()-started;timing['post_retrieval_seconds']+=elapsed
            timing['per_seed_suite_seconds'].append({'seed':r['seed'],'cwe':cwe,'seconds':elapsed})
        started=time.perf_counter()
        ranked[cwe]=sorted([r for r in records if r['verdict']==VER],key=lambda r:(-r['score'],r['seed']))
        timing['post_retrieval_seconds']+=time.perf_counter()-started
    unsupported=sorted(set(cwes)-set(a_by))
    if not results:
        cfg=check_artifact(artifacts[0]) if artifacts else Config()
        repo=Repository(path,cfg)
        for item in repo.candidates():results[repo.identity(item)]=[]
    started=time.perf_counter()
    seeds=[{'seed':k,'verdict':aggregate_verdicts([x['verdict'] for x in v]+([INC] if unsupported else [])),
            'weakness_results':v} for k,v in sorted(results.items())]
    report={'schema':'wise-fix-results-1.0','seeds':seeds,'ranked_verified_by_cwe':ranked,
            'unsupported_cwes':unsupported,'retrieval':retrieval}
    dump(output,report)
    timing['post_retrieval_seconds']+=time.perf_counter()-started
    timing['seed_count']=len(seeds)
    timing['scope']='post-retrieval extraction, verification, search, confirmation/attribution, validation, verdicts, scoring, sorting, serialization and result writing; timing sidecar excluded'
    dump(str(output)+'.timing.json',timing)
    return report


def evaluate_dataset(rows,artifacts,cwes,required_stages=STAGES,multi_commit=True):
    validate_rows(rows)
    a_by={a['cwe']:a for a in artifacts};parsed={k:check_artifact(v) for k,v in a_by.items()};results=[]
    forbidden={x for a in artifacts for x in a['manifest']['construction_ids']}
    forbidden_seeds={x for a in artifacts for x in a['manifest']['construction_seeds']}
    if forbidden & {r['id'] for r in rows} or forbidden_seeds & {row_identity(r) for r in rows}:raise ValueError('Test IDs or seeds overlap artifact construction data')
    import time,resource
    retrieval_seconds=0.;processing_seconds=0.;latencies=[];repos={}
    ranked={cwe:[] for cwe in sorted(set(cwes))}
    for row in rows:
        runs=[]
        for cwe in sorted(set(cwes)):
            if cwe not in a_by:runs.append({'cwe':cwe,'verdict':INC});continue
            a=a_by[cwe];cfg=parsed[cwe]
            if row.get('repository'):
                key=(str(Path(row['repository']).resolve()),digest(cfg.__dict__))
                if key not in repos:
                    started=time.perf_counter();repo=Repository(row['repository'],cfg);items=repo.candidates()
                    repos[key]=(repo,items);retrieval_seconds+=time.perf_counter()-started
                repo,items=repos[key]
                started=time.perf_counter()
                if row['parent'] not in repo.git('rev-list','--parents','-n','1',row['commit']).split()[1:]:
                    raise ValueError('Selected parent is not an actual commit parent')
                seed={'commit':row['commit'],'parent':row['parent'],'time':int(repo.git('show','-s','--format=%ct',row['commit']).strip()),
                      'files':repo.git('diff','--name-only',row['parent'],row['commit'],'--').splitlines()}
                if not any(repo.identity(x)==repo.identity(seed) for x in items):items.append(seed)
                result=detect_seed(a['suite'],repo,seed,items,cfg,required_stages,multi_commit)
            else:
                started=time.perf_counter();result=verify_unit(a['suite'],row_unit(row,cfg),cfg,required_stages)
            if result['verdict']==VER:result['score']=score(a['scorer'],result['features'])
            elapsed=time.perf_counter()-started;processing_seconds+=elapsed
            latencies.append({'id':row['id'],'cwe':cwe,'seconds':elapsed})
            runs.append(result)
            if result['verdict']==VER:ranked[cwe].append({'id':row['id'],'score':result['score'],
                                                       'evidence':result})
        started=time.perf_counter()
        verdict=aggregate_verdicts([r['verdict'] for r in runs])
        results.append({'id':row['id'],'verdict':verdict,'weakness_results':runs})
        processing_seconds+=time.perf_counter()-started
    started=time.perf_counter()
    identities={r['id']:row_identity(r) for r in rows}
    ranked_lists={k:sorted(v,key=lambda x:(-x['score'],identities[x['id']])) for k,v in ranked.items()}
    processing_seconds+=time.perf_counter()-started
    m=binary_metrics([(row['label'],r['verdict']) for row,r in zip(rows,results)])
    return {'metrics':m,'tri_state_counts':{v:sum(r['verdict']==v for r in results) for v in (VER,REJ,INC)},
            'results':results,'count':len(rows),
            'protocol':{'required_stages':list(required_stages),'multi_commit':multi_commit},
            'timing':{'retrieval_seconds':retrieval_seconds,'processing_seconds':processing_seconds,
                      'per_seed_suite':latencies,'process_peak_rss_mib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,
                      'scope':'processing includes extraction through scoring; caller measures reporting/serialization; RSS is process lifetime, not isolated dataset RSS'},
            'ranked_verified_by_cwe':ranked_lists}


def demo_suite():
    def pred(id,op,**kw):return {'id':id,'op':op,**kw}
    params={'position':'pos','length':'n','capacity':'limit','destination':'dst'}
    return {'schema':'obligations-1.0','cwe':'CWE-787','alternatives':[{
        'id':'destination_guard','selectors':{
            'old_guard':{'role':'pre','kind':'If'},'new_guard':{'role':'post','kind':'If'},
            'old_sink':{'role':'pre','kind':'FuncCall','name':'memcpy'},
            'new_sink':{'role':'post','kind':'FuncCall','name':'memcpy'}},
        'stages':{
            'pre':[pred('P1','AST_REFERENCE',node='old_guard',value='offset'),
                   pred('P2','AST_CALL',node='old_sink',value='memcpy'),
                   pred('P3','BUFFER_GUARD_MISMATCH',guard='old_guard',sink='old_sink',**params)],
            'repair':[pred('R1','CORRESPONDS',before='old_guard',after='new_guard'),
                      pred('R2','CORRESPONDS',before='old_sink',after='new_sink'),
                      pred('R3','EDIT_GUARD_STRENGTHENS',before='old_guard',after='new_guard',
                           sink_before='old_sink',sink_after='new_sink',attribution=True,**params),
                      pred('R4','AST_REFERENCE',node='new_guard',value='pos')],
            'safety':[pred('S1','AST_REFERENCE',node='new_guard',value='pos'),
                      pred('S2','CFG_DOMINATES',guard='new_guard',sink='new_sink'),
                      pred('S3','CFG_TRUE_BRANCH_EXITS',guard='new_guard'),
                      pred('S4','BUFFER_GUARD',guard='new_guard',sink='new_sink',**params)]}}]}


def main():
    ap=argparse.ArgumentParser(description=__doc__);sub=ap.add_subparsers(dest='command',required=True)
    p=sub.add_parser('init');p.add_argument('--directory',required=True)
    p=sub.add_parser('offline');p.add_argument('--train',required=True);p.add_argument('--dev',required=True)
    p.add_argument('--config',required=True);p.add_argument('--cwe',required=True);p.add_argument('--cwe-spec',required=True)
    p.add_argument('--candidate-suite');p.add_argument('--endpoint');p.add_argument('--model');p.add_argument('--key-env',default='DEEPSEEK_API_KEY');p.add_argument('--output',required=True)
    p=sub.add_parser('online');p.add_argument('--repo',required=True);p.add_argument('--artifacts',nargs='+',required=True)
    p.add_argument('--cwes',nargs='+',required=True);p.add_argument('--output',required=True)
    p=sub.add_parser('evaluate');p.add_argument('--test',required=True);p.add_argument('--artifacts',nargs='+',required=True)
    p.add_argument('--cwes',nargs='+',required=True);p.add_argument('--output',required=True)
    p=sub.add_parser('validate-artifact');p.add_argument('artifact')
    args=ap.parse_args()
    try:
        if args.command=='init':
            folder=Path(args.directory);dump(folder/'reference_config.json',Config().__dict__);dump(folder/'example_suite.json',demo_suite())
        elif args.command=='offline':
            cfg=Config.from_dict(load(args.config));logs=[]
            def generate(ex,diagnostics,previous):
                if not args.endpoint or not args.model:raise ValueError('LLM synthesis requires endpoint/model')
                key=os.environ.get(args.key_env)
                if not key:raise ValueError('API key environment variable unavailable')
                return llm_generate(args.cwe,Path(args.cwe_spec).read_text(),ex,diagnostics,previous,args.endpoint,args.model,key,logs)
            try:
                artifact=offline(args.cwe,Path(args.cwe_spec).read_text(),read_jsonl(args.train),read_jsonl(args.dev),cfg,
                                 load(args.candidate_suite) if args.candidate_suite else None,
                                 generate if not args.candidate_suite or (args.endpoint and args.model) else None,
                                 {'mode':'LLM' if not args.candidate_suite else 'supplied-suite',
                                  'model':args.model,'endpoint':args.endpoint,'temperature':0})
                dump(args.output,artifact)
                if artifact['status']!='Frozen':print('Unsupported: '+artifact['reason'],file=sys.stderr);return 2
            finally:
                if logs:dump(str(args.output)+'.synthesis_log.json',logs)
        elif args.command=='online':online_repository(args.repo,[load(p) for p in args.artifacts],args.cwes,args.output)
        elif args.command=='evaluate':dump(args.output,evaluate_dataset(read_jsonl(args.test),[load(p) for p in args.artifacts],args.cwes))
        elif args.command=='validate-artifact':check_artifact(load(args.artifact));print('Artifact integrity and compatibility: PASS')
        return 0
    except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired) as e:
        print('WISE-Fix: '+str(e),file=sys.stderr);return 2


REFERENCE_CANDIDATES = {'CWE-125': {'schema': 'obligations-1.0', 'cwe': 'CWE-125', 'alternatives': [{'id': 'destination_bound_correction', 'selectors': {'old_guard': {'role': 'pre', 'kind': 'If'}, 'old_write': {'role': 'pre', 'kind': 'Assignment'}, 'new_guard': {'role': 'post', 'kind': 'If'}, 'new_write': {'role': 'post', 'kind': 'FuncCall', 'name': 'memcpy'}}, 'stages': {'pre': [{'id': 'P1', 'op': 'DESTINATION_GUARD_MISMATCH', 'position': 'bitmap_caret', 'source_position': 'buffer_caret', 'count': 'encoded_pixels', 'width': 'pixel_block_size', 'capacity': 'image_block_size', 'destination': 'tga->bitmap', 'source': 'decompression_buffer', 'iterator': 'i', 'inner_iterator': 'j', 'guard': 'old_guard', 'write': 'old_write'}], 'repair': [{'id': 'R1', 'op': 'DESTINATION_REPAIR_LINK', 'position': 'bitmap_caret', 'source_position': 'buffer_caret', 'count': 'encoded_pixels', 'width': 'pixel_block_size', 'capacity': 'image_block_size', 'destination': 'tga->bitmap', 'source': 'decompression_buffer', 'iterator': 'i', 'inner_iterator': 'j', 'before': 'old_guard', 'after': 'new_guard', 'old_write': 'old_write', 'new_write': 'new_write'}, {'id': 'R2', 'op': 'EDIT_DESTINATION_GUARD', 'position': 'bitmap_caret', 'source_position': 'buffer_caret', 'count': 'encoded_pixels', 'width': 'pixel_block_size', 'capacity': 'image_block_size', 'destination': 'tga->bitmap', 'source': 'decompression_buffer', 'iterator': 'i', 'inner_iterator': 'j', 'before': 'old_guard', 'after': 'new_guard', 'new_write': 'new_write', 'attribution': True}], 'safety': [{'id': 'S1', 'op': 'DESTINATION_COPY_GUARDED', 'position': 'bitmap_caret', 'source_position': 'buffer_caret', 'count': 'encoded_pixels', 'width': 'pixel_block_size', 'capacity': 'image_block_size', 'destination': 'tga->bitmap', 'source': 'decompression_buffer', 'iterator': 'i', 'inner_iterator': 'j', 'guard': 'new_guard', 'write': 'new_write'}]}}]}, 'CWE-119': {'schema': 'obligations-1.0', 'cwe': 'CWE-119', 'alternatives': [{'id': 'unsigned_char_length_normalization', 'selectors': {'old_length': {'role': 'pre', 'kind': 'Assignment'}, 'old_arithmetic': {'role': 'pre', 'kind': 'Assignment'}, 'old_sink': {'role': 'pre', 'kind': 'FuncCall', 'name': 'ReadBlob'}, 'new_length': {'role': 'post', 'kind': 'Assignment'}, 'arithmetic': {'role': 'post', 'kind': 'Assignment'}, 'sink': {'role': 'post', 'kind': 'FuncCall', 'name': 'ReadBlob'}}, 'stages': {'pre': [{'id': 'P1', 'op': 'DIRECT_LENGTH_FLOW', 'variable': 'length', 'accumulator': 'combined_length', 'image': 'image', 'producer': 'ReadBlobByte', 'consumer': 'ReadBlob', 'outer_type': 'MagickSizeType', 'normalization_type': 'unsigned char', 'size_type': 'size_t', 'assignment': 'old_length', 'arithmetic': 'old_arithmetic', 'sink': 'old_sink'}], 'repair': [{'id': 'R1', 'op': 'EDIT_LENGTH_NORMALIZES', 'variable': 'length', 'accumulator': 'combined_length', 'image': 'image', 'producer': 'ReadBlobByte', 'consumer': 'ReadBlob', 'outer_type': 'MagickSizeType', 'normalization_type': 'unsigned char', 'size_type': 'size_t', 'before': 'old_length', 'after': 'new_length', 'attribution': True}], 'safety': [{'id': 'S1', 'op': 'NORMALIZED_LENGTH_FLOW', 'variable': 'length', 'accumulator': 'combined_length', 'image': 'image', 'producer': 'ReadBlobByte', 'consumer': 'ReadBlob', 'outer_type': 'MagickSizeType', 'normalization_type': 'unsigned char', 'size_type': 'size_t', 'assignment': 'new_length', 'arithmetic': 'arithmetic', 'sink': 'sink'}]}}]}}

import argparse
import csv
import json
import os
from pathlib import Path
import sys

w = sys.modules[__name__]


def dataset_folders(root):
    if (root / 'train.jsonl').is_file():
        folders = [root]
    else:
        folders = sorted(p for p in root.iterdir()
                         if p.is_dir() and (p / 'train.jsonl').is_file())
    if not folders:
        raise ValueError('Input must contain train.jsonl, dev.jsonl and test.jsonl, '
                         'or dataset subfolders containing these files.')
    for folder in folders:
        for name in ('train.jsonl', 'dev.jsonl', 'test.jsonl'):
            if not (folder / name).is_file():
                raise ValueError(f'Missing file: {folder / name}')
    return folders


def write_outputs(folder, report):
    w.dump(folder / 'results.json', report)
    with (folder / 'verdicts.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.writer(stream)
        writer.writerow(['id', 'verdict'])
        writer.writerows((r['id'], r['verdict']) for r in report['results'])
    with (folder / 'ranked_verified.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.writer(stream)
        writer.writerow(['cwe', 'rank', 'id', 'score'])
        for cwe, rows in report['ranked_verified_by_cwe'].items():
            writer.writerows((cwe, rank, r['id'], r['score'])
                             for rank, r in enumerate(rows, 1))
    w.dump(folder / 'metrics.json', report['metrics'])


def folder_main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path, help='Dataset folder')
    parser.add_argument('--output', required=True, type=Path, help='Results folder')
    parser.add_argument('--suites', type=Path, help='Candidate suite JSON folder')
    parser.add_argument('--cwes', nargs='+', help='Fixed CWE scope; defaults to supplied suites')
    parser.add_argument('--config', type=Path, help='Optional configuration JSON')
    parser.add_argument('--endpoint', help='Optional OpenAI-compatible API base URL')
    parser.add_argument('--model', help='Model for offline synthesis/revision')
    parser.add_argument('--key-env', default='DEEPSEEK_API_KEY')
    args = parser.parse_args()
    try:
        root, target = args.input.resolve(), args.output.resolve()
        if not root.is_dir():
            raise ValueError(f'Input folder does not exist: {root}')
        if target == root or target in root.parents:
            raise ValueError('Output must be separate from the input folder and its ancestors.')
        if bool(args.endpoint) != bool(args.model):
            raise ValueError('Provide both --endpoint and --model.')
        key = os.environ.get(args.key_env) if args.endpoint else None
        if args.endpoint and not key:
            raise ValueError(f'Set the {args.key_env} environment variable.')
        suite_dir = args.suites or (root / 'suites' if (root / 'suites').is_dir()
                                   else Path(__file__).resolve().parent / 'suites')
        if args.suites and not suite_dir.is_dir():
            raise ValueError(f'Suite folder does not exist: {suite_dir}')
        suites = copy.deepcopy(REFERENCE_CANDIDATES) if not suite_dir.is_dir() else {}
        for path in sorted(suite_dir.glob('*.json')):
            suite = w.load(path)
            w.validate_suite(suite)
            if suite['cwe'] in suites:
                raise ValueError(f'Duplicate suite: {suite["cwe"]}')
            suites[suite['cwe']] = suite
        cwes = sorted(set(args.cwes or suites))
        if not cwes:
            raise ValueError('Supply suites or use --cwes with --endpoint and --model.')
        if any(not c.startswith('CWE-') or not c[4:].isdigit() for c in cwes):
            raise ValueError('Use CWE identifiers such as CWE-119.')
        config_path = args.config or root / 'config.json'
        cfg = w.Config.from_dict(w.load(config_path)) if config_path.is_file() else w.Config()
        if args.config and not config_path.is_file():
            raise ValueError(f'Configuration file does not exist: {config_path}')
        cfg.validate()
        folders = dataset_folders(root)
        summary = {}
        for folder in folders:
            output = target if folders == [root] else target / folder.name
            output.mkdir(parents=True, exist_ok=True)
            train = w.read_jsonl(folder / 'train.jsonl')
            dev = w.read_jsonl(folder / 'dev.jsonl')
            artifacts, status = [], {}
            for cwe in cwes:
                spec_path = root / 'cwe_specs' / (cwe + '.txt')
                if args.endpoint and not spec_path.is_file():
                    raise ValueError(f'Offline LLM synthesis/revision requires {spec_path}')
                spec = spec_path.read_text(encoding='utf-8') if spec_path.is_file() else cwe
                logs = []

                def generate(examples, diagnostics, previous):
                    return w.llm_generate(cwe, spec, examples, diagnostics, previous,
                                          args.endpoint, args.model, key, logs)

                if cwe not in suites and not args.endpoint:
                    raise ValueError(f'No candidate suite or LLM configuration for {cwe}')
                training_classes = {r['label'] for r in w.corpus_for_cwe(train, cwe)}
                development_classes = {r['label'] for r in w.corpus_for_cwe(dev, cwe)}
                if training_classes != {0, 1} or development_classes != {0, 1}:
                    artifact = {'status': 'Unsupported', 'cwe': cwe,
                                'reason': 'insufficient_labeled_training_or_development_data'}
                else:
                    artifact = w.offline(
                        cwe, spec, train, dev, cfg, initial=suites.get(cwe),
                        generator=generate if args.endpoint else None,
                        provenance={'mode': 'supplied-suite' if cwe in suites else 'LLM',
                                    'model': args.model, 'endpoint': args.endpoint})
                w.dump(output / 'artifacts' / (cwe + '.json'), artifact)
                if logs:
                    w.dump(output / 'artifacts' / (cwe + '.synthesis_log.json'), logs)
                status[cwe] = artifact['status']
                if artifact['status'] == 'Frozen':
                    w.check_artifact(artifact)
                    artifacts.append(artifact)
            test = w.read_jsonl(folder / 'test.jsonl')
            w.validate_splits(train, dev, test)
            report = w.evaluate_dataset(test, artifacts, cwes)
            write_outputs(output, report)
            w.dump(output / 'suite_status.json', status)
            summary[folder.name] = {'suite_status': status, 'counts': report['tri_state_counts']}
            print(f'{folder.name}: {len(test)} patches -> {output}')
            print('Suites: ' + ', '.join(f'{c}: {s}' for c, s in status.items()))
        w.dump(target / 'summary.json', summary)
        return 0
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'WISE-Fix: {error}', file=sys.stderr)
        return 2
if __name__ == '__main__':
    commands = {'init', 'offline', 'online', 'evaluate', 'validate-artifact'}
    raise SystemExit(main() if len(sys.argv) > 1 and sys.argv[1] in commands else folder_main())

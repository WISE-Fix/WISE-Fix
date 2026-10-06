import copy
import unittest
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wise_fix_reference_verifiers import load_engine, load_candidate, DEFAULT_ENGINE
w = load_engine(Path(os.environ.get('WISE_FIX_ENGINE', str(DEFAULT_ENGINE))))
SUITES = {cwe: (lambda cwe=cwe: load_candidate(w, cwe)) for cwe in ('CWE-119','CWE-125')}
from fixture_code import PRE125,POST125,PRE119,POST119,diff


class ManuscriptVerifierTests(unittest.TestCase):
    def run_suite(self,cwe,before,after):
        file='gd_tga.c' if cwe=='CWE-125' else 'image.c'
        u=w.unit_from_text(before,after,diff(before,after,file),w.Config(),file=file)
        return w.verify_unit(SUITES[cwe](),u,w.Config()),u

    def test_destination_manuscript_transition(self):
        r,u=self.run_suite('CWE-125',PRE125,POST125)
        self.assertEqual(r['verdict'],w.VER)
        self.assertEqual(r['output']['statuses'],dict.fromkeys(w.STAGES,w.SAT))
        self.assertFalse(r['validation']['failed'])

    def test_normalization_manuscript_transition(self):
        r,u=self.run_suite('CWE-119',PRE119,POST119)
        self.assertEqual(r['verdict'],w.VER)
        self.assertFalse(r['validation']['failed'])

    def test_empty_guard_is_not_protection(self):
        after=POST125.replace('return -1;',';')
        self.assertNotEqual(self.run_suite('CWE-125',PRE125,after)[0]['verdict'],w.VER)

    def test_source_guard_does_not_fix_destination(self):
        after=POST125.replace('bitmap_caret + encoded_pixels','buffer_caret + encoded_pixels')
        self.assertNotEqual(self.run_suite('CWE-125',PRE125,after)[0]['verdict'],w.VER)

    def test_preexisting_destination_protection_not_verified(self):
        before=PRE125.replace('    int i, j;','    int i, j;\n    if ((bitmap_caret + encoded_pixels * pixel_block_size) >= image_block_size) return -1;')
        self.assertNotEqual(self.run_suite('CWE-125',before,POST125)[0]['verdict'],w.VER)

    def test_unused_preconversion_not_a_weakness_witness(self):
        before=PRE119.replace('combined_length += length + 1','combined_length += i + 1').replace('(size_t) length++','(size_t) i++')
        self.assertNotEqual(self.run_suite('CWE-119',before,POST119)[0]['verdict'],w.VER)

    def test_comment_matches_not_evidence(self):
        after='void example(void) { /* '+POST125+' */ }\n'
        self.assertNotEqual(self.run_suite('CWE-125',PRE125,after)[0]['verdict'],w.VER)

    def test_guard_in_another_function(self):
        after=POST125.replace('    if ((bitmap_caret + encoded_pixels * pixel_block_size) >= image_block_size) {\n        return -1;\n    }\n','')
        after+='int unrelated(int bitmap_caret,int encoded_pixels,int pixel_block_size,int image_block_size) { if ((bitmap_caret + encoded_pixels * pixel_block_size) >= image_block_size) return -1; return 0; }\n'
        self.assertNotEqual(self.run_suite('CWE-125',PRE125,after)[0]['verdict'],w.VER)

    def test_same_line_is_supported(self):
        for cwe,before,after in [('CWE-125',PRE125,POST125),('CWE-119',PRE119,POST119)]:
            r,u=self.run_suite(cwe,before.replace('\n',' ')+'\n',after.replace('\n',' ')+'\n')
            self.assertEqual(r['verdict'],w.VER)

    def test_wrong_copy_size_is_not_verified(self):
        after=POST125.replace('buffer_caret, pixel_block_size);','buffer_caret, encoded_pixels);')
        self.assertNotEqual(self.run_suite('CWE-125',PRE125,after)[0]['verdict'],w.VER)

    def test_missing_position_update_is_not_verified(self):
        after=POST125.replace('        bitmap_caret += pixel_block_size;\n','')
        self.assertNotEqual(self.run_suite('CWE-125',PRE125,after)[0]['verdict'],w.VER)

    def test_wrong_loop_extent_is_not_verified(self):
        after=POST125.replace('i < encoded_pixels','i < image_block_size')
        self.assertNotEqual(self.run_suite('CWE-125',PRE125,after)[0]['verdict'],w.VER)

    def test_unknown_control_flow_abstains(self):
        after=POST125.replace('    int i, j;','    int i, j;\n    while (encoded_pixels < 0) { encoded_pixels++; }')
        r,u=self.run_suite('CWE-125',PRE125,after)
        self.assertEqual(r['output']['statuses']['safety'],w.UNR)
        self.assertEqual(r['verdict'],w.INC)

    def test_unrelated_normalized_value(self):
        after=POST119.replace('MagickSizeType length,','MagickSizeType unused, length,').replace('    length =','    unused =')
        self.assertNotEqual(self.run_suite('CWE-119',PRE119,after)[0]['verdict'],w.VER)

    def test_wrong_readblob_size(self):
        after=POST119.replace('(size_t) length++','(size_t) combined_length++')
        self.assertNotEqual(self.run_suite('CWE-119',PRE119,after)[0]['verdict'],w.VER)

    def test_wrong_arithmetic_value(self):
        after=POST119.replace('combined_length += length + 1','combined_length += i + 1')
        self.assertNotEqual(self.run_suite('CWE-119',PRE119,after)[0]['verdict'],w.VER)

    def test_intervening_assignment_abstains(self):
        after=POST119.replace('    combined_length +=','    length = 5;\n    combined_length +=')
        r,u=self.run_suite('CWE-119',PRE119,after)
        self.assertEqual(r['output']['statuses']['safety'],w.UNR)
        self.assertEqual(r['verdict'],w.INC)

    def test_unrelated_direct_conversion_not_global_rejection(self):
        extra='void other(void *image) { MagickSizeType length; length = (MagickSizeType) ReadBlobByte(image); }\n'
        r,u=self.run_suite('CWE-119',PRE119+extra,POST119+extra)
        self.assertEqual(r['verdict'],w.VER)

    def test_empty_support_evidence_invalid(self):
        s=SUITES['CWE-119']();r,u=self.run_suite('CWE-119',PRE119,POST119);output=copy.deepcopy(r['output'])
        for a in w.all_atoms(output):a['facts']=[]
        validation=w.validate_evidence(s,u,output)
        self.assertFalse(validation['acceptance_valid'])
        self.assertEqual(w.assign_verdict(output,validation),w.INC)

    def test_missing_obligation_reporting_invalid(self):
        s=SUITES['CWE-125']();r,u=self.run_suite('CWE-125',PRE125,POST125);output=copy.deepcopy(r['output'])
        for alt in output['alternatives']:
            for witness in alt['witnesses']:
                for stage in w.STAGES:witness['stages'][stage]['atoms']=[]
        self.assertFalse(w.validate_evidence(s,u,output)['acceptance_valid'])

    def test_forged_diff_does_not_verify(self):
        u=w.unit_from_text(PRE119,POST119,'+ length = (MagickSizeType) (unsigned char) ReadBlobByte(image);',w.Config(),file='image.c')
        self.assertFalse(u.complete)
        self.assertNotEqual(w.verify_unit(SUITES['CWE-119'](),u,w.Config())['verdict'],w.VER)

    def test_typedef_coordinates_are_source_located(self):
        r,u=self.run_suite('CWE-119',PRE119,POST119)
        self.assertTrue(all(f['start_line']>0 for a in r['validation']['atoms'] for f in a['facts']))

    def test_noop_not_verified(self):
        for cwe,before in [('CWE-125',PRE125),('CWE-119',PRE119)]:
            self.assertNotEqual(self.run_suite(cwe,before,before)[0]['verdict'],w.VER)

    def test_freeze_and_independent_test_for_both_suites(self):
        for cwe,before,after in [('CWE-125',PRE125,POST125),('CWE-119',PRE119,POST119)]:
            file='gd_tga.c' if cwe=='CWE-125' else 'image.c'
            def row(split,label):
                end=after if label else before
                return {'id':split+str(label),'label':label,'cwes':[cwe] if label else [],'file':file,
                        'before':before,'after':end,'diff':diff(before,end,file)}
            artifact=w.offline(cwe,'Synthetic compatibility fixture only.',[row('train',1),row('train',0)],
                               [row('dev',1),row('dev',0)],w.Config(),SUITES[cwe](),
                               provenance={'mode':'synthetic-compatibility-fixture'})
            self.assertEqual(artifact['status'],'Frozen');w.check_artifact(artifact)
            report=w.evaluate_dataset([row('test',1),row('test',0)],[artifact],[cwe])
            self.assertEqual(report['metrics']['tp'],1);self.assertEqual(report['metrics']['tn'],1)
            self.assertEqual(len(report['ranked_verified_by_cwe'][cwe]),1)
            changed=copy.deepcopy(artifact);changed['semantic_contracts']={}
            changed['sha256']=w.digest({k:v for k,v in changed.items() if k!='sha256'})
            with self.assertRaisesRegex(ValueError,'Semantic contract'):w.check_artifact(changed)


if __name__=='__main__':unittest.main()

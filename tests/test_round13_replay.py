import copy
import hashlib
import io
import json
import math
import os
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile
import numpy as np
from src.round13.archive import Archive, safe_inventory, safe_name
from src.round13.common import EvidenceError, Unavailable, read, write, sha, fingerprint
from src.round13.control import Status, BudgetExceeded, classify, Lifecycle
from src.round13.metrics import coverage, csv_hits, validate_hits, coordinate_permutation, validate_ids, fixed_mask, regional, compare_hits
from src.round13.inputs import Inputs, state_key, match_historical, BASE
from src.round13.protocol import PHYSICAL_FIELDS, compatibility, protocol_scalars
from src.round13.checker import independent_coverage, independent_regions, independent_compatibility, differences, verify_report
from src.round13.replay import evaluate_existing
from src.round13.seal import write_seal, verify_seal, REQUIRED_PASS


class TempCase(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('ROUND13_TEST_ROOT'))
        self.root=Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()


class CoverageTests(unittest.TestCase):
    def test_dual_denominators(self):
        values=np.array([1.,2.,3.,np.inf]);self.assertEqual(coverage(values,5)['coverage_end_fraction'],.75)
        self.assertEqual(coverage(values[:3],5)['coverage_end_fraction'],1)
    def test_integer_ninety_threshold(self):
        values=list(range(10))+[np.inf]
        self.assertEqual(coverage(values,20)['threshold_90_count'],10)
        self.assertEqual(coverage(values,20)['T90_s'],9)
        self.assertEqual(coverage([0.]*9+[np.inf]*2,20)['T90_s'],None)
    def test_exact_hundred_and_unreached(self):
        self.assertEqual(coverage([0,10],10)['T100_s'],10)
        self.assertFalse(coverage([0,np.inf],10)['reached_100'])
        self.assertIsNone(coverage([0,np.inf],10)['T100_s'])
    def test_empty_and_all_miss(self):
        self.assertEqual(coverage([],10)['status'],'EMPTY_DOMAIN')
        self.assertFalse(coverage([],10)['reached_100'])
        self.assertEqual(coverage([np.inf]*5,10)['covered'],0)
    def test_csv_blank_only(self):
        self.assertTrue(np.isinf(csv_hits([{'first_hit_s':''}],10)[0]))
        self.assertEqual(csv_hits([{'first_hit_s':'2'}],10)[0],2)
        for value in ['NaN','inf','-inf']:
            with self.subTest(value=value),self.assertRaisesRegex(EvidenceError,'NONFINITE_CSV_FIRST_HIT'):
                csv_hits([{'first_hit_s':value}],10)
    def test_npy_invalid_sentinels(self):
        self.assertTrue(np.isinf(validate_hits([np.inf],10)[0]))
        for value,reason in [(np.nan,'NAN_FIRST_HIT'),(-np.inf,'NEGATIVE_INFINITY_FIRST_HIT'),(-1,'NEGATIVE_FIRST_HIT'),(11,'FIRST_HIT_OUTSIDE_WINDOW')]:
            with self.subTest(value=value),self.assertRaisesRegex(EvidenceError,reason):validate_hits([value],10)
    def test_inf_forbidden_format(self):
        self.assertEqual(validate_hits([0],10,False)[0],0)
        with self.assertRaisesRegex(EvidenceError,'INFINITY_NOT_ALLOWED_IN_SOURCE'):validate_hits([np.inf],10,False)
    def test_independent_threshold(self):
        for a in [[],[0.],[1.,2.,np.inf],list(range(11))]:
            self.assertFalse(differences(coverage(a,20),independent_coverage(a)))


class CoordinateTests(unittest.TestCase):
    def test_modulo_and_reorder(self):
        self.assertEqual(coordinate_permutation([[1,180],[2,359]],[[2,-1],[1,-180]]).tolist(),[1,0])
    def test_duplicate_coordinates(self):
        self.assertEqual(coordinate_permutation([[1,0]],[[1,360]]).tolist(),[0])
        with self.assertRaisesRegex(EvidenceError,'DUPLICATE_COORDINATE'):coordinate_permutation([[1,0],[1,360]],[[1,0],[2,0]])
    def test_new_coordinate_rejected(self):
        self.assertEqual(coordinate_permutation([[1,0]],[[1,0]]).tolist(),[0])
        with self.assertRaisesRegex(EvidenceError,'NEW_OR_MISSING_COORDINATE'):coordinate_permutation([[1,0]],[[1,0.1]])
    def test_missing_row(self):
        self.assertEqual(validate_ids([{'id':'0'}],'id',1),[0])
        with self.assertRaisesRegex(EvidenceError,'MISSING_POINT_ROWS'):validate_ids([{'id':'0'}],'id',2)
    def test_duplicate_id(self):
        self.assertEqual(validate_ids([{'id':'0'},{'id':'1'}],'id',2),[0,1])
        with self.assertRaisesRegex(EvidenceError,'DUPLICATE_POINT_ID'):validate_ids([{'id':'0'},{'id':'0'}],'id',2)
    def test_mask_rule_and_count(self):
        a=[[0,0],[85,1]];valid=np.array([True,False])
        self.assertEqual(fixed_mask(a,valid,1,83).tolist(),[True,False])
        with self.assertRaisesRegex(EvidenceError,'MASK_COUNT_MISMATCH'):fixed_mask(a,valid,2,83)
        with self.assertRaisesRegex(EvidenceError,'MASK_RULE_MISMATCH'):fixed_mask(a,~valid,1,83)
    def test_mask_not_bool(self):
        self.assertEqual(fixed_mask([[0,0]],np.array([True]),1,83).tolist(),[True])
        with self.assertRaisesRegex(EvidenceError,'INVALID_MASK_ENCODING'):fixed_mask([[0,0]],[1],1,83)
    def test_historical_unique_match(self):
        r=[dict(N=28,orbit_hash='x',name='exact')];m=dict(N=28,orbit_file_hash='x',source_legacy_run_id='exact')
        self.assertEqual(match_historical(r,m)[0],0)
        with self.assertRaisesRegex(EvidenceError,'HISTORICAL_ORBIT_MULTIPLE_MATCHES'):match_historical(r+r,m)
        with self.assertRaisesRegex(EvidenceError,'HISTORICAL_ORBIT_UNMATCHED'):match_historical([],m)


class RegionTests(unittest.TestCase):
    def test_overlap_touch_tolerance(self):
        r=regional({'a':[[3,4],[1,2],[1.5,3],[4.0000005,5],[5.000002,6]]},10)
        self.assertEqual(r['targets']['a']['merged_count'],2)
        self.assertEqual(r['targets']['a']['merged_intervals'][0],[1,5])
    def test_cross_object_not_merged(self):
        r=regional({'a':[[0,1],[5,6]],'b':[[0,6]]},10)
        self.assertEqual(r['pooled_internal']['gap_count'],1)
        self.assertEqual(r['pooled_internal']['max_s'],4)
    def test_zero_one_visits_preserved(self):
        r=regional({'a':[],'b':[[2,3]]},10)
        self.assertEqual(set(r['targets']),{'a','b'})
        self.assertIsNone(r['pooled_internal']['mean_s'])
        self.assertEqual(r['targets']['a']['boundary_inclusive']['max_s'],10)
        self.assertEqual(r['targets']['b']['boundary_inclusive']['gap_count'],2)
    def test_boundary_separate(self):
        r=regional({'a':[[2,3],[4,5]]},10)
        self.assertEqual(r['pooled_internal']['mean_s'],1)
        self.assertEqual(r['pooled_boundary_inclusive']['mean_s'],8/3)
    def test_pool_is_not_mean_of_means(self):
        r=regional({'a':[[0,1],[2,3],[4,5]],'b':[[0,1],[10,11]]},12)
        self.assertEqual(r['pooled_internal']['mean_s'],11/3)
        self.assertNotEqual(r['pooled_internal']['mean_s'],5)
    def test_clipping_and_invalid(self):
        self.assertEqual(regional({'a':[[-2,1],[9,12]]},10)['targets']['a']['merged_intervals'],[[0,1],[9,10]])
        for bad in [[[2,1]],[[0,float('nan')]],[[0,float('inf')]]]:
            with self.subTest(bad=bad),self.assertRaisesRegex(EvidenceError,'INVALID_ACCESS_INTERVAL'):regional({'a':bad},10)
    def test_independent_regions(self):
        r={'a':[[0,1],[0.5,2],[2.0000005,4],[9,10]],'b':[],'c':[[3,3.5]]}
        self.assertFalse(differences(regional(r,10),independent_regions(r,10,1e-6)))


class ProtocolTests(unittest.TestCase):
    def test_each_physical_field_rejected(self):
        positive={k:dict(value=k) for k in PHYSICAL_FIELDS}
        self.assertEqual(compatibility(positive,positive)['status'],'COMPATIBLE')
        for k in PHYSICAL_FIELDS:
            changed=copy.deepcopy(positive);changed[k]=dict(value='changed')
            with self.subTest(field=k):
                a=compatibility(positive,changed);b=independent_compatibility(positive,changed)
                self.assertEqual(a['status'],'NOT_COMPUTABLE_FROM_FROZEN_EVIDENCE');self.assertEqual(a['incompatible_fields'],[k]);self.assertEqual(a['status'],b['status'])
    def test_missing_field_is_not_wildcard(self):
        p={k:1 for k in PHYSICAL_FIELDS};self.assertEqual(compatibility(p,p)['status'],'COMPATIBLE')
        p.pop('earth_eop');self.assertEqual(compatibility(p,p)['missing_fields'],['earth_eop'])
    def test_producer_consumer_code_separate(self):
        p={k:1 for k in PHYSICAL_FIELDS};q=dict(p,consumer_code='different')
        self.assertEqual(compatibility(p,q)['status'],'COMPATIBLE')
    def test_pinned_scalar_format(self):
        x=protocol_scalars('epoch_utc: 1 Jan 2027 00:00:00.000\nmerge_tolerance_s: 1.0e-06\nregional_grid_created: false\nglobal_grid: null\n nested: ignored\n')
        self.assertEqual(x['merge_tolerance_s'],1e-6);self.assertFalse(x['regional_grid_created']);self.assertIsNone(x['global_grid']);self.assertNotIn(' nested',x)


def fixture_archive(root, payload):
    rows={n:dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest()) for n,b in payload.items()}
    manifest=json.dumps(dict(files=rows)).encode();zpath=root/'input.zip'
    with zipfile.ZipFile(zpath,'w') as z:
        z.writestr('fixture/MANIFEST.json',manifest)
        for n,b in payload.items():z.writestr('fixture/'+n,b)
    cfg=dict(archive=str(zpath),archive_bytes=zpath.stat().st_size,archive_sha256=sha(zpath),archive_root='fixture',archive_members=len(payload)+1,manifest_sha256=hashlib.sha256(manifest).hexdigest())
    return cfg


class ArchiveTests(TempCase):
    def test_raw_member_mutation_affects_same_reader(self):
        cfg=fixture_archive(self.root,{'hits.csv':b'first_hit_s\n1\n2\n'})
        a=Archive(cfg,self.root/'vendor')
        try:
            self.assertEqual(coverage(csv_hits(a.csv('hits.csv'),10),10)['T100_s'],2)
            (self.root/'vendor/hits.csv').write_bytes(b'first_hit_s\n1\n9\n')
            with self.assertRaisesRegex(EvidenceError,'MEMBER_BYTES_MISMATCH'):a.csv('hits.csv')
        finally:a.close()
    def test_unavailable_does_not_launch(self):
        cfg=fixture_archive(self.root,{'ok':b'x'});a=Archive(cfg,self.root/'vendor')
        try:
            self.assertEqual(a.path('ok').read_bytes(),b'x')
            with self.assertRaisesRegex(Unavailable,'UNAVAILABLE_FROM_FROZEN_LIBRARY'):a.path('missing')
        finally:a.close()
    def test_manifest_and_archive_digest(self):
        cfg=fixture_archive(self.root,{'ok':b'x'});a=Archive(cfg,self.root/'vendor');a.close()
        for k,reason in [('archive_sha256','ARCHIVE_SHA_MISMATCH'),('manifest_sha256','MANIFEST_SHA_MISMATCH')]:
            broken=dict(cfg);broken[k]='0'*64
            with self.subTest(k=k),self.assertRaisesRegex(EvidenceError,reason):Archive(broken,self.root/'v2')
    def test_path_traversal_windows_variants(self):
        self.assertEqual(safe_name('root/data.csv'),'root/data.csv')
        for name in ['/abs','C:/x','a/../x','a\\..\\x','a:stream','a/./b','a/NUL.txt','a /b']:
            with self.subTest(name=name),self.assertRaisesRegex(EvidenceError,'UNSAFE_MEMBER_PATH'):safe_name(name)
    def test_duplicates_case_and_links(self):
        safe_inventory([zipfile.ZipInfo('a')])
        for names in [['a','a'],['a','A']]:
            with self.assertRaisesRegex(EvidenceError,'DUPLICATE_OR_CASE_COLLISION'):safe_inventory([zipfile.ZipInfo(n) for n in names])
        link=zipfile.ZipInfo('link');link.external_attr=(stat.S_IFLNK|0o777)<<16
        with self.assertRaisesRegex(EvidenceError,'LINK_MEMBER_REJECTED'):safe_inventory([link])


class FixtureReader:
    def __init__(self,root):self.root=root;self.check=lambda:None
    def path(self,name):
        p=self.root/name
        if not p.exists():raise Unavailable('UNAVAILABLE_FROM_FROZEN_LIBRARY: '+name)
        return p
    def json(self,name):return read(self.path(name))
    def csv(self,name):
        import csv
        with self.path(name).open(newline='') as f:return list(csv.DictReader(f))


class ComponentTests(TempCase):
    def setUp(self):
        super().setUp();root=self.root;assets=[];orbits=[];context={'protocol':'frozen'}
        matrix=np.array([[1,np.inf,4],[2,3,np.inf]],dtype=float)
        for i in range(2):
            h=600.;a=6371+h;c=-(2*math.pi/(365.2421897*86400))/(1.5*(math.sqrt(5)*.484165143790815e-3)*math.sqrt(398600.4415/a**3)*(6378.1363/a)**2)
            row=dict(sat_id=f'Sat{i+1:03}',plane_id=0,altitude_km=h,inclination_deg=math.degrees(math.acos(c)),raan_deg=0.,arg_lat_deg=float(i*10))
            state=state_key(row);key=fingerprint(dict(state=state,context=context));origin=dict(native_protocol_hash='p')
            asset=dict(state=state,row=row,global_key=key,regional_key=key,origin=origin)
            for kind,data in [('global','hits.npz'),('regional','intervals.json')]:
                folder=root/(BASE+'runs/access_library/'+kind+'/'+key);folder.mkdir(parents=True)
                if kind=='global':np.savez(folder/data,first_hits=matrix[i])
                else:write(folder/data,{'target':[[i*3,i*3+1]]})
                digest=sha(folder/data);asset[kind+'_data_sha256']=digest
                write(folder/'entry.json',dict(state=state,original_row=row,context=context,origin=origin,data_sha256=digest))
            assets.append(asset);orbits.append(row)
        catdir=root/(BASE+'runs/component_catalog_v1');catdir.mkdir(parents=True)
        np.save(catdir/'first_hits.npy',matrix)
        cat=dict(assets=assets,global_context=context,regional_context=context,matrix_sha256=sha(catdir/'first_hits.npy'))
        write(catdir/'catalog.json',cat);self.cat=cat;self.catdir=catdir
        whole=root/'whole';whole.mkdir()
        write(whole/'promotion.json',dict(choice=dict(indices=[0,1],identity=fingerprint(sorted(a['state'] for a in assets)))))
        write(whole/'whole_review.json',dict(native_protocol_hash='p'))
        import csv
        with (whole/'orbits.csv').open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=list(orbits[0]));w.writeheader();w.writerows(orbits)
        self.inputs=Inputs.__new__(Inputs);self.inputs.arc=FixtureReader(root);self.inputs.targets=['target']
        self.inputs.cfg=dict(cases={'case':dict(N=2,path='whole')},raw_point_count=3,duration_s=10,matrix_bytes=(catdir/'first_hits.npy').stat().st_size,matrix_sha256=sha(catdir/'first_hits.npy'))
    def good(self):self.assertEqual(len(self.inputs.components('case')['hits']),2)
    def test_positive_and_pointwise_mismatch(self):
        self.good();self.assertEqual(compare_hits([1,np.inf],[1,np.inf],1e-6)['max_finite_first_hit_error_s'],0)
        with self.assertRaisesRegex(EvidenceError,'COMPOSITION_HIT_CLASSIFICATION_MISMATCH'):compare_hits([1,np.inf],[1,2],1e-6)
        with self.assertRaisesRegex(EvidenceError,'COMPOSITION_FIRST_HIT_TIME_MISMATCH'):compare_hits([1,2],[1,2.1],1e-6)
    def test_duplicate_asset(self):
        self.good();p=self.root/'whole/promotion.json';d=read(p);d['choice']['indices']=[0,0];write(p,d)
        with self.assertRaisesRegex(EvidenceError,'DUPLICATE_COMPONENT_ASSET'):self.inputs.components('case')
    def test_missing_asset(self):
        self.good();p=self.root/'whole/promotion.json';d=read(p);d['choice']['indices']=[0,9];write(p,d)
        with self.assertRaisesRegex(EvidenceError,'MISSING_COMPONENT_ASSET'):self.inputs.components('case')
    def test_state_misaligned(self):
        self.good();p=self.root/'whole/promotion.json';d=read(p);d['choice']['indices']=[1,0];write(p,d)
        with self.assertRaisesRegex(EvidenceError,'COMPONENT_STATE_IDENTITY_MISMATCH'):self.inputs.components('case')
    def test_matrix_digest(self):
        self.good();self.inputs.cfg['matrix_sha256']='0'*64
        with self.assertRaisesRegex(EvidenceError,'COMPONENT_MATRIX_DIGEST'):self.inputs.components('case')
    def test_source_matrix_disagreement(self):
        self.good();matrix=np.array([[9,np.inf,4],[2,3,np.inf]])
        np.save(self.catdir/'first_hits.npy',matrix);digest=sha(self.catdir/'first_hits.npy');self.inputs.cfg['matrix_sha256']=digest
        self.cat['matrix_sha256']=digest;write(self.catdir/'catalog.json',self.cat)
        with self.assertRaisesRegex(EvidenceError,'COMPONENT_SOURCE_MATRIX_MISMATCH'):self.inputs.components('case')
    def test_producer_protocol_mismatch(self):
        self.good();key=self.cat['assets'][0]['global_key'];p=self.root/(BASE+'runs/access_library/global/'+key+'/entry.json')
        d=read(p);d['context']={'protocol':'other'};write(p,d)
        with self.assertRaisesRegex(EvidenceError,'COMPONENT_PRODUCER_PROTOCOL'):self.inputs.components('case')
    def test_missing_data(self):
        self.good();key=self.cat['assets'][0]['regional_key'];(self.root/(BASE+'runs/access_library/regional/'+key+'/intervals.json')).unlink()
        with self.assertRaisesRegex(Unavailable,'UNAVAILABLE_FROM_FROZEN_LIBRARY'):self.inputs.components('case')
    def report_fixture(self):
        raw=dict(case_id='case',spec=dict(group='TEAM_COMPETITION_V3',evidence_type='saved_whole_constellation'),hits=np.array([1.,3.,4.]),keep=np.array([True,True,True]),
                 coords=np.array([[0,0],[1,1],[2,2]]),intervals={'target':[[0,1],[3,4]]},coordinate_permutation=np.arange(3),provenance={},read_counts={})
        self.inputs.case=lambda cid:raw
        self.inputs.cfg['absolute_time_tolerance_s']=1e-6
        protocol={k:1 for k in PHYSICAL_FIELDS};protocol['provenance']=dict(source_hash='fixture')
        report,_=evaluate_existing(self.inputs,'case',protocol)
        self.assertEqual(verify_report(self.inputs,'case',report,protocol)['status'],'PASS')
        return report,protocol
    def test_forged_component_comparison(self):
        report,protocol=self.report_fixture();report['components']['whole_comparison']['max_finite_first_hit_error_s']=1.
        checked=verify_report(self.inputs,'case',report,protocol)
        self.assertEqual(checked['status'],'FAIL');self.assertTrue(any('whole_comparison' in d['path'] for d in checked['differences']))
    def test_forged_component_endpoint_summary(self):
        report,protocol=self.report_fixture();report['components']['regional_comparison']['target']['max_endpoint_error_s']=1.
        checked=verify_report(self.inputs,'case',report,protocol)
        self.assertEqual(checked['status'],'FAIL');self.assertTrue(any('regional_comparison' in d['path'] for d in checked['differences']))


class CheckerTests(unittest.TestCase):
    def test_forged_report_rejected(self):
        class Raw:
            cfg=dict(duration_s=10,absolute_time_tolerance_s=1e-6)
            def case(self,cid):return dict(hits=np.array([1.,2.,np.inf]),keep=np.array([True,True,False]),intervals=None)
        proto={k:1 for k in PHYSICAL_FIELDS};report=dict(full_grid=coverage([1,2,np.inf],10),effective_grid=coverage([1,2],10),compatibility=compatibility(proto,proto))
        self.assertEqual(verify_report(Raw(),'case',report,proto)['status'],'PASS')
        report['effective_grid']['T100_s']=3
        result=verify_report(Raw(),'case',report,proto);self.assertEqual(result['status'],'FAIL')
        self.assertTrue(any(d['reason']=='NUMERIC_MISMATCH' for d in result['differences']))
    def test_classification_counts_exact(self):
        self.assertFalse(differences({'count':1},{'count':1}))
        self.assertEqual(differences({'count':1},{'count':1.0})[0]['reason'],'EXACT_MISMATCH')


class SealTests(TempCase):
    def valid(self):
        f=self.root/'seal';f.mkdir();write(f/'final_status.json',dict(status='BLOCKED',exit_code=2));write_seal(f,'BLOCKED',2,1,1)
        self.assertEqual(verify_seal(f)['exit_code'],2);return f
    def test_fake_receipt(self):
        self.valid();f=self.root/'fake';f.mkdir();write(f/'receipt.json',dict(status='PASS',exit_code=0))
        with self.assertRaisesRegex(EvidenceError,'SEAL_INCOMPLETE'):verify_seal(f)
    def test_tampered_report(self):
        f=self.valid();write(f/'final_status.json',dict(status='PASS',exit_code=0))
        with self.assertRaisesRegex(EvidenceError,'SEAL_BYTES_MISMATCH'):verify_seal(f)
    def test_forged_pass_coherent_hashes(self):
        self.valid();f=self.root/'fake';f.mkdir();write(f/'final_status.json',dict(status='PASS',exit_code=0));write_seal(f,'PASS',0,1,1)
        with self.assertRaisesRegex(EvidenceError,'SEAL_FAKE_PASS_GATES'):verify_seal(f)
    def test_exit_consistency(self):
        f=self.valid();r=read(f/'receipt.json');r['exit_code']=0;write(f/'receipt.json',r)
        with self.assertRaisesRegex(EvidenceError,'SEAL_STATUS_EXIT_INCONSISTENCY'):verify_seal(f)
    def test_unlisted_member(self):
        f=self.valid();(f/'extra.txt').write_text('extra')
        with self.assertRaisesRegex(EvidenceError,'SEAL_MEMBER_SET'):verify_seal(f)


class ControlTests(TempCase):
    def test_fail_dominates_timeout(self):
        s=Status();s.add('PASS','okay');self.assertEqual(s.exit_code,0)
        s.add('FAIL','bad bytes');s.add('BLOCKED','deadline');self.assertEqual((s.value,s.exit_code),('FAIL',1))
    def test_semantic_guard_classification(self):
        self.assertEqual(classify(PermissionError('unreadable')),'BLOCKED')
        self.assertEqual(classify(PermissionError('ROUND13_GUARD_NATIVE_IMPORT')),'FAIL')
    def test_lifecycle_expired(self):
        import time
        d=dict(start_epoch=time.time(),total_limit_seconds=60,pre_record_preparation_upper_bound_seconds=0,phase='input',phase_start_epoch=time.time(),phase_limits={'input':60})
        p=self.root/'life.json';write(p,d);Lifecycle(p).check()
        d['phase_start_epoch']-=120;write(p,d)
        with self.assertRaisesRegex(BudgetExceeded,'LIFECYCLE_OR_PHASE_LIMIT_EXCEEDED'):Lifecycle(p).check()
    def test_phase_cannot_restart(self):
        import time
        d=dict(start_epoch=time.time(),total_limit_seconds=60,pre_record_preparation_upper_bound_seconds=0,phase='validation',phase_start_epoch=time.time(),phase_limits={'validation':60})
        p=self.root/'life.json';write(p,d);l=Lifecycle(p);l.check()
        with self.assertRaisesRegex(ValueError,'PHASE_CANNOT_RESTART'):l.phase('input')

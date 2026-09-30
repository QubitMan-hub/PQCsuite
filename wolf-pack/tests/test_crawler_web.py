"""Static web edges resolve only supported syntax and preserve detector behavior."""
import json
import pytest
from wolfpack import pack

pytest.importorskip('tree_sitter')
pytest.importorskip('tree_sitter_javascript')
pytest.importorskip('tree_sitter_typescript')


def test_esmodules_crypto_wrapper_and_call_chain(tmp_path):
    (tmp_path/'keys.js').write_text('import crypto from "node:crypto";\nexport function digest(data) { return crypto.createHash("sha256").update(data); }')
    (tmp_path/'api.js').write_text('import {digest as hash} from "./keys.js";\nexport function payment(data) { return hash(data); }')
    r=pack.run(tmp_path,'web')
    assert any(c['target']=='keys.js#digest' for c in r.relationships['calls'])
    asset=next(a for a in r.assets if a.algo=='SHA-256' and a.params.get('code_impact'))
    assert asset.params['code_impact']['callers']==['api.js#payment']
    assert r.relationships['languages']=={'JavaScript':2}
    assert 'sha256' not in json.dumps(r.relationships)  # argument literal stays out of graph


def test_typescript_arrows_default_exports_and_js_interop(tmp_path):
    (tmp_path/'keys.ts').write_text('export default function digest(data: string): string { return data; }')
    (tmp_path/'api.ts').write_text('import hash from "./keys";\nexport const run = (data: string): string => hash(data);')
    r=pack.run(tmp_path,'ts')
    assert any(c['source']=='api.ts#run' and c['target']=='keys.ts#digest' for c in r.relationships['calls'])
    assert r.relationships['languages']=={'TypeScript':2}


def test_commonjs_named_and_default_exports(tmp_path):
    (tmp_path/'keys.cjs').write_text('exports.digest = function(data) { return data; };')
    (tmp_path/'entry.cjs').write_text('const {digest: hash} = require("./keys.cjs");\nmodule.exports = function(data) { return hash(data); };')
    (tmp_path/'app.cjs').write_text('const run = require("./entry.cjs");\nfunction route(data) { return run(data); }')
    calls=pack.run(tmp_path,'commonjs').relationships['calls']
    assert any(c['target']=='keys.cjs#digest' for c in calls)
    assert any(c['target']=='entry.cjs#default' for c in calls)


def test_shadowing_private_exports_and_anonymous_dispatch_stay_unresolved(tmp_path):
    (tmp_path/'keys.js').write_text('function privateKey() { return 0; }\nexport function key() {return 1;}')
    (tmp_path/'api.js').write_text('import {key, privateKey} from "./keys.js";\nfunction run(key) { return key(); }\nfunction other() { return privateKey(); }\nsetTimeout(()=>key(),10);')
    graph=pack.run(tmp_path,'ambiguous').relationships
    assert all(c['target'] is None for c in graph['calls'])
    assert not any(c['callee']=='key' and c['source']=='api.js#' for c in graph['calls'])


def test_malformed_web_syntax_reports_graph_gap(tmp_path):
    (tmp_path/'broken.ts').write_text('export function broken( { crypto.createHash("md5");')
    r=pack.run(tmp_path,'broken')
    assert r.relationships['skipped']=={'TypeScript (syntax errors)':1}
    assert not r.relationships['calls']


def test_web_same_line_defaults_and_method_scope_do_not_create_false_impact(tmp_path):
    (tmp_path/'api.js').write_text('import crypto from "node:crypto";\nexport function api(x=crypto.createHash("md5")) { return x; }\nclass A { helper() {return 1;} run() {return helper();} }')
    r=pack.run(tmp_path,'defaults')
    assert not any('code_impact' in a.params for a in r.assets)
    assert not any(c['target']=='api.js#A.helper' for c in r.relationships['calls'])


def test_optional_parser_missing_keeps_crypto_detection_and_explicit_coverage(tmp_path, monkeypatch):
    import sys
    (tmp_path/'api.js').write_text('const crypto=require("crypto"); crypto.createHash("sha256");')
    monkeypatch.setitem(sys.modules,'tree_sitter',None)
    r=pack.run(tmp_path,'base')
    assert r.relationships['skipped']=={'JavaScript':1}
    assert any(a.algo=='SHA-256' for a in r.assets)


def test_parser_depth_failure_keeps_other_files_and_crypto_detector(tmp_path, monkeypatch):
    from wolfpack import crawler_web
    (tmp_path/'api.js').write_text('const crypto=require("crypto"); crypto.createHash("md5");')
    (tmp_path/'safe.py').write_text('def safe(): return 1')
    def failure(crawler,path,text):
        crawler.add_symbol(path,'api','bogus','function',1,1)
        raise RecursionError('PRIVATE_SOURCE')
    monkeypatch.setattr(crawler_web,'observe',failure)
    r=pack.run(tmp_path,'depth')
    assert r.relationships['limited']
    assert not any(s['file']=='api.js' for s in r.relationships['symbols'])
    assert any(s['file']=='safe.py' for s in r.relationships['symbols'])
    assert any(a.algo=='MD5' for a in r.assets)


def test_directory_and_dotted_filename_imports_do_not_crash_or_misresolve(tmp_path):
    (tmp_path/'lib').mkdir()
    (tmp_path/'lib/index.js').write_text('exports.digest=function(data){return data;};')
    (tmp_path/'key.factory.js').write_text('export function make(){return 1;}')
    (tmp_path/'key.js').write_text('export function make(){return 2;}')
    (tmp_path/'api.js').write_text('const root=require("./"); const keys=require("./lib"); const unresolved=new require;\nimport {make} from "./key.factory";\nfunction run(){return keys.digest(make());}')
    r=pack.run(tmp_path,'directories')
    assert any(c['target']=='lib/index.js#digest' for c in r.relationships['calls'])
    assert any(c['target']=='key.factory.js#make' for c in r.relationships['calls'])
    assert not any(c['target']=='key.js#make' for c in r.relationships['calls'])


def test_commonjs_public_entrypoint_aliases_and_module_object(tmp_path):
    (tmp_path/'keys.js').write_text('function digest(data){return data;}\nexports.sign=digest;')
    (tmp_path/'entry.js').write_text('module.exports={sign:require("./keys")};')
    (tmp_path/'api.js').write_text('const keys=require("./keys");\nfunction run(){return keys.sign();}')
    r=pack.run(tmp_path,'aliases')
    assert any(c['target']=='keys.js#digest' for c in r.relationships['calls'])


def test_shadowed_commonjs_exports_are_not_public_graph_targets(tmp_path):
    (tmp_path/'private.js').write_text('const exports={};\nexports.digest=function(){return 1;};')
    (tmp_path/'api.js').write_text('const keys=require("./private");\nfunction run(){return keys.digest();}')
    assert not any(c['target']=='private.js#digest' for c in pack.run(tmp_path,'shadow-exports').relationships['calls'])

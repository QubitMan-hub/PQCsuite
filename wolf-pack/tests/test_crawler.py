"""Relationships must be evidenced, scoped, private, and useful across module boundaries."""
import ast
import json
import subprocess
from pathlib import Path

from wolfpack import pack, cbom
from wolfpack.crawler import CodeCrawler
from wolfpack.scouts import Scope, iter_files, snapshot


def test_cross_module_wrappers_are_attached_to_actual_crypto_findings(tmp_path):
    (tmp_path / "keys.py").write_text('from cryptography.hazmat.primitives.asymmetric import rsa\ndef make():\n    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n')
    (tmp_path / "service.py").write_text('from keys import make as issue\ndef enroll():\n    return issue()\ndef route():\n    return enroll()\n')
    result = pack.run(tmp_path, "test")
    asset = next(a for a in result.assets if a.algo == "RSA" and "code_impact" in a.params)
    impact = asset.params["code_impact"]
    assert impact["functions"] == ["keys.py#make"]
    assert impact["callers"] == ["service.py#enroll", "service.py#route"]
    component = cbom.algorithm_component(asset)
    assert any(p["name"] == "wolfpack:code-impact" for p in component["properties"])


def test_shadowing_dynamic_dispatch_and_ambiguous_definitions_are_not_confirmed():
    crawler = CodeCrawler()
    crawler.observe("a.py", ast.parse('def target(): pass\ndef target(): pass\ndef run(target):\n target()\n object().method()\ndef other(): target()'))
    graph = crawler.finish([])
    assert all(call["target"] is None for call in graph["calls"])
    assert all("unresolved" in call["confidence"] for call in graph["calls"])


def test_relative_imports_nested_functions_and_async_are_resolved(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg/__init__.py").write_text('')
    (tmp_path / "pkg/helper.py").write_text('def verify(): pass')
    (tmp_path / "pkg/api.py").write_text('from .helper import verify as check\nasync def endpoint():\n def inner():\n  return check()\n return inner()')
    graph = pack.run(tmp_path, "project").relationships
    assert any(c["target"] == "pkg/helper.py#verify" for c in graph["calls"])
    assert any(c["target"] == "pkg/api.py#endpoint.inner" for c in graph["calls"])


def test_graph_does_not_export_literals_snippets_or_docstrings():
    crawler = CodeCrawler()
    crawler.observe("safe.py", ast.parse('import hashlib\ndef digest():\n "PRIVATE_DOCSTRING"\n return hashlib.sha256(b"PRIVATE_ARGUMENT_VALUE")'))
    encoded = json.dumps(crawler.finish([]))
    assert "PRIVATE_" not in encoded
    assert "hashlib" in encoded


def test_shared_scope_respects_gitignore_exclusions_size_and_symlinks(tmp_path):
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    (tmp_path / '.gitignore').write_text('ignored.py\n')
    (tmp_path / 'ignored.py').write_text('import rsa')
    (tmp_path / 'kept.py').write_text('import hashlib')
    (tmp_path / 'large.py').write_text('x' * 2_000_001)
    (tmp_path / 'outside.py').symlink_to(Path(__file__).resolve())
    scope = snapshot(tmp_path, Scope(exclude=('large.py',)))
    names = [p.name for p in iter_files(tmp_path, scope)]
    assert 'kept.py' in names
    assert 'ignored.py' not in names
    assert 'outside.py' not in names
    assert 'large.py' not in names
    assert scope.files is not None


def test_nonpython_and_malformed_sources_keep_existing_detectors(tmp_path):
    (tmp_path / 'broken.py').write_text('def broken(')
    (tmp_path / 'code.js').write_text('const crypto = require("crypto"); crypto.createHash("sha256");')
    result = pack.run(tmp_path, 'mixed')
    assert result.relationships['languages'].get('Python', 0) == 0
    assert any(a.algo == 'SHA-256' for a in result.assets)
    assert any('could not be parsed' in n for n in result.notes)


def test_crypto_families_and_pqc_wrappers_have_supported_callers(tmp_path):
    (tmp_path/'crypto.py').write_text('''from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib, ssl, oqs
def protect():
 ec.ECDSA()
 ec.ECDH()
 AESGCM.generate_key(bit_length=256)
 hashlib.sha256(b"PRIVATE_VALUE")
 ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
 oqs.KeyEncapsulation("ML-KEM-768")
''')
    (tmp_path/'app.py').write_text('from crypto import protect\ndef workflow():\n return protect()')
    result=pack.run(tmp_path,'families')
    supported={a.algo for a in result.assets if a.params.get('code_impact',{}).get('callers') == ['app.py#workflow']}
    assert {'ECDSA','ECDH','AES','SHA-256','TLS 1.2','ML-KEM-768'} <= supported


def test_deferred_lambda_and_definition_defaults_are_not_function_uses(tmp_path):
    (tmp_path/'a.py').write_text('import hashlib\ndef deferred(x=hashlib.md5()):\n return lambda: hashlib.sha256()')
    result=pack.run(tmp_path,'deferred')
    assert not any('code_impact' in a.params for a in result.assets)


def test_git_fsmonitor_is_not_executed_during_source_discovery(tmp_path):
    subprocess.run(['git','init','-q',str(tmp_path)],check=True)
    hook=tmp_path/'dangerous-hook'
    hook.write_text('#!/bin/sh\ntouch '+str(tmp_path/'EXECUTED')+'\n')
    hook.chmod(0o700)
    subprocess.run(['git','-C',str(tmp_path),'config','core.fsmonitor',str(hook)],check=True)
    (tmp_path/'safe.py').write_text('import hashlib')
    assert list(iter_files(tmp_path))
    assert not (tmp_path/'EXECUTED').exists()


def test_same_line_default_is_not_reported_as_a_function_body_use(tmp_path):
    (tmp_path/'default.py').write_text('import hashlib\ndef api(x=hashlib.md5()): return x')
    result=pack.run(tmp_path,'default')
    assert not any('code_impact' in a.params for a in result.assets)


def test_module_objects_are_not_resolved_as_callable_functions(tmp_path):
    (tmp_path/'helper.py').write_text('x=1')
    (tmp_path/'api.py').write_text('import helper\ndef run(): helper()')
    result=pack.run(tmp_path,'module')
    assert all(c['target'] is None for c in result.relationships['calls'])


def test_python_package_reexports_preserve_crypto_caller_chain(tmp_path):
    (tmp_path/'keys').mkdir()
    (tmp_path/'keys/crypto.py').write_text('import hashlib\ndef digest(): return hashlib.sha256()')
    (tmp_path/'keys/__init__.py').write_text('from .crypto import digest as sign')
    (tmp_path/'api.py').write_text('from keys import sign\ndef payment(): return sign()')
    r=pack.run(tmp_path,'public-api')
    assert any(c['target']=='keys/crypto.py#digest' for c in r.relationships['calls'])
    asset=next(a for a in r.assets if a.algo=='SHA-256' and a.params.get('code_impact'))
    assert asset.params['code_impact']['callers']==['api.py#payment']


def test_cyclic_python_reexports_stay_unresolved(tmp_path):
    (tmp_path/'a.py').write_text('from b import helper')
    (tmp_path/'b.py').write_text('from a import helper\ndef run(): helper()')
    assert all(c['target'] is None for c in pack.run(tmp_path,'cycle').relationships['calls'])

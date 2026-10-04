"""Java and Go relationships: calls resolved only from declared types, imports and receivers; anything else stays unresolved."""
import importlib.util
import textwrap

import pytest

from wolfpack import pack

pytestmark = pytest.mark.skipif(not all(importlib.util.find_spec(m) for m in ("tree_sitter_java", "tree_sitter_go")),
                                reason="needs the crawler extra (tree-sitter Java and Go grammars)")


def write(root, files):
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")


def impact(result, variant):
    return next(a.params.get("code_impact") for a in result.assets if a.variant == variant)


def test_java_callers_through_fields_parameters_statics_and_constructors(tmp_path):
    write(tmp_path, {
        "src/com/acme/pay/Signer.java": """
            package com.acme.pay;
            import java.security.KeyPairGenerator;
            public class Signer {
                public byte[] sign(byte[] d) throws Exception {
                    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
                    g.initialize(2048);
                    return g.generateKeyPair().getPublic().getEncoded();
                }
                public static Signer standard() { return new Signer(); }
            }
        """,
        "src/com/acme/pay/Checkout.java": """
            package com.acme.pay;
            public class Checkout {
                private final Signer signer = new Signer();
                public byte[] pay(byte[] o) throws Exception { return signer.sign(o); }
                byte[] refund(Signer s, byte[] o) throws Exception { return s.sign(o); }
                byte[] audit(byte[] o) throws Exception { return Signer.standard().sign(o); }
                byte[] retry(byte[] o) throws Exception { return pay(o); }
            }
        """,
        "src/com/acme/web/Api.java": """
            package com.acme.web;
            import com.acme.pay.Checkout;
            public class Api {
                byte[] handle(Checkout c, byte[] o) throws Exception { return c.pay(o); }
                byte[] dynamic(Object any, byte[] o) throws Exception { return ((Runnable) any).hashCode() == 0 ? null : o; }
            }
        """,
    })
    found = impact(pack.run(tmp_path, "java"), "RSA-2048")
    assert found["functions"] == ["src/com/acme/pay/Signer.java#Signer.sign"]
    assert {"src/com/acme/pay/Checkout.java#Checkout.pay", "src/com/acme/pay/Checkout.java#Checkout.refund",
            "src/com/acme/pay/Checkout.java#Checkout.retry", "src/com/acme/web/Api.java#Api.handle"} <= set(found["callers"])
    assert "src/com/acme/pay/Checkout.java#Checkout.audit" not in found["callers"], "a chained call on an unknown return type is not guessed"
    assert "src/com/acme/web/Api.java#Api.dynamic" not in found["callers"]


def test_go_callers_across_packages_receivers_and_declared_variables(tmp_path):
    write(tmp_path, {
        "go.mod": "module example.com/app\n",
        "internal/keys/keys.go": """
            package keys
            import ("crypto/ecdsa"; "crypto/elliptic"; "crypto/rand")
            type Maker struct{}
            func (m *Maker) Make() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
            func New() (*ecdsa.PrivateKey, error) { var m Maker; return m.Make() }
        """,
        "internal/other/keys/keys.go": """
            package keys
            func New() int { return 1 }
        """,
        "cmd/api/main.go": """
            package main
            import k "example.com/app/internal/keys"
            func main() { start() }
            func start() { k.New() }
            func later(f func()) { f() }
            func inferred() { m := pick(); m.Make() }
            func pick() int { return 0 }
        """,
    })
    found = impact(pack.run(tmp_path, "go"), "ECDSA-P-256")
    assert found["functions"] == ["internal/keys/keys.go#Maker.Make"]
    assert set(found["callers"]) == {"internal/keys/keys.go#New", "cmd/api/main.go#start", "cmd/api/main.go#main"}


def test_broken_and_other_jvm_files_are_coverage_gaps(tmp_path):
    write(tmp_path, {"A.java": "class A { void f( }", "B.kt": "fun f() {}", "c.go": "package c\nfunc (\n"})
    rel = pack.run(tmp_path, "gaps").relationships
    assert rel["skipped"]["Java (syntax errors)"] == 1 and rel["skipped"]["Go (syntax errors)"] == 1
    assert rel["skipped"]["java (no relationship adapter)"] == 1, "Kotlin keeps its crypto detectors but has no relationship adapter"

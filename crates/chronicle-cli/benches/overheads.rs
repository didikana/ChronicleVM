use chronicle_asm::Assembler;
use chronicle_core::{CapabilityDecision, HostPolicy, Module, Verifier, Vm};
use chronicle_lang::Compiler;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::BTreeMap;

const CHR: &str = include_str!("fixtures/plugin.chr");
const CASM: &str = include_str!("fixtures/plugin.casm");

fn mock_policy() -> HostPolicy {
    HostPolicy {
        decisions: BTreeMap::from([
            (
                "log.print@1".into(),
                CapabilityDecision::Mock(chronicle_core::Value::Nil),
            ),
            (
                "clock.now@1".into(),
                CapabilityDecision::Mock(chronicle_core::Value::I64(1_800_000_000)),
            ),
            (
                "random.u64@1".into(),
                CapabilityDecision::Mock(chronicle_core::Value::I64(9_001)),
            ),
        ]),
    }
}

fn grant_policy() -> HostPolicy {
    HostPolicy {
        decisions: BTreeMap::from([
            (
                "log.print@1".into(),
                CapabilityDecision::Mock(chronicle_core::Value::Nil),
            ),
            ("clock.now@1".into(), CapabilityDecision::Grant),
            ("random.u64@1".into(), CapabilityDecision::Grant),
        ]),
    }
}

fn bench_overheads(c: &mut Criterion) {
    let module = Compiler::compile(CHR).unwrap().module;
    let binary = module.to_bytes().unwrap();
    let trace = {
        let mut vm = Vm::new(module.clone(), mock_policy()).unwrap();
        vm.run_with_trace("main").unwrap()
    };

    c.bench_function("source chr compile and verify", |b| {
        b.iter(|| {
            let compiled = Compiler::compile(black_box(CHR)).unwrap();
            Verifier::verify(&compiled.module).unwrap();
        })
    });

    c.bench_function("casm assemble and verify", |b| {
        b.iter(|| {
            let module = Assembler::parse(black_box(CASM)).unwrap();
            Verifier::verify(&module).unwrap();
        })
    });

    c.bench_function("binary cmod load and verify", |b| {
        b.iter(|| {
            let module = Module::from_bytes(black_box(&binary)).unwrap();
            Verifier::verify(&module).unwrap();
        })
    });

    c.bench_function("verifier overhead on cmod", |b| {
        b.iter(|| Verifier::verify(black_box(&module)).unwrap())
    });

    c.bench_function("baseline execution without trace", |b| {
        b.iter(|| {
            let mut vm = Vm::new(module.clone(), mock_policy()).unwrap();
            vm.run_entry("main").unwrap();
        })
    });

    c.bench_function("traced execution", |b| {
        b.iter(|| {
            let mut vm = Vm::new(module.clone(), mock_policy()).unwrap();
            vm.run_with_trace("main").unwrap();
        })
    });

    c.bench_function("replay execution", |b| {
        b.iter(|| Vm::replay(black_box(trace.clone())).unwrap())
    });

    c.bench_function("capability mediation mock", |b| {
        b.iter(|| {
            let mut vm = Vm::new(module.clone(), mock_policy()).unwrap();
            vm.run_entry("main").unwrap();
        })
    });

    c.bench_function("capability mediation grant", |b| {
        b.iter(|| {
            let mut vm = Vm::new(module.clone(), grant_policy()).unwrap();
            vm.run_entry("main").unwrap();
        })
    });
}

criterion_group!(benches, bench_overheads);
criterion_main!(benches);

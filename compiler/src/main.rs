use compiler_lib::modules::{lexer::lexer, parser::Parser, vm::{VM, Limits}};
use std::{env, fs, process::exit};
use log::{debug, info, error};

fn parse_args() -> (String, usize, bool, bool) {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.is_empty() || args.contains(&"-h".into()) {
        println!("edge [-c code] [-d] [-dd] [-q] [--sandbox] <file>"); 
        exit(0);
    }
    if let Some(pos) = args.iter().position(|a| a == "-c") {
        let code = args.get(pos + 1).cloned().unwrap_or_default();
        return (code, 0, false, false);
    }
    let p = args.iter().find(|&a| !a.starts_with('-')).cloned().unwrap_or_else(|| {
        error!("abort: execution failed because no input target was specified"); 
        exit(1);
    });
    let v = args.iter().filter(|&a| a == "-d").count() + (args.iter().filter(|&a| a == "-dd").count() * 2);
    (p, if v > 0 { v + 2 } else { 0 }, args.contains(&"-q".into()), args.contains(&"--sandbox".into()))
}

fn run(path: &str, v: usize, q: bool, sandbox: bool) -> Result<(), String> {
    let src = if path.ends_with(".py") {
        fs::read_to_string(path).map_err(|e| format!("io: cannot access '{}' because {}", path, e))?
    } else {
        path.to_string()
    };

    let (chunk, errs) = Parser::new(&src, lexer(&src)).parse();
    if !errs.is_empty() {
        errs.iter().for_each(|e| {
            error!("syntax: integrity check failed at {}:{} -> {} (parser rejected token stream)", path, e.line + 1, e.msg);
        });
        exit(1);
    }

    info!("emit: snapshot created [ops={} consts={}]", chunk.instructions.len(), chunk.constants.len());

    let limits = if sandbox { Limits::sandbox() } else { Limits::none() };
    let mut vm = VM::with_limits(&chunk, limits);
    
    let exec_result = vm.run();

    vm.output.iter().for_each(|l| println!("{l}"));

    if let Err(e) = exec_result {
        return Err(format!("trap: cpu-stop triggered by '{}'", e));
    }

    let (sp, tot) = vm.cache_stats();
    debug!("vm: specialization_ratio={}/{} [heap_footprint={}b]", sp, tot, vm.heap_usage());
    
    Ok(())
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let (p, v, q, sandbox) = parse_args();
    
    if let Err(e) = run(&p, v, q, sandbox) {
        error!("process terminated: {}", e);
        exit(1);
    }
}
use std::error::Error;

use vergen_gix::{Emitter, Gix};

fn main() {
    println!("cargo:rustc-env=VERGEN_GIT_SHA=unknown");
    if let Err(error) = emit_git_sha() {
        println!("cargo:warning=unable to determine git commit: {error}");
    }
}

fn emit_git_sha() -> Result<(), Box<dyn Error>> {
    let git = Gix::builder().sha(true).build();
    Emitter::default().add_instructions(&git)?.emit()?;
    Ok(())
}

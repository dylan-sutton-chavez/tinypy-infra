#![cfg_attr(target_arch = "wasm32", no_std)] // Enables no_std only for WASM builds.
 
extern crate alloc; // Enables heap allocation without the standard library.
 
/* 
Webassembly architecture entry point.
*/

#[cfg(any(target_arch = "wasm32", test))]
pub mod wasm;

/*
Internal modules accessed through all the package.
*/
 
pub mod modules {
    pub mod lexer;
    pub mod parser;
    pub mod vm;
}
 
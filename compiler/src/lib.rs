#![no_std]
extern crate alloc; // Enables heap allocation without the standard library.

/*
Internal modules accessed through all the package.
*/

pub mod modules {
    pub mod lexer;
    pub mod parser;
    pub mod vm;
}
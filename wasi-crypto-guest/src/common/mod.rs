mod array_output;
mod options;
pub(crate) use array_output::*;
pub(crate) use options::*;

pub mod algorithm_type {
    pub trait AlgorithmType {}

    #[derive(Debug)]
    pub struct Symmetric;
    #[derive(Debug)]
    pub struct Signatures;
    #[derive(Debug)]
    pub struct KeyExchange;

    impl AlgorithmType for Symmetric {}
    impl AlgorithmType for Signatures {}
    impl AlgorithmType for KeyExchange {}
}

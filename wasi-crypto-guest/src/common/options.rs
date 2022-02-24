use std::marker::PhantomData;

use super::algorithm_type;
use crate::raw;

#[derive(Debug)]
pub(crate) struct Options<T: algorithm_type::AlgorithmType> {
    pub handle: raw::Options,
    _t: PhantomData<T>,
}

impl<T: algorithm_type::AlgorithmType> Options<T> {
    pub fn new(alg_type: raw::AlgorithmType) -> Self {
        let handle = unsafe { raw::options_open(alg_type) }.unwrap();
        Options {
            handle,
            _t: PhantomData,
        }
    }
}

impl<T: algorithm_type::AlgorithmType> Drop for Options<T> {
    fn drop(&mut self) {
        unsafe { raw::options_close(self.handle) }.unwrap()
    }
}

pub(crate) struct OptOptions;

impl OptOptions {
    pub fn none() -> raw::OptOptions {
        raw::OptOptions {
            tag: raw::OPT_OPTIONS_U_NONE,
            u: raw::OptOptionsUnion { none: false },
        }
    }

    pub fn some<T: algorithm_type::AlgorithmType>(options: &Options<T>) -> raw::OptOptions {
        raw::OptOptions {
            tag: raw::OPT_OPTIONS_U_SOME,
            u: raw::OptOptionsUnion {
                some: options.handle,
            },
        }
    }
}

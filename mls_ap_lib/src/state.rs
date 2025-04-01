use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

pub(crate) struct AsState {
    credential: SignatureKeyPair,
    provider: OpenMlsRustCrypto,
}

impl AsState {
    pub(crate) fn new(credential: SignatureKeyPair, crypto: OpenMlsRustCrypto) -> Self {
        Self {
            credential,
            provider: crypto,
        }
    }
}

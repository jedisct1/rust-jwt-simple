mod test {
    use crate::prelude::*;

    #[test]
    fn test_symmetric() -> Result<(), WasiCryptoError> {
        let mut options = SymmetricOptions::new();
        let nonce = [0u8; 12];
        options.set("nonce", &nonce)?;
        let key = SymmetricKey::generate("AES-128-GCM", Some(&options))?;
        let mut state = SymmetricState::new("AES-128-GCM", Some(&key), Some(&options))?;
        let ciphertext = state.encrypt(b"test")?;
        let mut state = SymmetricState::new("AES-128-GCM", Some(&key), Some(&options))?;
        state.decrypt(&ciphertext)?;

        let key = SymmetricKey::generate("XOODYAK-128", None)?;
        let mut state = SymmetricState::new("XOODYAK-128", Some(&key), Some(&options))?;
        let _ = state.squeeze_tag()?;
        let mut ciphertext = vec![0u8; 4];
        let tag = state.encrypt_detached(&mut ciphertext, b"test")?;
        state.ratchet()?;

        let mut state = SymmetricState::new("XOODYAK-128", Some(&key), Some(&options))?;
        let session_tag = state.squeeze_tag()?;
        let mut out = vec![0u8; 4];

        state.decrypt_detached(&mut out, &ciphertext, &tag)?;

        let mut state = SymmetricState::new("XOODYAK-128", Some(&key), Some(&options))?;
        state.verify(&session_tag)?;

        let mut state = SymmetricState::new("SHA-512/256", None, None)?;
        state.absorb(b"test")?;
        state.squeeze(32)?;

        Ok(())
    }

    #[test]
    fn test_signatures() -> Result<(), WasiCryptoError> {
        let _ = SignaturePublicKey::from_raw("Ed25519", &[0; 32])?;

        let kp = SignatureKeyPair::generate("Ed25519")?;
        let signature = kp.sign("hello")?;

        kp.publickey()?.signature_verify("hello", &signature)?;

        Ok(())
    }

    #[test]
    fn test_symmetric_hash() -> Result<(), WasiCryptoError> {
        let hash = Hash::hash("SHA-256", b"test", 32, None)?;
        assert_eq!(hash.len(), 32);
        Ok(())
    }

    #[test]
    fn test_symmetric_auth() -> Result<(), WasiCryptoError> {
        let key = AuthKey::generate("HMAC/SHA-512")?;
        let tag = Auth::auth("test", &key)?;
        Auth::auth_verify("test", &key, tag)?;
        Ok(())
    }

    #[test]
    fn test_symmetric_hkdf() -> Result<(), WasiCryptoError> {
        let key = HkdfKey::generate("HKDF-EXTRACT/SHA-512")?;
        let prk = Hkdf::new("HKDF-EXPAND/SHA-512", &key, Some(b"salt"))?;
        let derived_key = prk.expand("info", 100)?;
        assert_eq!(derived_key.len(), 100);
        Ok(())
    }

    #[test]
    fn test_symmetric_aead() -> Result<(), WasiCryptoError> {
        let key = AeadKey::generate("AES-128-GCM")?;
        let nonce = [0u8; 12];
        let mut aead = Aead::new(&key, Some(&nonce), Some(b"ad"))?;
        let ct = aead.encrypt("test")?;
        let mut aead = Aead::new(&key, Some(&nonce), Some(b"ad"))?;
        let pt = aead.decrypt(ct)?;
        assert_eq!(pt, b"test");

        Ok(())
    }
}

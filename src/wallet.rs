use bip39::{Mnemonic, Seed};
use fuel_crypto::{Hasher, SecretKey};
use fuel_types::Address;
use serde::{ser::SerializeStruct, Serialize, Serializer};

#[derive(Clone, Debug)]
pub(crate) struct Wallet {
    mnemonic: Mnemonic,
    secret: SecretKey,
    address: Address,
}

impl Serialize for Wallet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Wallet", 3)?;
        state.serialize_field("mnemonic", self.mnemonic.phrase())?;
        state.serialize_field("secret", &format!("{:#x}", self.secret))?;
        state.serialize_field("address", &format!("{:#x}", self.address))?;
        state.end()
    }
}

impl From<Mnemonic> for Wallet {
    fn from(mnemonic: Mnemonic) -> Self {
        let seed = Seed::new(&mnemonic, "");
        let seed_bytes: &[u8] = seed.as_bytes();
        let secret_bytes = Hasher::hash(seed_bytes);
        let secret = SecretKey::try_from(secret_bytes).unwrap();
        let public_key = secret.public_key();
        let address = Address::from(*public_key.hash());
        Self {
            mnemonic,
            secret,
            address,
        }
    }
}

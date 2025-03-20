use alloy::primitives::address;

use crate::{
    clients::{
        arbiters::ArbitersAddresses, attestation::AttestationAddresses, erc1155::Erc1155Addresses,
        erc20::Erc20Addresses, erc721::Erc721Addresses,
        string_obligation::StringObligationAddresses, token_bundle::TokenBundleAddresses,
    },
    AddressConfig,
};

pub const FILECOIN_CALIBRATION_ADDRESSES: AddressConfig = AddressConfig {
    arbiters_addresses: Some(ArbitersAddresses {
        specific_attestation_arbiter: address!("0x10788ba2c4c65d1e97bc6005436b61c2c2e51572"),
        trusted_party_arbiter: address!("0xed550301b3258612509615bbddd4b2383cf32df4"),
        trivial_arbiter: address!("0x6e9bc0d34fff16140401fc51653347be0a1f0ec0"),
        trusted_oracle_arbiter: address!("0x5f1db54dbc5006894ef6c43b2174c05ccaa250ec"),
    }),
    string_obligation_addresses: Some(StringObligationAddresses {
        eas: address!("0x3c79a0225380fb6f3cb990ffc4e3d5af4546b524"),
        obligation: address!("0xbb022fc36d0cc97b6cae5a2e15d45b7a9ad46f99"),
    }),
    erc20_addresses: Some(Erc20Addresses {
        eas: address!("0x3c79a0225380fb6f3cb990ffc4e3d5af4546b524"),
        barter_utils: address!("0xaeeddd0a2f24f7286eae7e7fa5cea746fcf064fc"),
        escrow_obligation: address!("0x235792a6d077a04fb190a19f362acecab7866ab5"),
        payment_obligation: address!("0xd8b6199aa91992f5d3bafddc3372b391e46c92ce"),
    }),
    erc721_addresses: Some(Erc721Addresses {
        eas: address!("0x3c79a0225380fb6f3cb990ffc4e3d5af4546b524"),
        barter_utils: address!("0x2129f46737135fe4ebb3c49953487122088bc739"),
        escrow_obligation: address!("0x336f2f91b093001edd90e49216422b33b8b4e03b"),
        payment_obligation: address!("0x4b9b6ff4a7c2bc89eee6f28355b9a94e6649bbf8"),
    }),
    erc1155_addresses: Some(Erc1155Addresses {
        eas: address!("0x3c79a0225380fb6f3cb990ffc4e3d5af4546b524"),
        barter_utils: address!("0x66b7398b2bb322bb4a480ae370142c02c52b886a"),
        escrow_obligation: address!("0x553e4de0916074201a9d32123efcc8f734ee5675"),
        payment_obligation: address!("0x903caa028b1848ab8fdd15c4ccd20c4e7be2b1c0"),
    }),
    token_bundle_addresses: Some(TokenBundleAddresses {
        eas: address!("0x3c79a0225380fb6f3cb990ffc4e3d5af4546b524"),
        barter_utils: address!("0xb63cf08c6623f69d2ad34e37b8a68cca6c125d49"),
        escrow_obligation: address!("0xdcc1104325d9d99c6bd5faa0804a7d743f3d0c20"),
        payment_obligation: address!("0xab43cce34a7b831fa7ab134bcdc21a6ba20882b6"),
    }),
    attestation_addresses: Some(AttestationAddresses {
        eas: address!("0x3c79a0225380fb6f3cb990ffc4e3d5af4546b524"),
        eas_schema_registry: address!("0x2bb94a4e6ec0d81de7f81007b572ac09a5be37b4"),
        barter_utils: address!("0x0c19138441e1bee2964e65e0edf1702d59a2e786"),
        escrow_obligation: address!("0x553e4de0916074201a9d32123efcc8f734ee5675"),
        escrow_obligation_2: address!("0x11c3931f2715d8fca8ea5ca79fac4bbbcdbe9903"),
    }),
};

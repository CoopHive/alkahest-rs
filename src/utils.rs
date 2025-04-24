use alloy::{
    network::{EthereumWallet, TxSigner},
    node_bindings::AnvilInstance,
    primitives::{Address, PrimitiveSignature},
    providers::{ProviderBuilder, WsConnect},
    signers::local::PrivateKeySigner,
};

use crate::{
    AddressConfig, AlkahestClient,
    clients::{
        arbiters::ArbitersAddresses, attestation::AttestationAddresses, erc20::Erc20Addresses,
        erc721::Erc721Addresses, erc1155::Erc1155Addresses,
        string_obligation::StringObligationAddresses, token_bundle::TokenBundleAddresses,
    },
    contracts::{
        AllArbiter, AnyArbiter, AttestationBarterUtils, AttestationEscrowObligation,
        AttestationEscrowObligation2, ERC20EscrowObligation, ERC20PaymentObligation,
        ERC721EscrowObligation, ERC721PaymentObligation, ERC1155EscrowObligation,
        ERC1155PaymentObligation, IntrinsicsArbiter, IntrinsicsArbiter2,
        SpecificAttestationArbiter, StringObligation, TokenBundleBarterUtils, TrivialArbiter,
        TrustedOracleArbiter, TrustedPartyArbiter,
        erc20_barter_cross_token::ERC20BarterCrossToken,
        erc721_barter_cross_token::ERC721BarterCrossToken,
        erc1155_barter_cross_token::ERC1155BarterCrossToken,
        token_bundle::{TokenBundleEscrowObligation, TokenBundlePaymentObligation},
    },
    fixtures::{EAS, MockERC20Permit, MockERC721, MockERC1155, SchemaRegistry},
    types::{PublicProvider, WalletProvider},
};

pub async fn get_wallet_provider<T: TxSigner<PrimitiveSignature> + Sync + Send + 'static>(
    private_key: T,
    rpc_url: impl ToString,
) -> eyre::Result<WalletProvider> {
    let wallet = EthereumWallet::from(private_key);
    let ws = WsConnect::new(rpc_url.to_string());

    let provider = ProviderBuilder::new().wallet(wallet).on_ws(ws).await?;

    Ok(provider)
}

pub async fn get_public_provider(rpc_url: impl ToString) -> eyre::Result<PublicProvider> {
    let ws = WsConnect::new(rpc_url.to_string());

    let provider = ProviderBuilder::new().on_ws(ws).await?;

    Ok(provider)
}

pub async fn setup_test_environment() -> eyre::Result<TestContext> {
    let anvil = alloy::node_bindings::Anvil::new().try_spawn()?;

    let god: PrivateKeySigner = anvil.keys()[0].clone().into();
    let god_wallet = EthereumWallet::from(god.clone());

    let ws = WsConnect::new(anvil.ws_endpoint_url());
    let god_provider = ProviderBuilder::new().wallet(god_wallet).on_ws(ws).await?;
    let god_provider_ = god_provider.clone();

    let schema_registry = SchemaRegistry::deploy(&god_provider).await?;
    let eas = EAS::deploy(&god_provider, schema_registry.address().clone()).await?;

    let mock_erc20_a =
        MockERC20Permit::deploy(&god_provider, "Mock Erc20".into(), "TK1".into()).await?;
    let mock_erc20_b =
        MockERC20Permit::deploy(&god_provider, "Mock Erc20".into(), "TK2".into()).await?;
    let mock_erc721_a = MockERC721::deploy(&god_provider).await?;
    let mock_erc721_b = MockERC721::deploy(&god_provider).await?;
    let mock_erc1155_a = MockERC1155::deploy(&god_provider).await?;
    let mock_erc1155_b = MockERC1155::deploy(&god_provider).await?;

    let specific_attestation_arbiter = SpecificAttestationArbiter::deploy(&god_provider).await?;
    let trivial_arbiter = TrivialArbiter::deploy(&god_provider).await?;
    let trusted_oracle_arbiter = TrustedOracleArbiter::deploy(&god_provider).await?;
    let trusted_party_arbiter = TrustedPartyArbiter::deploy(&god_provider).await?;
    let intrinsics_arbiter = IntrinsicsArbiter::deploy(&god_provider).await?;
    let intrinsics_arbiter_2 = IntrinsicsArbiter2::deploy(&god_provider).await?;
    let any_arbiter = AnyArbiter::deploy(&god_provider).await?;
    let all_arbiter = AllArbiter::deploy(&god_provider).await?;

    macro_rules! deploy_obligation {
        ($name:ident) => {
            $name::deploy(
                &god_provider,
                eas.address().clone(),
                schema_registry.address().clone(),
            )
            .await?
        };
    }

    let attestation_escrow_obligation = deploy_obligation!(AttestationEscrowObligation);
    let attestation_escrow_obligation_2 = deploy_obligation!(AttestationEscrowObligation2);
    let bundle_escrow_obligation = deploy_obligation!(TokenBundleEscrowObligation);
    let bundle_payment_obligation = deploy_obligation!(TokenBundlePaymentObligation);
    let erc20_escrow_obligation = deploy_obligation!(ERC20EscrowObligation);
    let erc20_payment_obligation = deploy_obligation!(ERC20PaymentObligation);
    let erc721_escrow_obligation = deploy_obligation!(ERC721EscrowObligation);
    let erc721_payment_obligation = deploy_obligation!(ERC721PaymentObligation);
    let erc1155_escrow_obligation = deploy_obligation!(ERC1155EscrowObligation);
    let erc1155_payment_obligation = deploy_obligation!(ERC1155PaymentObligation);
    let string_obligation = deploy_obligation!(StringObligation);

    macro_rules! deploy_cross_token {
        ($name:ident) => {
            $name::deploy(
                &god_provider,
                eas.address().clone(),
                erc20_escrow_obligation.address().clone(),
                erc20_payment_obligation.address().clone(),
                erc721_escrow_obligation.address().clone(),
                erc721_payment_obligation.address().clone(),
                erc1155_escrow_obligation.address().clone(),
                erc1155_payment_obligation.address().clone(),
                bundle_escrow_obligation.address().clone(),
                bundle_payment_obligation.address().clone(),
            )
            .await?
        };
    }

    let attestation_barter_utils = AttestationBarterUtils::deploy(
        &god_provider,
        eas.address().clone(),
        schema_registry.address().clone(),
        attestation_escrow_obligation_2.address().clone(),
    )
    .await?;
    let bundle_barter_utils = TokenBundleBarterUtils::deploy(
        &god_provider,
        eas.address().clone(),
        bundle_escrow_obligation.address().clone(),
        bundle_payment_obligation.address().clone(),
    )
    .await?;
    let erc20_barter_utils = deploy_cross_token!(ERC20BarterCrossToken);
    let erc721_barter_utils = deploy_cross_token!(ERC721BarterCrossToken);
    let erc1155_barter_utils = deploy_cross_token!(ERC1155BarterCrossToken);

    let alice: PrivateKeySigner = anvil.keys()[1].clone().into();
    let bob: PrivateKeySigner = anvil.keys()[2].clone().into();

    let addresses = AddressConfig {
        arbiters_addresses: Some(ArbitersAddresses {
            specific_attestation_arbiter: specific_attestation_arbiter.address().clone(),
            trivial_arbiter: trivial_arbiter.address().clone(),
            trusted_oracle_arbiter: trusted_oracle_arbiter.address().clone(),
            trusted_party_arbiter: trusted_party_arbiter.address().clone(),
            intrinsics_arbiter: intrinsics_arbiter.address().clone(),
            intrinsics_arbiter_2: intrinsics_arbiter_2.address().clone(),
            any_arbiter: any_arbiter.address().clone(),
            all_arbiter: all_arbiter.address().clone(),
        }),
        string_obligation_addresses: Some(StringObligationAddresses {
            eas: eas.address().clone(),
            obligation: string_obligation.address().clone(),
        }),
        erc20_addresses: Some(Erc20Addresses {
            eas: eas.address().clone(),
            barter_utils: erc20_barter_utils.address().clone(),
            escrow_obligation: erc20_escrow_obligation.address().clone(),
            payment_obligation: erc20_payment_obligation.address().clone(),
        }),
        erc721_addresses: Some(Erc721Addresses {
            eas: eas.address().clone(),
            barter_utils: erc721_barter_utils.address().clone(),
            escrow_obligation: erc721_escrow_obligation.address().clone(),
            payment_obligation: erc721_payment_obligation.address().clone(),
        }),
        erc1155_addresses: Some(Erc1155Addresses {
            eas: eas.address().clone(),
            barter_utils: erc1155_barter_utils.address().clone(),
            escrow_obligation: erc1155_escrow_obligation.address().clone(),
            payment_obligation: erc1155_payment_obligation.address().clone(),
        }),
        token_bundle_addresses: Some(TokenBundleAddresses {
            eas: eas.address().clone(),
            barter_utils: bundle_barter_utils.address().clone(),
            escrow_obligation: bundle_escrow_obligation.address().clone(),
            payment_obligation: bundle_payment_obligation.address().clone(),
        }),
        attestation_addresses: Some(AttestationAddresses {
            eas: eas.address().clone(),
            eas_schema_registry: schema_registry.address().clone(),
            barter_utils: attestation_barter_utils.address().clone(),
            escrow_obligation: attestation_escrow_obligation.address().clone(),
            escrow_obligation_2: attestation_escrow_obligation_2.address().clone(),
        }),
    };

    let alice_client = AlkahestClient::new(
        alice.clone(),
        anvil.ws_endpoint_url(),
        Some(addresses.clone()),
    )
    .await?;
    let bob_client = AlkahestClient::new(
        bob.clone(),
        anvil.ws_endpoint_url(),
        Some(addresses.clone()),
    )
    .await?;

    Ok(TestContext {
        anvil,
        alice,
        bob,
        god,
        god_provider: god_provider_,
        alice_client,
        bob_client,
        addresses,
        mock_addresses: MockAddresses {
            erc20_a: mock_erc20_a.address().clone(),
            erc20_b: mock_erc20_b.address().clone(),
            erc721_a: mock_erc721_a.address().clone(),
            erc721_b: mock_erc721_b.address().clone(),
            erc1155_a: mock_erc1155_a.address().clone(),
            erc1155_b: mock_erc1155_b.address().clone(),
        },
    })
}

pub struct TestContext {
    pub anvil: AnvilInstance,
    pub alice: PrivateKeySigner,
    pub bob: PrivateKeySigner,
    pub god: PrivateKeySigner,
    pub god_provider: WalletProvider,
    pub alice_client: AlkahestClient,
    pub bob_client: AlkahestClient,
    pub addresses: AddressConfig,
    pub mock_addresses: MockAddresses,
}

pub struct MockAddresses {
    pub erc20_a: Address,
    pub erc20_b: Address,
    pub erc721_a: Address,
    pub erc721_b: Address,
    pub erc1155_a: Address,
    pub erc1155_b: Address,
}

use crate::extensions::{
    ArbitersModule, AttestationModule, Erc20Module, Erc721Module, Erc1155Module,
    StringObligationModule, TokenBundleModule,
};
use alloy::primitives::Address;

/// Trait that modules implement to expose their contract addresses
pub trait ContractModule {
    /// The enum type representing available contracts for this module
    type Contract: Copy;

    /// Get the address of a specific contract
    fn address(&self, contract: Self::Contract) -> Address;
}

/// Available contracts in the ERC20 module
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erc20Contract {
    /// EAS (Ethereum Attestation Service) contract
    Eas,
    /// Barter utilities contract for ERC20 tokens
    BarterUtils,
    /// Escrow obligation contract for ERC20 tokens
    EscrowObligation,
    /// Payment obligation contract for ERC20 tokens
    PaymentObligation,
}

impl ContractModule for Erc20Module {
    type Contract = Erc20Contract;

    fn address(&self, contract: Self::Contract) -> Address {
        match contract {
            Erc20Contract::Eas => self.client.addresses.eas,
            Erc20Contract::BarterUtils => self.client.addresses.barter_utils,
            Erc20Contract::EscrowObligation => self.client.addresses.escrow_obligation,
            Erc20Contract::PaymentObligation => self.client.addresses.payment_obligation,
        }
    }
}

/// Available contracts in the ERC721 module
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erc721Contract {
    /// EAS (Ethereum Attestation Service) contract
    Eas,
    /// Barter utilities contract for ERC721 tokens
    BarterUtils,
    /// Escrow obligation contract for ERC721 tokens
    EscrowObligation,
    /// Payment obligation contract for ERC721 tokens
    PaymentObligation,
}

impl ContractModule for Erc721Module {
    type Contract = Erc721Contract;

    fn address(&self, contract: Self::Contract) -> Address {
        match contract {
            Erc721Contract::Eas => self.client.addresses.eas,
            Erc721Contract::BarterUtils => self.client.addresses.barter_utils,
            Erc721Contract::EscrowObligation => self.client.addresses.escrow_obligation,
            Erc721Contract::PaymentObligation => self.client.addresses.payment_obligation,
        }
    }
}

/// Available contracts in the ERC1155 module
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erc1155Contract {
    /// EAS (Ethereum Attestation Service) contract
    Eas,
    /// Barter utilities contract for ERC1155 tokens
    BarterUtils,
    /// Escrow obligation contract for ERC1155 tokens
    EscrowObligation,
    /// Payment obligation contract for ERC1155 tokens
    PaymentObligation,
}

impl ContractModule for Erc1155Module {
    type Contract = Erc1155Contract;

    fn address(&self, contract: Self::Contract) -> Address {
        match contract {
            Erc1155Contract::Eas => self.client.addresses.eas,
            Erc1155Contract::BarterUtils => self.client.addresses.barter_utils,
            Erc1155Contract::EscrowObligation => self.client.addresses.escrow_obligation,
            Erc1155Contract::PaymentObligation => self.client.addresses.payment_obligation,
        }
    }
}

/// Available contracts in the TokenBundle module
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenBundleContract {
    /// EAS (Ethereum Attestation Service) contract
    Eas,
    /// Barter utilities contract for token bundles
    BarterUtils,
    /// Escrow obligation contract for token bundles
    EscrowObligation,
    /// Payment obligation contract for token bundles
    PaymentObligation,
}

impl ContractModule for TokenBundleModule {
    type Contract = TokenBundleContract;

    fn address(&self, contract: Self::Contract) -> Address {
        match contract {
            TokenBundleContract::Eas => self.client.addresses.eas,
            TokenBundleContract::BarterUtils => self.client.addresses.barter_utils,
            TokenBundleContract::EscrowObligation => self.client.addresses.escrow_obligation,
            TokenBundleContract::PaymentObligation => self.client.addresses.payment_obligation,
        }
    }
}

/// Available contracts in the Attestation module
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationContract {
    /// EAS (Ethereum Attestation Service) contract
    Eas,
    /// EAS Schema Registry contract
    EasSchemaRegistry,
    /// Barter utilities contract for attestations
    BarterUtils,
    /// Escrow obligation contract for attestations
    EscrowObligation,
    /// Alternative escrow obligation contract for attestations
    EscrowObligation2,
}

impl ContractModule for AttestationModule {
    type Contract = AttestationContract;

    fn address(&self, contract: Self::Contract) -> Address {
        match contract {
            AttestationContract::Eas => self.client.addresses.eas,
            AttestationContract::EasSchemaRegistry => self.client.addresses.eas_schema_registry,
            AttestationContract::BarterUtils => self.client.addresses.barter_utils,
            AttestationContract::EscrowObligation => self.client.addresses.escrow_obligation,
            AttestationContract::EscrowObligation2 => self.client.addresses.escrow_obligation_2,
        }
    }
}

/// Available contracts in the StringObligation module
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringObligationContract {
    /// EAS (Ethereum Attestation Service) contract
    Eas,
    /// String obligation contract
    Obligation,
}

impl ContractModule for StringObligationModule {
    type Contract = StringObligationContract;

    fn address(&self, contract: Self::Contract) -> Address {
        match contract {
            StringObligationContract::Eas => self.client.addresses.eas,
            StringObligationContract::Obligation => self.client.addresses.obligation,
        }
    }
}

/// Available contracts in the Arbiters module
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArbitersContract {
    /// EAS (Ethereum Attestation Service) contract
    Eas,
    /// Specific attestation arbiter
    SpecificAttestationArbiter,
    /// Trusted party arbiter
    TrustedPartyArbiter,
    /// Trivial arbiter (always accepts)
    TrivialArbiter,
    /// Trusted oracle arbiter
    TrustedOracleArbiter,
    // Add more as needed - there are many arbiter contracts
}

impl ContractModule for ArbitersModule {
    type Contract = ArbitersContract;

    fn address(&self, contract: Self::Contract) -> Address {
        match contract {
            ArbitersContract::Eas => self.client.addresses.eas,
            ArbitersContract::SpecificAttestationArbiter => {
                self.client.addresses.specific_attestation_arbiter
            }
            ArbitersContract::TrustedPartyArbiter => self.client.addresses.trusted_party_arbiter,
            ArbitersContract::TrivialArbiter => self.client.addresses.trivial_arbiter,
            ArbitersContract::TrustedOracleArbiter => self.client.addresses.trusted_oracle_arbiter,
        }
    }
}

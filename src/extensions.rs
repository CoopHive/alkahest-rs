use crate::{
    AlkahestClient, DefaultExtensionAddresses,
    clients::{
        arbiters::{ArbitersAddresses, ArbitersClient},
        attestation::{AttestationAddresses, AttestationClient},
        erc20::{Erc20Addresses, Erc20Client},
        erc721::{Erc721Addresses, Erc721Client},
        erc1155::{Erc1155Addresses, Erc1155Client},
        oracle::{OracleAddresses, OracleClient},
        string_obligation::{StringObligationAddresses, StringObligationClient},
        token_bundle::{TokenBundleAddresses, TokenBundleClient},
    },
};
use alloy::signers::local::PrivateKeySigner;
use std::any::Any;

pub trait AlkahestExtension: Clone + Send + Sync {
    /// Associated type for the client - can be () for extensions without a single client
    type Client: Clone + Send + Sync + 'static;

    fn init(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<DefaultExtensionAddresses>,
    ) -> impl std::future::Future<Output = eyre::Result<Self>> + Send;

    /// Generic initialization method that can accept any addresses type
    fn init_with_addresses<A: Clone + Send + Sync + 'static>(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<A>,
    ) -> impl std::future::Future<Output = eyre::Result<Self>> + Send {
        // Default implementation that throws an error - must be implemented by each module
        async move {
            Err(eyre::eyre!(
                "init_with_addresses not implemented for {}. Please implement this method or use init() instead.",
                std::any::type_name::<Self>()
            ))
        }
    }

    /// Get the client directly - implement this for modules with a single client
    fn client(&self) -> Option<&Self::Client> {
        None
    }

    /// Recursively search for a client by type - this is the main method
    fn find_client<T: Clone + Send + Sync + 'static>(&self) -> Option<&T> {
        // Default implementation for modules with a single client
        if let Some(client) = self.client() {
            let client_any: &dyn Any = client;
            if let Some(downcasted) = client_any.downcast_ref::<T>() {
                return Some(downcasted);
            }
        }
        None
    }

    /// Get a reference to a client by type, panicking if not found
    fn get_client<T: Clone + Send + Sync + 'static>(&self) -> &T {
        self.find_client::<T>()
            .unwrap_or_else(|| panic!("Client {} not found", std::any::type_name::<T>()))
    }

    /// Check if a client of type T exists
    fn has_client<T: Clone + Send + Sync + 'static>(&self) -> bool {
        self.find_client::<T>().is_some()
    }
}

#[derive(Clone)]
pub struct NoExtension;

impl AlkahestExtension for NoExtension {
    type Client = ();

    async fn init(
        _private_key: PrivateKeySigner,
        _rpc_url: impl ToString + Clone + Send,
        _addresses: Option<DefaultExtensionAddresses>,
    ) -> eyre::Result<Self> {
        Ok(NoExtension)
    }

    async fn init_with_addresses<A: Clone + Send + Sync + 'static>(
        _private_key: PrivateKeySigner,
        _rpc_url: impl ToString + Clone + Send,
        _addresses: Option<A>,
    ) -> eyre::Result<Self> {
        Ok(NoExtension)
    }

    // Uses default implementation that returns None
}

/// Joins two extensions together into a single extension type
#[derive(Clone)]
pub struct JoinExtension<A: AlkahestExtension, B: AlkahestExtension> {
    pub left: A,
    pub right: B,
}

impl<A: AlkahestExtension, B: AlkahestExtension> AlkahestExtension for JoinExtension<A, B> {
    // JoinExtension doesn't have a single client, so we use the default unit type
    type Client = ();

    async fn init(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<DefaultExtensionAddresses>,
    ) -> eyre::Result<Self> {
        let left = A::init(private_key.clone(), rpc_url.clone(), addresses.clone()).await?;
        let right = B::init(private_key, rpc_url, addresses).await?;

        Ok(JoinExtension { left, right })
    }

    async fn init_with_addresses<Addr: Clone + Send + Sync + 'static>(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<Addr>,
    ) -> eyre::Result<Self> {
        let left =
            A::init_with_addresses(private_key.clone(), rpc_url.clone(), addresses.clone()).await?;
        let right = B::init_with_addresses(private_key, rpc_url, addresses).await?;

        Ok(JoinExtension { left, right })
    }

    // JoinExtension doesn't have a single client, so return None
    fn client(&self) -> Option<&Self::Client> {
        None
    }

    /// Recursive search through both sides
    fn find_client<T: Clone + Send + Sync + 'static>(&self) -> Option<&T> {
        // First try left recursively
        if let Some(client) = self.left.find_client::<T>() {
            return Some(client);
        }
        // Then try right recursively
        if let Some(client) = self.right.find_client::<T>() {
            return Some(client);
        }
        None
    }
}

/// Base extension that includes all default modules using JoinExtension
pub type BaseExtensions = JoinExtension<
    JoinExtension<
        JoinExtension<Erc20Module, Erc721Module>,
        JoinExtension<Erc1155Module, TokenBundleModule>,
    >,
    JoinExtension<
        JoinExtension<AttestationModule, StringObligationModule>,
        JoinExtension<ArbitersModule, OracleModule>,
    >,
>;

/// === Modules ===

#[derive(Clone)]
pub struct Erc20Module {
    pub client: Erc20Client,
}
impl AlkahestExtension for Erc20Module {
    type Client = Erc20Client;

    async fn init(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<DefaultExtensionAddresses>,
    ) -> eyre::Result<Self> {
        let client = Erc20Client::new(
            private_key,
            rpc_url,
            addresses.and_then(|a| a.erc20_addresses),
        )
        .await?;
        Ok(Erc20Module { client })
    }

    /// Custom implementation that can handle Erc20Addresses directly
    async fn init_with_addresses<A: Clone + Send + Sync + 'static>(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<A>,
    ) -> eyre::Result<Self> {
        // Try to downcast to Erc20Addresses first
        let erc20_addresses = if let Some(addr) = addresses {
            // Use Any trait to attempt downcast
            let addr_any: &dyn Any = &addr;
            if let Some(erc20_addr) = addr_any.downcast_ref::<Erc20Addresses>() {
                Some(erc20_addr.clone())
            } else {
                None
            }
        } else {
            None
        };
        println!("Using RPC URL: {}", rpc_url.to_string());
        println!("init_with_addresses Using addresses: {:?}", erc20_addresses);
        let client = Erc20Client::new(private_key, rpc_url, erc20_addresses).await?;
        Ok(Erc20Module { client })
    }

    fn client(&self) -> Option<&Self::Client> {
        Some(&self.client)
    }
}

#[derive(Clone)]
pub struct Erc721Module {
    pub client: Erc721Client,
}
impl AlkahestExtension for Erc721Module {
    type Client = Erc721Client;

    async fn init(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<DefaultExtensionAddresses>,
    ) -> eyre::Result<Self> {
        let client = Erc721Client::new(
            private_key,
            rpc_url,
            addresses.and_then(|a| a.erc721_addresses),
        )
        .await?;
        Ok(Erc721Module { client })
    }

    async fn init_with_addresses<A: Clone + Send + Sync + 'static>(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<A>,
    ) -> eyre::Result<Self> {
        // Try to downcast to Erc721Addresses first
        let erc721_addresses = if let Some(addr) = addresses {
            let addr_any: &dyn Any = &addr;
            if let Some(erc721_addr) = addr_any.downcast_ref::<Erc721Addresses>() {
                Some(erc721_addr.clone())
            } else {
                None
            }
        } else {
            None
        };

        let client = Erc721Client::new(private_key, rpc_url, erc721_addresses).await?;
        Ok(Erc721Module { client })
    }

    fn client(&self) -> Option<&Self::Client> {
        Some(&self.client)
    }
}

#[derive(Clone)]
pub struct Erc1155Module {
    pub client: Erc1155Client,
}
impl AlkahestExtension for Erc1155Module {
    type Client = Erc1155Client;

    async fn init(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<DefaultExtensionAddresses>,
    ) -> eyre::Result<Self> {
        let client = Erc1155Client::new(
            private_key,
            rpc_url,
            addresses.and_then(|a| a.erc1155_addresses),
        )
        .await?;
        Ok(Erc1155Module { client })
    }

    async fn init_with_addresses<A: Clone + Send + Sync + 'static>(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<A>,
    ) -> eyre::Result<Self> {
        // Try to downcast to Erc1155Addresses first
        let erc1155_addresses = if let Some(addr) = addresses {
            let addr_any: &dyn Any = &addr;
            if let Some(erc1155_addr) = addr_any.downcast_ref::<Erc1155Addresses>() {
                Some(erc1155_addr.clone())
            } else {
                None
            }
        } else {
            None
        };

        let client = Erc1155Client::new(private_key, rpc_url, erc1155_addresses).await?;
        Ok(Erc1155Module { client })
    }

    fn client(&self) -> Option<&Self::Client> {
        Some(&self.client)
    }
}

#[derive(Clone)]
pub struct TokenBundleModule {
    pub client: TokenBundleClient,
}
impl AlkahestExtension for TokenBundleModule {
    type Client = TokenBundleClient;

    async fn init(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<DefaultExtensionAddresses>,
    ) -> eyre::Result<Self> {
        let client = TokenBundleClient::new(
            private_key,
            rpc_url,
            addresses.and_then(|a| a.token_bundle_addresses),
        )
        .await?;
        Ok(TokenBundleModule { client })
    }

    async fn init_with_addresses<A: Clone + Send + Sync + 'static>(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<A>,
    ) -> eyre::Result<Self> {
        // Try to downcast to TokenBundleAddresses first
        let token_bundle_addresses = if let Some(addr) = addresses {
            let addr_any: &dyn Any = &addr;
            if let Some(token_bundle_addr) = addr_any.downcast_ref::<TokenBundleAddresses>() {
                Some(token_bundle_addr.clone())
            } else {
                None
            }
        } else {
            None
        };

        let client = TokenBundleClient::new(private_key, rpc_url, token_bundle_addresses).await?;
        Ok(TokenBundleModule { client })
    }

    fn client(&self) -> Option<&Self::Client> {
        Some(&self.client)
    }
}

#[derive(Clone)]
pub struct AttestationModule {
    pub client: AttestationClient,
}
impl AlkahestExtension for AttestationModule {
    type Client = AttestationClient;

    async fn init(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<DefaultExtensionAddresses>,
    ) -> eyre::Result<Self> {
        let client = AttestationClient::new(
            private_key,
            rpc_url,
            addresses.and_then(|a| a.attestation_addresses),
        )
        .await?;
        Ok(AttestationModule { client })
    }

    async fn init_with_addresses<A: Clone + Send + Sync + 'static>(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<A>,
    ) -> eyre::Result<Self> {
        // Try to downcast to AttestationAddresses first
        let attestation_addresses = if let Some(addr) = addresses {
            let addr_any: &dyn Any = &addr;
            if let Some(attestation_addr) = addr_any.downcast_ref::<AttestationAddresses>() {
                Some(attestation_addr.clone())
            } else {
                None
            }
        } else {
            None
        };

        let client = AttestationClient::new(private_key, rpc_url, attestation_addresses).await?;
        Ok(AttestationModule { client })
    }

    fn client(&self) -> Option<&Self::Client> {
        Some(&self.client)
    }
}

#[derive(Clone)]
pub struct StringObligationModule {
    pub client: StringObligationClient,
}
impl AlkahestExtension for StringObligationModule {
    type Client = StringObligationClient;

    async fn init(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<DefaultExtensionAddresses>,
    ) -> eyre::Result<Self> {
        let client = StringObligationClient::new(
            private_key,
            rpc_url,
            addresses.and_then(|a| a.string_obligation_addresses),
        )
        .await?;
        Ok(StringObligationModule { client })
    }

    async fn init_with_addresses<A: Clone + Send + Sync + 'static>(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<A>,
    ) -> eyre::Result<Self> {
        // Try to downcast to StringObligationAddresses first
        let string_obligation_addresses = if let Some(addr) = addresses {
            let addr_any: &dyn Any = &addr;
            if let Some(string_obligation_addr) =
                addr_any.downcast_ref::<StringObligationAddresses>()
            {
                Some(string_obligation_addr.clone())
            } else {
                None
            }
        } else {
            None
        };

        let client =
            StringObligationClient::new(private_key, rpc_url, string_obligation_addresses).await?;
        Ok(StringObligationModule { client })
    }

    fn client(&self) -> Option<&Self::Client> {
        Some(&self.client)
    }
}

#[derive(Clone)]
pub struct ArbitersModule {
    pub client: ArbitersClient,
}
impl AlkahestExtension for ArbitersModule {
    type Client = ArbitersClient;

    async fn init(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<DefaultExtensionAddresses>,
    ) -> eyre::Result<Self> {
        let client = ArbitersClient::new(
            private_key,
            rpc_url,
            addresses.and_then(|a| a.arbiters_addresses),
        )
        .await?;
        Ok(ArbitersModule { client })
    }

    async fn init_with_addresses<A: Clone + Send + Sync + 'static>(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<A>,
    ) -> eyre::Result<Self> {
        // Try to downcast to ArbitersAddresses first
        let arbiters_addresses = if let Some(addr) = addresses {
            let addr_any: &dyn Any = &addr;
            if let Some(arbiters_addr) = addr_any.downcast_ref::<ArbitersAddresses>() {
                Some(arbiters_addr.clone())
            } else {
                None
            }
        } else {
            None
        };

        let client = ArbitersClient::new(private_key, rpc_url, arbiters_addresses).await?;
        Ok(ArbitersModule { client })
    }

    fn client(&self) -> Option<&Self::Client> {
        Some(&self.client)
    }
}
#[derive(Clone)]
pub struct OracleModule {
    pub client: OracleClient,
}
impl AlkahestExtension for OracleModule {
    type Client = OracleClient;

    async fn init(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<DefaultExtensionAddresses>,
    ) -> eyre::Result<Self> {
        let oracle_addresses =
            addresses
                .and_then(|a| a.arbiters_addresses)
                .map(|a| OracleAddresses {
                    eas: a.eas,
                    trusted_oracle_arbiter: a.trusted_oracle_arbiter,
                });
        let client = OracleClient::new(private_key, rpc_url, oracle_addresses).await?;
        Ok(OracleModule { client })
    }

    async fn init_with_addresses<A: Clone + Send + Sync + 'static>(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<A>,
    ) -> eyre::Result<Self> {
        // Try to downcast to OracleAddresses first
        let oracle_addresses = if let Some(addr) = addresses {
            let addr_any: &dyn Any = &addr;
            if let Some(oracle_addr) = addr_any.downcast_ref::<OracleAddresses>() {
                Some(oracle_addr.clone())
            } else {
                // Try to downcast to ArbitersAddresses and convert to OracleAddresses
                if let Some(arbiters_addr) = addr_any.downcast_ref::<ArbitersAddresses>() {
                    Some(OracleAddresses {
                        eas: arbiters_addr.eas,
                        trusted_oracle_arbiter: arbiters_addr.trusted_oracle_arbiter,
                    })
                } else {
                    None
                }
            }
        } else {
            None
        };

        let client = OracleClient::new(private_key, rpc_url, oracle_addresses).await?;
        Ok(OracleModule { client })
    }

    fn client(&self) -> Option<&Self::Client> {
        Some(&self.client)
    }
}

/// === Helper Traits ===
pub trait HasErc20 {
    fn erc20(&self) -> &Erc20Client;
}
pub trait HasErc721 {
    fn erc721(&self) -> &Erc721Client;
}
pub trait HasErc1155 {
    fn erc1155(&self) -> &Erc1155Client;
}
pub trait HasTokenBundle {
    fn token_bundle(&self) -> &TokenBundleClient;
}
pub trait HasAttestation {
    fn attestation(&self) -> &AttestationClient;
}
pub trait HasStringObligation {
    fn string_obligation(&self) -> &StringObligationClient;
}
pub trait HasArbiters {
    fn arbiters(&self) -> &ArbitersClient;
}
pub trait HasOracle {
    fn oracle(&self) -> &OracleClient;
}

/// === Direct Module Implementations ===
impl HasErc20 for Erc20Module {
    fn erc20(&self) -> &Erc20Client {
        &self.client
    }
}
impl HasErc721 for Erc721Module {
    fn erc721(&self) -> &Erc721Client {
        &self.client
    }
}
impl HasErc1155 for Erc1155Module {
    fn erc1155(&self) -> &Erc1155Client {
        &self.client
    }
}
impl HasTokenBundle for TokenBundleModule {
    fn token_bundle(&self) -> &TokenBundleClient {
        &self.client
    }
}
impl HasAttestation for AttestationModule {
    fn attestation(&self) -> &AttestationClient {
        &self.client
    }
}
impl HasStringObligation for StringObligationModule {
    fn string_obligation(&self) -> &StringObligationClient {
        &self.client
    }
}
impl HasArbiters for ArbitersModule {
    fn arbiters(&self) -> &ArbitersClient {
        &self.client
    }
}
impl HasOracle for OracleModule {
    fn oracle(&self) -> &OracleClient {
        &self.client
    }
}

/// === Has* Traits for JoinExtension - Search left and right ===
impl<A: AlkahestExtension, B: AlkahestExtension> HasErc20 for JoinExtension<A, B>
where
    Self: AlkahestExtension,
{
    fn erc20(&self) -> &Erc20Client {
        self.find_client::<Erc20Client>()
            .expect("ERC20 client not found in JoinExtension")
    }
}

impl<A: AlkahestExtension, B: AlkahestExtension> HasErc721 for JoinExtension<A, B>
where
    Self: AlkahestExtension,
{
    fn erc721(&self) -> &Erc721Client {
        self.find_client::<Erc721Client>()
            .expect("ERC721 client not found in JoinExtension")
    }
}

impl<A: AlkahestExtension, B: AlkahestExtension> HasErc1155 for JoinExtension<A, B>
where
    Self: AlkahestExtension,
{
    fn erc1155(&self) -> &Erc1155Client {
        self.find_client::<Erc1155Client>()
            .expect("ERC1155 client not found in JoinExtension")
    }
}

impl<A: AlkahestExtension, B: AlkahestExtension> HasTokenBundle for JoinExtension<A, B>
where
    Self: AlkahestExtension,
{
    fn token_bundle(&self) -> &TokenBundleClient {
        self.find_client::<TokenBundleClient>()
            .expect("TokenBundle client not found in JoinExtension")
    }
}

impl<A: AlkahestExtension, B: AlkahestExtension> HasAttestation for JoinExtension<A, B>
where
    Self: AlkahestExtension,
{
    fn attestation(&self) -> &AttestationClient {
        self.find_client::<AttestationClient>()
            .expect("Attestation client not found in JoinExtension")
    }
}

impl<A: AlkahestExtension, B: AlkahestExtension> HasStringObligation for JoinExtension<A, B>
where
    Self: AlkahestExtension,
{
    fn string_obligation(&self) -> &StringObligationClient {
        self.find_client::<StringObligationClient>()
            .expect("StringObligation client not found in JoinExtension")
    }
}

impl<A: AlkahestExtension, B: AlkahestExtension> HasArbiters for JoinExtension<A, B>
where
    Self: AlkahestExtension,
{
    fn arbiters(&self) -> &ArbitersClient {
        self.find_client::<ArbitersClient>()
            .expect("Arbiters client not found in JoinExtension")
    }
}

impl<A: AlkahestExtension, B: AlkahestExtension> HasOracle for JoinExtension<A, B>
where
    Self: AlkahestExtension,
{
    fn oracle(&self) -> &OracleClient {
        self.find_client::<OracleClient>()
            .expect("Oracle client not found in JoinExtension")
    }
}

/// === Forward Has* Traits for AlkahestClient ===
impl<Ext: AlkahestExtension + HasErc20> HasErc20 for AlkahestClient<Ext> {
    fn erc20(&self) -> &Erc20Client {
        self.extensions.erc20()
    }
}
impl<Ext: AlkahestExtension + HasErc721> HasErc721 for AlkahestClient<Ext> {
    fn erc721(&self) -> &Erc721Client {
        self.extensions.erc721()
    }
}
impl<Ext: AlkahestExtension + HasErc1155> HasErc1155 for AlkahestClient<Ext> {
    fn erc1155(&self) -> &Erc1155Client {
        self.extensions.erc1155()
    }
}
impl<Ext: AlkahestExtension + HasTokenBundle> HasTokenBundle for AlkahestClient<Ext> {
    fn token_bundle(&self) -> &TokenBundleClient {
        self.extensions.token_bundle()
    }
}
impl<Ext: AlkahestExtension + HasAttestation> HasAttestation for AlkahestClient<Ext> {
    fn attestation(&self) -> &AttestationClient {
        self.extensions.attestation()
    }
}
impl<Ext: AlkahestExtension + HasStringObligation> HasStringObligation for AlkahestClient<Ext> {
    fn string_obligation(&self) -> &StringObligationClient {
        self.extensions.string_obligation()
    }
}
impl<Ext: AlkahestExtension + HasArbiters> HasArbiters for AlkahestClient<Ext> {
    fn arbiters(&self) -> &ArbitersClient {
        self.extensions.arbiters()
    }
}
impl<Ext: AlkahestExtension + HasOracle> HasOracle for AlkahestClient<Ext> {
    fn oracle(&self) -> &OracleClient {
        self.extensions.oracle()
    }
}

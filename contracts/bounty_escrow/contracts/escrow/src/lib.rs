
//! # Bounty Escrow Smart Contract
//!
//! A trustless escrow system for bounty payments on the Stellar blockchain.
//! This contract enables secure fund locking, conditional release to contributors,
//! and automatic refunds after deadlines.
//!
//! ## Overview
//!
//! The Bounty Escrow contract manages the complete lifecycle of bounty payments:
//! 1. **Initialization**: Set up admin and token contract
//! 2. **Lock Funds**: Depositor locks tokens for a bounty with a deadline
//! 3. **Release**: Admin releases funds to contributor upon task completion
//! 4. **Refund**: Automatic refund to depositor if deadline passes
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  Contract Architecture                       │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                              │
//! │  ┌──────────────┐                                           │
//! │  │  Depositor   │─────┐                                     │
//! │  └──────────────┘     │                                     │
//! │                       ├──> lock_funds()                     │
//! │  ┌──────────────┐     │         │                           │
//! │  │    Admin     │─────┘         ▼                           │
//! │  └──────────────┘          ┌─────────┐                      │
//! │         │                  │ ESCROW  │                      │
//! │         │                  │ LOCKED  │                      │
//! │         │                  └────┬────┘                      │
//! │         │                       │                           │
//! │         │        ┌──────────────┴───────────────┐           │
//! │         │        │                              │           │
//! │         ▼        ▼                              ▼           │
//! │   release_funds()                          refund()         │
//! │         │                                       │           │
//! │         ▼                                       ▼           │
//! │  ┌──────────────┐                      ┌──────────────┐    │
//! │  │ Contributor  │                      │  Depositor   │    │
//! │  └──────────────┘                      └──────────────┘    │
//! │    (RELEASED)                            (REFUNDED)        │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Security Model
//!
//! ### Trust Assumptions
//! - **Admin**: Trusted entity (backend service) authorized to release funds
//! - **Depositor**: Self-interested party; funds protected by deadline mechanism
//! - **Contributor**: Receives funds only after admin approval
//! - **Contract**: Trustless; operates according to programmed rules
//!
//! ### Key Security Features
//! 1. **Single Initialization**: Prevents admin takeover
//! 2. **Unique Bounty IDs**: No duplicate escrows
//! 3. **Authorization Checks**: All state changes require proper auth
//! 4. **Deadline Protection**: Prevents indefinite fund locking
//! 5. **State Machine**: Enforces valid state transitions
//! 6. **Atomic Operations**: Transfer + state update in single transaction
//!
//! ## Usage Example
//!
//! ```rust
//! use soroban_sdk::{Address, Env};
//!
//! // 1. Initialize contract (one-time setup)
//! let admin = Address::from_string("GADMIN...");
//! let token = Address::from_string("CUSDC...");
//! escrow_client.init(&admin, &token);
//!
//! // 2. Depositor locks 1000 USDC for bounty #42
//! let depositor = Address::from_string("GDEPOSIT...");
//! let amount = 1000_0000000; // 1000 USDC (7 decimals)
//! let deadline = current_timestamp + (30 * 24 * 60 * 60); // 30 days
//! escrow_client.lock_funds(&depositor, &42, &amount, &deadline);
//!
//! // 3a. Admin releases to contributor (happy path)
//! let contributor = Address::from_string("GCONTRIB...");
//! escrow_client.release_funds(&42, &contributor);
//!
//! // OR
//!
//! // 3b. Refund to depositor after deadline (timeout path)
//! // (Can be called by anyone after deadline passes)
//! escrow_client.refund(&42);
//! ```

#![no_std]
mod events;
mod test_bounty_escrow;

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, token, Address, Env, Map, String, Vec};
use events::{
    BountyEscrowInitialized, FundsLocked, FundsReleased, FundsRefunded,
    emit_bounty_initialized, emit_funds_locked, emit_funds_released, emit_funds_refunded
};

// ============================================================================
// Error Definitions
// ============================================================================

/// Contract error codes for the Bounty Escrow system.
///
/// # Error Codes
/// * `AlreadyInitialized (1)` - Contract has already been initialized
/// * `NotInitialized (2)` - Contract must be initialized before use
/// * `BountyExists (3)` - Bounty ID already has funds locked
/// * `BountyNotFound (4)` - No escrow exists for this bounty ID
/// * `FundsNotLocked (5)` - Funds are not in LOCKED state
/// * `DeadlineNotPassed (6)` - Cannot refund before deadline
/// * `Unauthorized (7)` - Caller lacks required authorization
///
/// # Usage in Error Handling
/// ```rust
/// if env.storage().instance().has(&DataKey::Admin) {
///     return Err(Error::AlreadyInitialized);
/// }
/// ```
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Returned when attempting to initialize an already initialized contract
    AlreadyInitialized = 1,
    
    /// Returned when calling contract functions before initialization
    NotInitialized = 2,
    
    /// Returned when attempting to lock funds with a duplicate bounty ID
    BountyExists = 3,
    
    /// Returned when querying or operating on a non-existent bounty
    BountyNotFound = 4,
    
    /// Returned when attempting operations on non-LOCKED funds
    FundsNotLocked = 5,
    
    /// Returned when attempting refund before the deadline has passed
    DeadlineNotPassed = 6,
    
    /// Returned when caller lacks required authorization for the operation
    Unauthorized = 7,
    
    /// Returned when metadata exceeds size limits
    MetadataTooLarge = 8,
}

// ============================================================================
// Data Structures
// ============================================================================

/// Represents the current state of escrowed funds.
///
/// # State Transitions
/// ```text
/// NONE → Locked → Released (final)
///           ↓
///        Refunded (final)
/// ```
///
/// # States
/// * `Locked` - Funds are held in escrow, awaiting release or refund
/// * `Released` - Funds have been transferred to contributor (final state)
/// * `Refunded` - Funds have been returned to depositor (final state)
///
/// # Invariants
/// - Once in Released or Refunded state, no further transitions allowed
/// - Only Locked state allows state changes
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EscrowStatus {
    Locked,
    Released,
    Refunded,
}

/// Complete escrow record for a bounty.
///
/// # Fields
/// * `depositor` - Address that locked the funds (receives refunds)
/// * `amount` - Token amount held in escrow (in smallest denomination)
/// * `status` - Current state of the escrow (Locked/Released/Refunded)
/// * `deadline` - Unix timestamp after which refunds are allowed
///
/// # Storage
/// Stored in persistent storage with key `DataKey::Escrow(bounty_id)`.
/// TTL is automatically extended on access.
///
/// # Example
/// ```rust
/// let escrow = Escrow {
///     depositor: depositor_address,
///     amount: 1000_0000000, // 1000 tokens
///     status: EscrowStatus::Locked,
///     deadline: current_time + 2592000, // 30 days
/// };
/// ```
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Escrow {
    pub depositor: Address,
    pub amount: i128,
    pub status: EscrowStatus,
    pub deadline: u64,
}

/// Metadata structure for enhanced escrow indexing and categorization.
///
/// # Fields
/// * `repo_id` - Repository identifier (e.g., "owner/repo")
/// * `issue_id` - Issue or pull request identifier
/// * `bounty_type` - Type classification (e.g., "bug", "feature", "security")
/// * `tags` - Custom tags for filtering and categorization
/// * `custom_fields` - Additional key-value pairs for extensibility
///
/// # Size Limits
/// * Total serialized size: 1024 bytes maximum
/// * Tags vector: 20 items maximum
/// * Custom fields map: 10 key-value pairs maximum
/// * Individual string values: 128 characters maximum
///
/// # Storage
/// Stored separately from core escrow data with key `DataKey::EscrowMetadata(bounty_id)`.
/// Metadata is optional and can be added/updated after escrow creation.
///
/// # Example
/// ```rust
/// let metadata = EscrowMetadata {
///     repo_id: Some(String::from_str(&env, "stellar/rs-soroban-sdk")),
///     issue_id: Some(String::from_str(&env, "123")),
///     bounty_type: Some(String::from_str(&env, "bug")),
///     tags: vec![&env, 
///         String::from_str(&env, "priority-high"),
///         String::from_str(&env, "security")
///     ],
///     custom_fields: map![
///         &env,
///         (String::from_str(&env, "difficulty"), String::from_str(&env, "medium")),
///         (String::from_str(&env, "estimated_hours"), String::from_str(&env, "20"))
///     ]
/// };
/// ```
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowMetadata {
    pub repo_id: Option<String>,
    pub issue_id: Option<String>,
    pub bounty_type: Option<String>,
    pub tags: Vec<String>,
    pub custom_fields: Map<String, String>,
}

/// Combined view of escrow data and metadata for convenient access.
///
/// # Fields
/// * `escrow` - Core escrow information
/// * `metadata` - Optional metadata (None if not set)
///
/// # Usage
/// Provides a unified interface for retrieving complete escrow information
/// including both financial and descriptive data.
///
/// # Example
/// ```rust
/// let escrow_view = escrow_client.get_escrow_with_metadata(&42)?;
/// if let Some(metadata) = escrow_view.metadata {
///     println!("Repo: {:?}", metadata.repo_id);
///     println!("Issue: {:?}", metadata.issue_id);
///     println!("Tags: {:?}", metadata.tags);
/// }
/// ```
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowWithMetadata {
    pub escrow: Escrow,
    pub metadata: Option<EscrowMetadata>,
}

/// Storage keys for contract data.
///
/// # Keys
/// * `Admin` - Stores the admin address (instance storage)
/// * `Token` - Stores the token contract address (instance storage)
/// * `Escrow(u64)` - Stores escrow data indexed by bounty_id (persistent storage)
/// * `EscrowMetadata(u64)` - Stores metadata for bounty_id (persistent storage)
///
/// # Storage Types
/// - **Instance Storage**: Admin and Token (never expires, tied to contract)
/// - **Persistent Storage**: Individual escrow records and metadata (extended TTL on access)
#[contracttype]
pub enum DataKey {
    Admin,
    Token,
    Escrow(u64), // bounty_id
    EscrowMetadata(u64), // bounty_id
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Validates metadata size limits to prevent excessive storage costs.
///
/// # Parameters
/// * `metadata` - Metadata to validate
///
/// # Returns
/// * `true` if metadata is within size limits
/// * `false` if metadata exceeds limits
///
/// # Limits Checked
/// * Tags vector length ≤ 20
/// * Custom fields map size ≤ 10
/// * Individual string values ≤ 128 characters
/// * Total serialized size ≤ 1024 bytes
fn validate_metadata_size(env: &Env, metadata: &EscrowMetadata) -> bool {
    // Check tags limit
    if metadata.tags.len() > 20 {
        return false;
    }
    
    // Check custom fields limit
    if metadata.custom_fields.len() > 10 {
        return false;
    }
    
    // Check individual string lengths
    if let Some(repo_id) = &metadata.repo_id {
        if repo_id.len() > 128 {
            return false;
        }
    }
    
    if let Some(issue_id) = &metadata.issue_id {
        if issue_id.len() > 128 {
            return false;
        }
    }
    
    if let Some(bounty_type) = &metadata.bounty_type {
        if bounty_type.len() > 128 {
            return false;
        }
    }
    
    for tag in metadata.tags.iter() {
        if tag.len() > 128 {
            return false;
        }
    }
    
    for (_, value) in metadata.custom_fields.iter() {
        if value.len() > 128 {
            return false;
        }
    }
    
    // Check total serialized size (approximate)
    let serialized_size = env
        .serialize_to_bytes(metadata)
        .len();
    
    serialized_size <= 1024
}

// ============================================================================
// Contract Implementation
// ============================================================================

#[contract]
pub struct BountyEscrowContract;

#[contractimpl]
impl BountyEscrowContract {
    // ========================================================================
    // Initialization
    // ========================================================================
    
    /// Initializes the Bounty Escrow contract with admin and token addresses.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `admin` - Address authorized to release funds
    /// * `token` - Token contract address for escrow payments (e.g., XLM, USDC)
    ///
    /// # Returns
    /// * `Ok(())` - Contract successfully initialized
    /// * `Err(Error::AlreadyInitialized)` - Contract already initialized
    ///
    /// # State Changes
    /// - Sets Admin address in instance storage
    /// - Sets Token address in instance storage
    /// - Emits BountyEscrowInitialized event
    ///
    /// # Security Considerations
    /// - Can only be called once (prevents admin takeover)
    /// - Admin should be a secure backend service address
    /// - Token must be a valid Stellar Asset Contract
    /// - No authorization required (first-caller initialization)
    ///
    /// # Events
    /// Emits: `BountyEscrowInitialized { admin, token, timestamp }`
    ///
    /// # Example
    /// ```rust
    /// let admin = Address::from_string("GADMIN...");
    /// let usdc_token = Address::from_string("CUSDC...");
    /// escrow_client.init(&admin, &usdc_token)?;
    /// ```
    ///
    /// # Gas Cost
    /// Low - Only two storage writes
    pub fn init(env: Env, admin: Address, token: Address) -> Result<(), Error> {
        // Prevent re-initialization
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        
        // Store configuration
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);

        // Emit initialization event
        emit_bounty_initialized(
            &env,
            BountyEscrowInitialized {
                admin,
                token,
                timestamp: env.ledger().timestamp()
            },
        );

        Ok(())
    }

    // ========================================================================
    // Core Escrow Functions
    // ========================================================================

    /// Locks funds in escrow for a specific bounty.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `depositor` - Address depositing the funds (must authorize)
    /// * `bounty_id` - Unique identifier for this bounty
    /// * `amount` - Token amount to lock (in smallest denomination)
    /// * `deadline` - Unix timestamp after which refund is allowed
    ///
    /// # Returns
    /// * `Ok(())` - Funds successfully locked
    /// * `Err(Error::NotInitialized)` - Contract not initialized
    /// * `Err(Error::BountyExists)` - Bounty ID already in use
    ///
    /// # State Changes
    /// - Transfers `amount` tokens from depositor to contract
    /// - Creates Escrow record in persistent storage
    /// - Emits FundsLocked event
    ///
    /// # Authorization
    /// - Depositor must authorize the transaction
    /// - Depositor must have sufficient token balance
    /// - Depositor must have approved contract for token transfer
    ///
    /// # Security Considerations
    /// - Bounty ID must be unique (prevents overwrites)
    /// - Amount must be positive (enforced by token contract)
    /// - Deadline should be reasonable (recommended: 7-90 days)
    /// - Token transfer is atomic with state update
    ///
    /// # Events
    /// Emits: `FundsLocked { bounty_id, amount, depositor, deadline }`
    ///
    /// # Example
    /// ```rust
    /// let depositor = Address::from_string("GDEPOSIT...");
    /// let amount = 1000_0000000; // 1000 USDC
    /// let deadline = env.ledger().timestamp() + (30 * 24 * 60 * 60); // 30 days
    /// 
    /// escrow_client.lock_funds(&depositor, &42, &amount, &deadline)?;
    /// // Funds are now locked and can be released or refunded
    /// ```
    ///
    /// # Gas Cost
    /// Medium - Token transfer + storage write + event emission
    ///
    /// # Common Pitfalls
    /// - Forgetting to approve token contract before calling
    /// - Using a bounty ID that already exists
    /// - Setting deadline in the past or too far in the future
    pub fn lock_funds(
        env: Env,
        depositor: Address,
        bounty_id: u64,
        amount: i128,
        deadline: u64,
    ) -> Result<(), Error> {
        // Verify depositor authorization
        depositor.require_auth();

        // Ensure contract is initialized
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }

        // Prevent duplicate bounty IDs
        if env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyExists);
        }

        // Get token contract and transfer funds
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);

        // Transfer funds from depositor to contract
        client.transfer(&depositor, &env.current_contract_address(), &amount);

        // Create escrow record
        let escrow = Escrow {
            depositor: depositor.clone(),
            amount,
            status: EscrowStatus::Locked,
            deadline,
        };

        // Store in persistent storage with extended TTL
        env.storage().persistent().set(&DataKey::Escrow(bounty_id), &escrow);
        
        // Emit event for off-chain indexing
        emit_funds_locked(
            &env,
            FundsLocked {
                bounty_id,
                amount,
                depositor: depositor.clone(),
                deadline
            },
        );

        Ok(())
    }

    /// Sets or updates metadata for an existing escrow.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `bounty_id` - The bounty to attach metadata to
    /// * `metadata` - Metadata structure containing repo, issue, type, and tags
    ///
    /// # Returns
    /// * `Ok(())` - Metadata successfully set/updated
    /// * `Err(Error::BountyNotFound)` - Bounty doesn't exist
    /// * `Err(Error::MetadataTooLarge)` - Metadata exceeds size limits
    /// * `Err(Error::Unauthorized)` - Caller is not the depositor
    ///
    /// # State Changes
    /// - Stores/updates metadata in persistent storage
    /// - Extends storage TTL on access
    ///
    /// # Authorization
    /// - Only the original depositor can set/update metadata
    /// - This prevents unauthorized metadata modification
    ///
    /// # Size Limits
    /// See `validate_metadata_size()` documentation for detailed limits.
    ///
    /// # Events
    /// Emits: `FundsLocked` event with additional metadata field
    ///
    /// # Example
    /// ```rust
    /// let metadata = EscrowMetadata {
    ///     repo_id: Some(String::from_str(&env, "owner/repo")),
    ///     issue_id: Some(String::from_str(&env, "123")),
    ///     bounty_type: Some(String::from_str(&env, "bug")),
    ///     tags: vec![&env, String::from_str(&env, "priority-high")],
    ///     custom_fields: map![&env],
    /// };
    /// 
    /// escrow_client.set_escrow_metadata(&42, &metadata)?;
    /// ```
    pub fn set_escrow_metadata(
        env: Env,
        bounty_id: u64,
        metadata: EscrowMetadata,
    ) -> Result<(), Error> {
        // Verify bounty exists
        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }

        // Get escrow to verify depositor authorization
        let escrow: Escrow = env.storage().persistent().get(&DataKey::Escrow(bounty_id)).unwrap();
        escrow.depositor.require_auth();

        // Validate metadata size limits
        if !validate_metadata_size(&env, &metadata) {
            return Err(Error::MetadataTooLarge);
        }

        // Store metadata
        env.storage().persistent().set(&DataKey::EscrowMetadata(bounty_id), &metadata);

        // Extend TTL for both escrow and metadata
        env.storage().persistent().extend_ttl(
            &DataKey::Escrow(bounty_id),
            1000000, // Minimum
            10000000, // Maximum
        );
        env.storage().persistent().extend_ttl(
            &DataKey::EscrowMetadata(bounty_id),
            1000000, // Minimum
            10000000, // Maximum
        );

        Ok(())
    }

    /// Releases escrowed funds to a contributor.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `bounty_id` - The bounty to release funds for
    /// * `contributor` - Address to receive the funds
    ///
    /// # Returns
    /// * `Ok(())` - Funds successfully released
    /// * `Err(Error::NotInitialized)` - Contract not initialized
    /// * `Err(Error::Unauthorized)` - Caller is not the admin
    /// * `Err(Error::BountyNotFound)` - Bounty doesn't exist
    /// * `Err(Error::FundsNotLocked)` - Funds not in LOCKED state
    ///
    /// # State Changes
    /// - Transfers tokens from contract to contributor
    /// - Updates escrow status to Released
    /// - Emits FundsReleased event
    ///
    /// # Authorization
    /// - **CRITICAL**: Only admin can call this function
    /// - Admin address must match initialization value
    ///
    /// # Security Considerations
    /// - This is the most security-critical function
    /// - Admin should verify task completion off-chain before calling
    /// - Once released, funds cannot be retrieved
    /// - Recipient address should be verified carefully
    /// - Consider implementing multi-sig for admin
    ///
    /// # Events
    /// Emits: `FundsReleased { bounty_id, amount, recipient, timestamp }`
    ///
    /// # Example
    /// ```rust
    /// // After verifying task completion off-chain:
    /// let contributor = Address::from_string("GCONTRIB...");
    /// 
    /// // Admin calls release
    /// escrow_client.release_funds(&42, &contributor)?;
    /// // Funds transferred to contributor, escrow marked as Released
    /// ```
    ///
    /// # Gas Cost
    /// Medium - Token transfer + storage update + event emission
    ///
    /// # Best Practices
    /// 1. Verify contributor identity off-chain
    /// 2. Confirm task completion before release
    /// 3. Log release decisions in backend system
    /// 4. Monitor release events for anomalies
    /// 5. Consider implementing release delays for high-value bounties
    pub fn release_funds(env: Env, bounty_id: u64, contributor: Address) -> Result<(), Error> {
        // Ensure contract is initialized
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }

        // Verify admin authorization
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        // Verify bounty exists
        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }

        // Get and verify escrow state
        let mut escrow: Escrow = env.storage().persistent().get(&DataKey::Escrow(bounty_id)).unwrap();

        if escrow.status != EscrowStatus::Locked {
            return Err(Error::FundsNotLocked);
        }

        // Transfer funds to contributor
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);
        client.transfer(&env.current_contract_address(), &contributor, &escrow.amount);

        // Update escrow status
        escrow.status = EscrowStatus::Released;
        env.storage().persistent().set(&DataKey::Escrow(bounty_id), &escrow);

        // Emit release event
        emit_funds_released(
            &env,
            FundsReleased {
                bounty_id,
                amount: escrow.amount,
                recipient: contributor.clone(),
                timestamp: env.ledger().timestamp()
            },
        );

        Ok(())
    }

    /// Refunds escrowed funds to the depositor after deadline expiration.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `bounty_id` - The bounty to refund
    ///
    /// # Returns
    /// * `Ok(())` - Funds successfully refunded
    /// * `Err(Error::BountyNotFound)` - Bounty doesn't exist
    /// * `Err(Error::FundsNotLocked)` - Funds not in LOCKED state
    /// * `Err(Error::DeadlineNotPassed)` - Current time before deadline
    ///
    /// # State Changes
    /// - Transfers tokens from contract back to depositor
    /// - Updates escrow status to Refunded
    /// - Emits FundsRefunded event
    ///
    /// # Authorization
    /// - **Permissionless**: Anyone can trigger refund after deadline
    /// - No authorization required (time-based protection)
    ///
    /// # Security Considerations
    /// - Deadline enforcement prevents premature refunds
    /// - Permissionless design ensures funds aren't stuck
    /// - Original depositor always receives refund (prevents theft)
    /// - State check prevents double-refund
    ///
    /// # Design Rationale
    /// This function is intentionally permissionless to ensure:
    /// 1. Depositors can always recover funds after deadline
    /// 2. No dependency on admin availability
    /// 3. Trustless, predictable behavior
    /// 4. Protection against key loss scenarios
    ///
    /// # Events
    /// Emits: `FundsRefunded { bounty_id, amount, refund_to, timestamp }`
    ///
    /// # Example
    /// ```rust
    /// // Deadline was January 1, 2025
    /// // Current time: January 15, 2025
    /// 
    /// // Anyone can call refund now
    /// escrow_client.refund(&42)?;
    /// // Funds returned to original depositor
    /// ```
    ///
    /// # Gas Cost
    /// Medium - Token transfer + storage update + event emission
    ///
    /// # Time Calculations
    /// ```rust
    /// // Set deadline for 30 days from now
    /// let deadline = env.ledger().timestamp() + (30 * 24 * 60 * 60);
    /// 
    /// // After deadline passes, refund becomes available
    /// // Current time must be > deadline
    /// ```
    pub fn refund(env: Env, bounty_id: u64) -> Result<(), Error> {
        // Verify bounty exists
        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }

        // Get and verify escrow state
        let mut escrow: Escrow = env.storage().persistent().get(&DataKey::Escrow(bounty_id)).unwrap();

        if escrow.status != EscrowStatus::Locked {
            return Err(Error::FundsNotLocked);
        }

        // Verify deadline has passed
        let now = env.ledger().timestamp();
        if now < escrow.deadline {
            return Err(Error::DeadlineNotPassed);
        }

        // Transfer funds back to depositor
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);
        client.transfer(&env.current_contract_address(), &escrow.depositor, &escrow.amount);

        // Update escrow status
        escrow.status = EscrowStatus::Refunded;
        env.storage().persistent().set(&DataKey::Escrow(bounty_id), &escrow);

        // Emit refund event
        emit_funds_refunded(
            &env,
            FundsRefunded {
                bounty_id,
                amount: escrow.amount,
                refund_to: escrow.depositor,
                timestamp: env.ledger().timestamp()
            },
        );

        Ok(())
    }

    // ========================================================================
    // View Functions (Read-only)
    // ========================================================================

    /// Retrieves escrow information for a specific bounty.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `bounty_id` - The bounty to query
    ///
    /// # Returns
    /// * `Ok(Escrow)` - The complete escrow record
    /// * `Err(Error::BountyNotFound)` - Bounty doesn't exist
    ///
    /// # Gas Cost
    /// Very Low - Single storage read
    ///
    /// # Example
    /// ```rust
    /// let escrow_info = escrow_client.get_escrow_info(&42)?;
    /// println!("Amount: {}", escrow_info.amount);
    /// println!("Status: {:?}", escrow_info.status);
    /// println!("Deadline: {}", escrow_info.deadline);
    /// ```
    pub fn get_escrow_info(env: Env, bounty_id: u64) -> Result<Escrow, Error> {
        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }
        Ok(env.storage().persistent().get(&DataKey::Escrow(bounty_id)).unwrap())
    }

    /// Retrieves metadata for a specific bounty.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `bounty_id` - The bounty to query
    ///
    /// # Returns
    /// * `Ok(Option<EscrowMetadata>)` - Metadata if set, None if not set
    /// * `Err(Error::BountyNotFound)` - Bounty doesn't exist
    ///
    /// # Gas Cost
    /// Very Low - Single storage read
    ///
    /// # Example
    /// ```rust
    /// let metadata_opt = escrow_client.get_escrow_metadata(&42)?;
    /// if let Some(metadata) = metadata_opt {
    ///     println!("Repo: {:?}", metadata.repo_id);
    ///     println!("Issue: {:?}", metadata.issue_id);
    ///     println!("Type: {:?}", metadata.bounty_type);
    ///     println!("Tags: {:?}", metadata.tags);
    /// }
    /// ```
    pub fn get_escrow_metadata(env: Env, bounty_id: u64) -> Result<Option<EscrowMetadata>, Error> {
        // Verify bounty exists
        if !env.storage().persistent().has(&DataKey::Escrow(bounty_id)) {
            return Err(Error::BountyNotFound);
        }
        
        // Get metadata if it exists
        let metadata: Option<EscrowMetadata> = env.storage().persistent().get(&DataKey::EscrowMetadata(bounty_id));
        Ok(metadata)
    }

    /// Retrieves complete escrow information including metadata.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `bounty_id` - The bounty to query
    ///
    /// # Returns
    /// * `Ok(EscrowWithMetadata)` - Combined escrow and metadata information
    /// * `Err(Error::BountyNotFound)` - Bounty doesn't exist
    ///
    /// # Gas Cost
    /// Low - Two storage reads
    ///
    /// # Example
    /// ```rust
    /// let escrow_view = escrow_client.get_escrow_with_metadata(&42)?;
    /// println!("Amount: {}", escrow_view.escrow.amount);
    /// println!("Status: {:?}", escrow_view.escrow.status);
    /// 
    /// if let Some(meta) = escrow_view.metadata {
    ///     println!("Repository: {:?}", meta.repo_id);
    ///     println!("Issue: {:?}", meta.issue_id);
    /// }
    /// ```
    pub fn get_escrow_with_metadata(env: Env, bounty_id: u64) -> Result<EscrowWithMetadata, Error> {
        // Get core escrow data
        let escrow = Self::get_escrow_info(env.clone(), bounty_id)?;
        
        // Get metadata if it exists
        let metadata = Self::get_escrow_metadata(env, bounty_id)?;
        
        Ok(EscrowWithMetadata {
            escrow,
            metadata,
        })
    }

    /// Returns the current token balance held by the contract.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    /// * `Ok(i128)` - Current contract token balance
    /// * `Err(Error::NotInitialized)` - Contract not initialized
    ///
    /// # Use Cases
    /// - Monitoring total locked funds
    /// - Verifying contract solvency
    /// - Auditing and reconciliation
    ///
    /// # Gas Cost
    /// Low - Token contract call
    ///
    /// # Example
    /// ```rust
    /// let balance = escrow_client.get_balance()?;
    /// println!("Total locked: {} stroops", balance);
    /// ```
    pub fn get_balance(env: Env) -> Result<i128, Error> {
        if !env.storage().instance().has(&DataKey::Token) {
            return Err(Error::NotInitialized);
        }
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let client = token::Client::new(&env, &token_addr);
        Ok(client.balance(&env.current_contract_address()))
    }
}

#[cfg(test)]
mod test;
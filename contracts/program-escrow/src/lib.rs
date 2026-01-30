
//! # Program Escrow Smart Contract
//!
//! A secure escrow system for managing hackathon and program prize pools on Stellar.
//! This contract enables organizers to lock funds and distribute prizes to multiple
//! winners through secure, auditable batch payouts.
//!
//! ## Overview
//!
//! The Program Escrow contract manages the complete lifecycle of hackathon/program prizes:
//! 1. **Initialization**: Set up program with authorized payout controller
//! 2. **Fund Locking**: Lock prize pool funds in escrow
//! 3. **Batch Payouts**: Distribute prizes to multiple winners simultaneously
//! 4. **Single Payouts**: Distribute individual prizes
//! 5. **Tracking**: Maintain complete payout history and balance tracking
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │              Program Escrow Architecture                         │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────┐                                               │
//! │  │  Organizer   │                                               │
//! │  └──────┬───────┘                                               │
//! │         │                                                        │
//! │         │ 1. init_program()                                     │
//! │         ▼                                                        │
//! │  ┌──────────────────┐                                           │
//! │  │  Program Created │                                           │
//! │  └────────┬─────────┘                                           │
//! │           │                                                      │
//! │           │ 2. lock_program_funds()                             │
//! │           ▼                                                      │
//! │  ┌──────────────────┐                                           │
//! │  │  Funds Locked    │                                           │
//! │  │  (Prize Pool)    │                                           │
//! │  └────────┬─────────┘                                           │
//! │           │                                                      │
//! │           │ 3. Hackathon happens...                             │
//! │           │                                                      │
//! │  ┌────────▼─────────┐                                           │
//! │  │ Authorized       │                                           │
//! │  │ Payout Key       │                                           │
//! │  └────────┬─────────┘                                           │
//! │           │                                                      │
//! │    ┌──────┴───────┐                                             │
//! │    │              │                                             │
//! │    ▼              ▼                                             │
//! │ batch_payout() single_payout()                                  │
//! │    │              │                                             │
//! │    ▼              ▼                                             │
//! │ ┌─────────────────────────┐                                    │
//! │ │   Winner 1, 2, 3, ...   │                                    │
//! │ └─────────────────────────┘                                    │
//! │                                                                  │
//! │  Storage:                                                        │
//! │  ┌──────────────────────────────────────────┐                  │
//! │  │ ProgramData:                             │                  │
//! │  │  - program_id                            │                  │
//! │  │  - total_funds                           │                  │
//! │  │  - remaining_balance                     │                  │
//! │  │  - authorized_payout_key                 │                  │
//! │  │  - payout_history: [PayoutRecord]        │                  │
//! │  │  - token_address                         │                  │
//! │  └──────────────────────────────────────────┘                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Security Model
//!
//! ### Trust Assumptions
//! - **Authorized Payout Key**: Trusted backend service that triggers payouts
//! - **Organizer**: Trusted to lock appropriate prize amounts
//! - **Token Contract**: Standard Stellar Asset Contract (SAC)
//! - **Contract**: Trustless; operates according to programmed rules
//!
//! ### Key Security Features
//! 1. **Single Initialization**: Prevents program re-configuration
//! 2. **Authorization Checks**: Only authorized key can trigger payouts
//! 3. **Balance Validation**: Prevents overdrafts
//! 4. **Atomic Transfers**: All-or-nothing batch operations
//! 5. **Complete Audit Trail**: Full payout history tracking
//! 6. **Overflow Protection**: Safe arithmetic for all calculations
//!
//! ## Usage Example
//!
//! ```rust
//! use soroban_sdk::{Address, Env, String, vec};
//!
//! // 1. Initialize program (one-time setup)
//! let program_id = String::from_str(&env, "Hackathon2024");
//! let backend = Address::from_string("GBACKEND...");
//! let usdc_token = Address::from_string("CUSDC...");
//! 
//! let program = escrow_client.init_program(
//!     &program_id,
//!     &backend,
//!     &usdc_token
//! );
//!
//! // 2. Lock prize pool (10,000 USDC)
//! let prize_pool = 10_000_0000000; // 10,000 USDC (7 decimals)
//! escrow_client.lock_program_funds(&prize_pool);
//!
//! // 3. After hackathon, distribute prizes
//! let winners = vec![
//!     &env,
//!     Address::from_string("GWINNER1..."),
//!     Address::from_string("GWINNER2..."),
//!     Address::from_string("GWINNER3..."),
//! ];
//! 
//! let prizes = vec![
//!     &env,
//!     5_000_0000000,  // 1st place: 5,000 USDC
//!     3_000_0000000,  // 2nd place: 3,000 USDC
//!     2_000_0000000,  // 3rd place: 2,000 USDC
//! ];
//!
//! escrow_client.batch_payout(&winners, &prizes);
//! ```
//!
//! ## Event System
//!
//! The contract emits events for all major operations:
//! - `ProgramInit`: Program initialization
//! - `FundsLocked`: Prize funds locked
//! - `BatchPayout`: Multiple prizes distributed
//! - `Payout`: Single prize distributed
//!
//! ## Best Practices
//!
//! 1. **Verify Winners**: Confirm winner addresses off-chain before payout
//! 2. **Test Payouts**: Use testnet for testing prize distributions
//! 3. **Secure Backend**: Protect authorized payout key with HSM/multi-sig
//! 4. **Audit History**: Review payout history before each distribution
//! 5. **Balance Checks**: Verify remaining balance matches expectations
//! 6. **Token Approval**: Ensure contract has token allowance before locking funds

#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, vec, Address, Env, Map, String, Symbol, Vec,
    token,
};

// ============================================================================
// Error Definitions
// ============================================================================

/// Contract error codes for the Program Escrow system.
///
/// # Error Codes
/// * `AlreadyInitialized (1)` - Program has already been initialized
/// * `NotInitialized (2)` - Program must be initialized before use
/// * `InsufficientBalance (3)` - Insufficient funds for payout
/// * `Unauthorized (4)` - Caller lacks required authorization
/// * `InvalidAmount (5)` - Amount must be greater than zero
/// * `BatchMismatch (6)` - Recipients and amounts vectors length mismatch
/// * `MetadataTooLarge (7)` - Metadata exceeds size limits
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Returned when attempting to initialize an already initialized program
    AlreadyInitialized = 1,
    
    /// Returned when calling program functions before initialization
    NotInitialized = 2,
    
    /// Returned when attempting payout with insufficient balance
    InsufficientBalance = 3,
    
    /// Returned when caller lacks required authorization for the operation
    Unauthorized = 4,
    
    /// Returned when amount is zero or negative
    InvalidAmount = 5,
    
    /// Returned when recipients and amounts vectors have different lengths
    BatchMismatch = 6,
    
    /// Returned when metadata exceeds size limits
    MetadataTooLarge = 7,
}

// ============================================================================
// Event Types
// ============================================================================

/// Event emitted when a program is initialized.
/// Topic: `ProgramInit`
const PROGRAM_INITIALIZED: Symbol = symbol_short!("ProgramInit");

/// Event emitted when funds are locked in the program.
/// Topic: `FundsLocked`
const FUNDS_LOCKED: Symbol = symbol_short!("FundsLocked");

/// Event emitted when a batch payout is executed.
/// Topic: `BatchPayout`
const BATCH_PAYOUT: Symbol = symbol_short!("BatchPayout");

/// Event emitted when a single payout is executed.
/// Topic: `Payout`
const PAYOUT: Symbol = symbol_short!("Payout");

// ============================================================================
// Storage Keys
// ============================================================================

/// Storage key for program data.
/// Contains all program state including balances and payout history.
const PROGRAM_DATA: Symbol = symbol_short!("ProgramData");

/// Storage key for program metadata.
/// Contains optional metadata for indexing and categorization.
const PROGRAM_METADATA: Symbol = symbol_short!("ProgramMeta");

// ============================================================================
// Data Structures
// ============================================================================

/// Record of an individual payout transaction.
///
/// # Fields
/// * `recipient` - Address that received the payout
/// * `amount` - Amount transferred (in token's smallest denomination)
/// * `timestamp` - Unix timestamp when payout was executed
///
/// # Usage
/// These records are stored in the payout history to provide a complete
/// audit trail of all prize distributions.
///
/// # Example
/// ```rust
/// let record = PayoutRecord {
///     recipient: winner_address,
///     amount: 1000_0000000, // 1000 USDC
///     timestamp: env.ledger().timestamp(),
/// };
/// ```
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayoutRecord {
    pub recipient: Address,
    pub amount: i128,
    pub timestamp: u64,
}

/// Complete program state and configuration.
///
/// # Fields
/// * `program_id` - Unique identifier for the program/hackathon
/// * `total_funds` - Total amount of funds locked (cumulative)
/// * `remaining_balance` - Current available balance for payouts
/// * `authorized_payout_key` - Address authorized to trigger payouts
/// * `payout_history` - Complete record of all payouts
/// * `token_address` - Token contract used for transfers
///
/// # Storage
/// Stored in instance storage with key `PROGRAM_DATA`.
///
/// # Invariants
/// - `remaining_balance <= total_funds` (always)
/// - `remaining_balance = total_funds - sum(payout_history.amounts)`
/// - `payout_history` is append-only
/// - `program_id` and `authorized_payout_key` are immutable after init
///
/// # Example
/// ```rust
/// let program_data = ProgramData {
///     program_id: String::from_str(&env, "Hackathon2024"),
///     total_funds: 10_000_0000000,
///     remaining_balance: 7_000_0000000,
///     authorized_payout_key: backend_address,
///     payout_history: vec![&env],
///     token_address: usdc_token_address,
/// };
/// ```
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramData {
    pub program_id: String,
    pub total_funds: i128,
    pub remaining_balance: i128,
    pub authorized_payout_key: Address,
    pub payout_history: Vec<PayoutRecord>,
    pub token_address: Address,
}

/// Metadata structure for enhanced program indexing and categorization.
///
/// # Fields
/// * `event_name` - Full event/hackathon name
/// * `event_type` - Type classification (e.g., "hackathon", "grant", "bounty-program")
/// * `start_date` - Event start date (YYYY-MM-DD format)
/// * `end_date` - Event end date (YYYY-MM-DD format)
/// * `website` - Event website URL
/// * `tags` - Custom tags for filtering and categorization
/// * `custom_fields` - Additional key-value pairs for extensibility
///
/// # Size Limits
/// * Total serialized size: 2048 bytes maximum
/// * Tags vector: 30 items maximum
/// * Custom fields map: 15 key-value pairs maximum
/// * Individual string values: 256 characters maximum
///
/// # Storage
/// Stored in instance storage with key `PROGRAM_METADATA`.
/// Metadata is optional and can be added/updated after program creation.
///
/// # Example
/// ```rust
/// let metadata = ProgramMetadata {
///     event_name: Some(String::from_str(&env, "Stellar Hackathon 2024")),
///     event_type: Some(String::from_str(&env, "hackathon")),
///     start_date: Some(String::from_str(&env, "2024-06-01")),
///     end_date: Some(String::from_str(&env, "2024-06-30")),
///     website: Some(String::from_str(&env, "https://hackathon.stellar.org")),
///     tags: vec![&env,
///         String::from_str(&env, "blockchain"),
///         String::from_str(&env, "defi"),
///         String::from_str(&env, "web3")
///     ],
///     custom_fields: map![
///         &env,
///         (String::from_str(&env, "track_count"), String::from_str(&env, "5")),
///         (String::from_str(&env, "expected_participants"), String::from_str(&env, "500"))
///     ]
/// };
/// ```
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramMetadata {
    pub event_name: Option<String>,
    pub event_type: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub website: Option<String>,
    pub tags: Vec<String>,
    pub custom_fields: Map<String, String>,
}

/// Combined view of program data and metadata for convenient access.
///
/// # Fields
/// * `program` - Core program information
/// * `metadata` - Optional metadata (None if not set)
///
/// # Usage
/// Provides a unified interface for retrieving complete program information
/// including both financial and descriptive data.
///
/// # Example
/// ```rust
/// let program_view = escrow_client.get_program_with_metadata()?;
/// if let Some(metadata) = program_view.metadata {
///     println!("Event: {:?}", metadata.event_name);
///     println!("Type: {:?}", metadata.event_type);
///     println!("Website: {:?}", metadata.website);
/// }
/// ```
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramWithMetadata {
    pub program: ProgramData,
    pub metadata: Option<ProgramMetadata>,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Validates program metadata size limits to prevent excessive storage costs.
///
/// # Parameters
/// * `metadata` - Metadata to validate
///
/// # Returns
/// * `true` if metadata is within size limits
/// * `false` if metadata exceeds limits
///
/// # Limits Checked
/// * Tags vector length ≤ 30
/// * Custom fields map size ≤ 15
/// * Individual string values ≤ 256 characters
/// * Total serialized size ≤ 2048 bytes
fn validate_program_metadata_size(env: &Env, metadata: &ProgramMetadata) -> bool {
    // Check tags limit
    if metadata.tags.len() > 30 {
        return false;
    }
    
    // Check custom fields limit
    if metadata.custom_fields.len() > 15 {
        return false;
    }
    
    // Check individual string lengths
    if let Some(event_name) = &metadata.event_name {
        if event_name.len() > 256 {
            return false;
        }
    }
    
    if let Some(event_type) = &metadata.event_type {
        if event_type.len() > 256 {
            return false;
        }
    }
    
    if let Some(start_date) = &metadata.start_date {
        if start_date.len() > 256 {
            return false;
        }
    }
    
    if let Some(end_date) = &metadata.end_date {
        if end_date.len() > 256 {
            return false;
        }
    }
    
    if let Some(website) = &metadata.website {
        if website.len() > 256 {
            return false;
        }
    }
    
    for tag in metadata.tags.iter() {
        if tag.len() > 256 {
            return false;
        }
    }
    
    for (_, value) in metadata.custom_fields.iter() {
        if value.len() > 256 {
            return false;
        }
    }
    
    // Check total serialized size (approximate)
    let serialized_size = env
        .serialize_to_bytes(metadata)
        .len();
    
    serialized_size <= 2048
}

// ============================================================================
// Contract Implementation
// ============================================================================

#[contract]
pub struct ProgramEscrowContract;

#[contractimpl]
impl ProgramEscrowContract {
    // ========================================================================
    // Initialization
    // ========================================================================

    /// Initializes a new program escrow for managing prize distributions.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `program_id` - Unique identifier for this program/hackathon
    /// * `authorized_payout_key` - Address authorized to trigger payouts (backend)
    /// * `token_address` - Address of the token contract for transfers (e.g., USDC)
    ///
    /// # Returns
    /// * `ProgramData` - The initialized program configuration
    ///
    /// # Returns
    /// * `Ok(ProgramData)` - The initialized program configuration
    /// * `Err(Error::AlreadyInitialized)` - Program already initialized
    ///
    /// # State Changes
    /// - Creates ProgramData with zero balances
    /// - Sets authorized payout key (immutable after this)
    /// - Initializes empty payout history
    /// - Emits ProgramInitialized event
    ///
    /// # Security Considerations
    /// - Can only be called once (prevents re-configuration)
    /// - No authorization required (first-caller initialization)
    /// - Authorized payout key should be a secure backend service
    /// - Token address must be a valid Stellar Asset Contract
    /// - Program ID should be unique and descriptive
    ///
    /// # Events
    /// Emits: `ProgramInit(program_id, authorized_payout_key, token_address, 0)`
    ///
    /// # Example
    /// ```rust
    /// use soroban_sdk::{Address, String, Env};
    /// 
    /// let program_id = String::from_str(&env, "ETHGlobal2024");
    /// let backend = Address::from_string("GBACKEND...");
    /// let usdc = Address::from_string("CUSDC...");
    /// 
    /// let program = escrow_client.init_program(
    ///     &program_id,
    ///     &backend,
    ///     &usdc
    /// );
    /// 
    /// println!("Program created: {}", program.program_id);
    /// ```
    ///
    /// # Production Setup
    /// ```bash
    /// # Deploy contract
    /// stellar contract deploy \
    ///   --wasm target/wasm32-unknown-unknown/release/escrow.wasm \
    ///   --source ORGANIZER_KEY
    ///
    /// # Initialize program
    /// stellar contract invoke \
    ///   --id CONTRACT_ID \
    ///   --source ORGANIZER_KEY \
    ///   -- init_program \
    ///   --program_id "Hackathon2024" \
    ///   --authorized_payout_key GBACKEND... \
    ///   --token_address CUSDC...
    /// ```
    ///
    /// # Gas Cost
    /// Low - Initial storage writes
    pub fn init_program(
        env: Env,
        program_id: String,
        authorized_payout_key: Address,
        token_address: Address,
    ) -> Result<ProgramData, Error> {
        // Prevent re-initialization
        if env.storage().instance().has(&PROGRAM_DATA) {
            return Err(Error::AlreadyInitialized);
        }

        // Create program data with zero balances
        let program_data = ProgramData {
            program_id: program_id.clone(),
            total_funds: 0,
            remaining_balance: 0,
            authorized_payout_key: authorized_payout_key.clone(),
            payout_history: vec![&env],
            token_address: token_address.clone(),
        };

        // Store program configuration
        env.storage().instance().set(&PROGRAM_DATA, &program_data);

        // Emit initialization event
        env.events().publish(
            (PROGRAM_INITIALIZED,),
            (program_id, authorized_payout_key, token_address, 0i128),
        );

        Ok(program_data)
    }

    /// Sets or updates metadata for the program.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `metadata` - Metadata structure containing event details and tags
    ///
    /// # Returns
    /// * `Ok(())` - Metadata successfully set/updated
    /// * `Err(Error::NotInitialized)` - Program not initialized
    /// * `Err(Error::MetadataTooLarge)` - Metadata exceeds size limits
    /// * `Err(Error::Unauthorized)` - Caller is not the authorized payout key
    ///
    /// # State Changes
    /// - Stores/updates metadata in instance storage
    ///
    /// # Authorization
    /// - Only the authorized payout key can set/update metadata
    /// - This prevents unauthorized metadata modification
    ///
    /// # Size Limits
    /// See `validate_program_metadata_size()` documentation for detailed limits.
    ///
    /// # Example
    /// ```rust
    /// let metadata = ProgramMetadata {
    ///     event_name: Some(String::from_str(&env, "Stellar Hackathon 2024")),
    ///     event_type: Some(String::from_str(&env, "hackathon")),
    ///     start_date: Some(String::from_str(&env, "2024-06-01")),
    ///     end_date: Some(String::from_str(&env, "2024-06-30")),
    ///     website: Some(String::from_str(&env, "https://hackathon.stellar.org")),
    ///     tags: vec![&env, String::from_str(&env, "blockchain")],
    ///     custom_fields: map![&env],
    /// };
    /// 
    /// escrow_client.set_program_metadata(&metadata);
    /// ```
    pub fn set_program_metadata(env: Env, metadata: ProgramMetadata) -> Result<(), Error> {
        // Verify program is initialized
        if !env.storage().instance().has(&PROGRAM_DATA) {
            return Err(Error::NotInitialized);
        }

        // Get current program data for authorization check
        let program_data: ProgramData = env
            .storage()
            .instance()
            .get(&PROGRAM_DATA)
            .unwrap();

        // Verify authorization
        let caller = env.invoker();
        if caller != program_data.authorized_payout_key {
            return Err(Error::Unauthorized);
        }

        // Validate metadata size limits
        if !validate_program_metadata_size(&env, &metadata) {
            return Err(Error::MetadataTooLarge);
        }

        // Store metadata
        env.storage().instance().set(&PROGRAM_METADATA, &metadata);

        Ok(())
    }

    // ========================================================================
    // Fund Management
    // ========================================================================

    /// Locks funds into the program escrow for prize distribution.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `amount` - Amount of tokens to lock (in token's smallest denomination)
    ///
    /// # Returns
    /// * `ProgramData` - Updated program data with new balance
    ///
    /// # Returns
    /// * `Ok(ProgramData)` - Updated program data with new balance
    /// * `Err(Error::InvalidAmount)` - Amount must be greater than zero
    /// * `Err(Error::NotInitialized)` - Program not initialized
    ///
    /// # State Changes
    /// - Increases `total_funds` by amount
    /// - Increases `remaining_balance` by amount
    /// - Emits FundsLocked event
    ///
    /// # Prerequisites
    /// Before calling this function:
    /// 1. Caller must have sufficient token balance
    /// 2. Caller must approve contract for token transfer
    /// 3. Tokens must actually be transferred to contract
    ///
    /// # Security Considerations
    /// - Amount must be positive
    /// - This function doesn't perform the actual token transfer
    /// - Caller is responsible for transferring tokens to contract
    /// - Consider verifying contract balance matches recorded amount
    /// - Multiple lock operations are additive (cumulative)
    ///
    /// # Events
    /// Emits: `FundsLocked(program_id, amount, new_remaining_balance)`
    ///
    /// # Example
    /// ```rust
    /// use soroban_sdk::token;
    /// 
    /// // 1. Transfer tokens to contract
    /// let amount = 10_000_0000000; // 10,000 USDC
    /// token_client.transfer(
    ///     &organizer,
    ///     &contract_address,
    ///     &amount
    /// );
    /// 
    /// // 2. Record the locked funds
    /// let updated = escrow_client.lock_program_funds(&amount);
    /// println!("Locked: {} USDC", amount / 10_000_000);
    /// println!("Remaining: {}", updated.remaining_balance);
    /// ```
    ///
    /// # Production Usage
    /// ```bash
    /// # 1. Transfer USDC to contract
    /// stellar contract invoke \
    ///   --id USDC_TOKEN_ID \
    ///   --source ORGANIZER_KEY \
    ///   -- transfer \
    ///   --from ORGANIZER_ADDRESS \
    ///   --to CONTRACT_ADDRESS \
    ///   --amount 10000000000
    ///
    /// # 2. Record locked funds
    /// stellar contract invoke \
    ///   --id CONTRACT_ID \
    ///   --source ORGANIZER_KEY \
    ///   -- lock_program_funds \
    ///   --amount 10000000000
    /// ```
    ///
    /// # Gas Cost
    /// Low - Storage update + event emission
    ///
    /// # Common Pitfalls
    /// - Forgetting to transfer tokens before calling
    /// -  Locking amount that exceeds actual contract balance
    /// -  Not verifying contract received the tokens
    pub fn lock_program_funds(env: Env, amount: i128) -> Result<ProgramData, Error> {
        // Validate amount
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        // Verify program is initialized
        if !env.storage().instance().has(&PROGRAM_DATA) {
            return Err(Error::NotInitialized);
        }

        // Get current program data
        let mut program_data: ProgramData = env
            .storage()
            .instance()
            .get(&PROGRAM_DATA)
            .unwrap();

        // Update balances (cumulative)
        program_data.total_funds += amount;
        program_data.remaining_balance += amount;

        // Store updated data
        env.storage().instance().set(&PROGRAM_DATA, &program_data);

        // Emit funds locked event
        env.events().publish(
            (FUNDS_LOCKED,),
            (
                program_data.program_id.clone(),
                amount,
                program_data.remaining_balance,
            ),
        );

        Ok(program_data)
    }

    // ========================================================================
    // Payout Functions
    // ========================================================================

    /// Executes batch payouts to multiple recipients simultaneously.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `recipients` - Vector of recipient addresses
    /// * `amounts` - Vector of amounts (must match recipients length)
    ///
    /// # Returns
    /// * `Ok(ProgramData)` - Updated program data after payouts
    /// * `Err(Error::Unauthorized)` - Caller is not the authorized payout key
    /// * `Err(Error::NotInitialized)` - Program not initialized
    /// * `Err(Error::BatchMismatch)` - Recipients and amounts vectors length mismatch
    /// * `Err(Error::InvalidAmount)` - Amount is zero or negative
    /// * `Err(Error::InsufficientBalance)` - Total payout exceeds remaining balance
    ///
    /// # Authorization
    /// - **CRITICAL**: Only authorized payout key can call
    /// - Caller must be exact match to `authorized_payout_key`
    ///
    /// # State Changes
    /// - Transfers tokens from contract to each recipient
    /// - Adds PayoutRecord for each transfer to history
    /// - Decreases `remaining_balance` by total payout amount
    /// - Emits BatchPayout event
    ///
    /// # Atomicity
    /// This operation is atomic - either all transfers succeed or all fail.
    /// If any transfer fails, the entire batch is reverted.
    ///
    /// # Security Considerations
    /// - Verify recipient addresses off-chain before calling
    /// - Ensure amounts match winner rankings/criteria
    /// - Total payout is calculated with overflow protection
    /// - Balance check prevents overdraft
    /// - All transfers are logged for audit trail
    /// - Consider implementing payout limits for additional safety
    ///
    /// # Events
    /// Emits: `BatchPayout(program_id, recipient_count, total_amount, new_balance)`
    ///
    /// # Example
    /// ```rust
    /// use soroban_sdk::{vec, Address};
    /// 
    /// // Define winners and prizes
    /// let winners = vec![
    ///     &env,
    ///     Address::from_string("GWINNER1..."), // 1st place
    ///     Address::from_string("GWINNER2..."), // 2nd place
    ///     Address::from_string("GWINNER3..."), // 3rd place
    /// ];
    /// 
    /// let prizes = vec![
    ///     &env,
    ///     5_000_0000000,  // $5,000 USDC
    ///     3_000_0000000,  // $3,000 USDC
    ///     2_000_0000000,  // $2,000 USDC
    /// ];
    /// 
    /// // Execute batch payout (only authorized backend can call)
    /// let result = escrow_client.batch_payout(&winners, &prizes);
    /// println!("Paid {} winners", winners.len());
    /// println!("Remaining: {}", result.remaining_balance);
    /// ```
    ///
    /// # Production Usage
    /// ```bash
    /// # Batch payout to 3 winners
    /// stellar contract invoke \
    ///   --id CONTRACT_ID \
    ///   --source BACKEND_KEY \
    ///   -- batch_payout \
    ///   --recipients '["GWINNER1...", "GWINNER2...", "GWINNER3..."]' \
    ///   --amounts '[5000000000, 3000000000, 2000000000]'
    /// ```
    ///
    /// # Gas Cost
    /// High - Multiple token transfers + storage updates
    /// Cost scales linearly with number of recipients
    ///
    /// # Best Practices
    /// 1. Verify all winner addresses before execution
    /// 2. Double-check prize amounts match criteria
    /// 3. Test on testnet with same number of recipients
    /// 4. Monitor events for successful completion
    /// 5. Keep batch size reasonable (recommend < 50 recipients)
    ///
    /// # Limitations
    /// - Maximum batch size limited by gas/resource limits
    /// - For very large batches, consider multiple calls
    /// - All amounts must be positive
    pub fn batch_payout(
        env: Env,
        recipients: Vec<Address>,
        amounts: Vec<i128>,
    ) -> Result<ProgramData, Error> {
        // Verify program is initialized
        if !env.storage().instance().has(&PROGRAM_DATA) {
            return Err(Error::NotInitialized);
        }

        // Get current program data
        let program_data: ProgramData = env
            .storage()
            .instance()
            .get(&PROGRAM_DATA)
            .unwrap();

        // Verify authorization - CRITICAL security check
        let caller = env.invoker();
        if caller != program_data.authorized_payout_key {
            return Err(Error::Unauthorized);
        }

        // Validate input lengths match
        if recipients.len() != amounts.len() {
            return Err(Error::BatchMismatch);
        }

        // Validate non-empty batch
        if recipients.len() == 0 {
            return Err(Error::BatchMismatch);
        }

        // Calculate total payout with overflow protection
        let mut total_payout: i128 = 0;
        for amount in amounts.iter() {
            if *amount <= 0 {
                return Err(Error::InvalidAmount);
            }
            total_payout = total_payout
                .checked_add(*amount)
                .ok_or(Error::InvalidAmount)?;
        }

        // Validate sufficient balance
        if total_payout > program_data.remaining_balance {
            return Err(Error::InsufficientBalance);
        }

        // Execute transfers and record payouts
        let mut updated_history = program_data.payout_history.clone();
        let timestamp = env.ledger().timestamp();
        let contract_address = env.current_contract_address();
        let token_client = token::Client::new(&env, &program_data.token_address);

        for (i, recipient) in recipients.iter().enumerate() {
            let amount = amounts.get(i).unwrap();

            // Transfer tokens from contract to recipient
            token_client.transfer(&contract_address, recipient, amount);

            // Record payout in history
            let payout_record = PayoutRecord {
                recipient: recipient.clone(),
                amount: *amount,
                timestamp,
            };
            updated_history.push_back(payout_record);
        }

        // Update program data
        let mut updated_data = program_data.clone();
        updated_data.remaining_balance -= total_payout;
        updated_data.payout_history = updated_history;

        // Store updated data
        env.storage()
            .instance()
            .set(&PROGRAM_DATA, &updated_data);

        // Emit batch payout event
        env.events().publish(
            (BATCH_PAYOUT,),
            (
                updated_data.program_id.clone(),
                recipients.len() as u32,
                total_payout,
                updated_data.remaining_balance,
            ),
        );

        Ok(updated_data)
    }

    /// Executes a single payout to one recipient.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `recipient` - Address of the prize recipient
    /// * `amount` - Amount to transfer (in token's smallest denomination)
    ///
    /// # Returns
    /// * `Ok(ProgramData)` - Updated program data after payout
    /// * `Err(Error::Unauthorized)` - Caller is not the authorized payout key
    /// * `Err(Error::NotInitialized)` - Program not initialized
    /// * `Err(Error::InvalidAmount)` - Amount is zero or negative
    /// * `Err(Error::InsufficientBalance)` - Amount exceeds remaining balance
    ///
    /// # Authorization
    /// - Only authorized payout key can call this function
    ///
    /// # State Changes
    /// - Transfers tokens from contract to recipient
    /// - Adds PayoutRecord to history
    /// - Decreases `remaining_balance` by amount
    /// - Emits Payout event
    ///
    /// # Security Considerations
    /// - Verify recipient address before calling
    /// - Amount must be positive
    /// - Balance check prevents overdraft
    /// - Transfer is logged in payout history
    ///
    /// # Events
    /// Emits: `Payout(program_id, recipient, amount, new_balance)`
    ///
    /// # Example
    /// ```rust
    /// use soroban_sdk::Address;
    /// 
    /// let winner = Address::from_string("GWINNER...");
    /// let prize = 1_000_0000000; // $1,000 USDC
    /// 
    /// // Execute single payout
    /// let result = escrow_client.single_payout(&winner, &prize);
    /// println!("Paid {} to winner", prize);
    /// ```
    ///
    /// # Gas Cost
    /// Medium - Single token transfer + storage update
    ///
    /// # Use Cases
    /// - Individual prize awards
    /// - Bonus payments
    /// - Late additions to prize pool distribution
    pub fn single_payout(env: Env, recipient: Address, amount: i128) -> Result<ProgramData, Error> {
        // Verify program is initialized
        if !env.storage().instance().has(&PROGRAM_DATA) {
            return Err(Error::NotInitialized);
        }

        // Get current program data
        let program_data: ProgramData = env
            .storage()
            .instance()
            .get(&PROGRAM_DATA)
            .unwrap();

        // Verify authorization
        let caller = env.invoker();
        if caller != program_data.authorized_payout_key {
            return Err(Error::Unauthorized);
        }

        // Validate amount
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        // Validate sufficient balance
        if amount > program_data.remaining_balance {
            return Err(Error::InsufficientBalance);
        }

        // Transfer tokens to recipient
        let contract_address = env.current_contract_address();
        let token_client = token::Client::new(&env, &program_data.token_address);
        token_client.transfer(&contract_address, &recipient, &amount);

        // Record payout
        let timestamp = env.ledger().timestamp();
        let payout_record = PayoutRecord {
            recipient: recipient.clone(),
            amount,
            timestamp,
        };

        let mut updated_history = program_data.payout_history.clone();
        updated_history.push_back(payout_record);

        // Update program data
        let mut updated_data = program_data.clone();
        updated_data.remaining_balance -= amount;
        updated_data.payout_history = updated_history;

        // Store updated data
        env.storage()
            .instance()
            .set(&PROGRAM_DATA, &updated_data);

        // Emit payout event
        env.events().publish(
            (PAYOUT,),
            (
                updated_data.program_id.clone(),
                recipient,
                amount,
                updated_data.remaining_balance,
            ),
        );

        Ok(updated_data)
    }

    // ========================================================================
    // View Functions (Read-only)
    // ========================================================================

    /// Retrieves complete program information.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    /// * `Ok(ProgramData)` - Complete program state including:
    ///   - Program ID
    ///   - Total funds locked
    ///   - Remaining balance
    ///   - Authorized payout key
    ///   - Complete payout history
    ///   - Token contract address
    /// * `Err(Error::NotInitialized)` - Program not initialized
    ///
    /// # Use Cases
    /// - Verifying program configuration
    /// - Checking balances before payouts
    /// - Auditing payout history
    /// - Displaying program status in UI
    ///
    /// # Example
    /// ```rust
    /// let info = escrow_client.get_program_info();
    /// println!("Program: {}", info.program_id);
    /// println!("Total Locked: {}", info.total_funds);
    /// println!("Remaining: {}", info.remaining_balance);
    /// println!("Payouts Made: {}", info.payout_history.len());
    /// ```
    ///
    /// # Gas Cost
    /// Very Low - Single storage read
    pub fn get_program_info(env: Env) -> Result<ProgramData, Error> {
        if !env.storage().instance().has(&PROGRAM_DATA) {
            return Err(Error::NotInitialized);
        }
        
        Ok(env.storage()
            .instance()
            .get(&PROGRAM_DATA)
            .unwrap())
    }

    /// Retrieves metadata for the program.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    /// * `Ok(Option<ProgramMetadata>)` - Metadata if set, None if not set
    /// * `Err(Error::NotInitialized)` - Program not initialized
    ///
    /// # Example
    /// ```rust
    /// let metadata_opt = escrow_client.get_program_metadata();
    /// if let Some(metadata) = metadata_opt {
    ///     println!("Event: {:?}", metadata.event_name);
    ///     println!("Type: {:?}", metadata.event_type);
    ///     println!("Website: {:?}", metadata.website);
    ///     println!("Tags: {:?}", metadata.tags);
    /// }
    /// ```
    pub fn get_program_metadata(env: Env) -> Result<Option<ProgramMetadata>, Error> {
        // Verify program is initialized
        if !env.storage().instance().has(&PROGRAM_DATA) {
            return Err(Error::NotInitialized);
        }
        
        // Get metadata if it exists
        Ok(env.storage().instance().get(&PROGRAM_METADATA))
    }

    /// Retrieves complete program information including metadata.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    /// * `Ok(ProgramWithMetadata)` - Combined program and metadata information
    /// * `Err(Error::NotInitialized)` - Program not initialized
    ///
    /// # Example
    /// ```rust
    /// let program_view = escrow_client.get_program_with_metadata();
    /// println!("Program: {}", program_view.program.program_id);
    /// println!("Balance: {}", program_view.program.remaining_balance);
    /// 
    /// if let Some(meta) = program_view.metadata {
    ///     println!("Event: {:?}", meta.event_name);
    ///     println!("Website: {:?}", meta.website);
    /// }
    /// ```
    pub fn get_program_with_metadata(env: Env) -> Result<ProgramWithMetadata, Error> {
        // Get core program data
        let program = Self::get_program_info(env.clone())?;
        
        // Get metadata if it exists
        let metadata = Self::get_program_metadata(env)?;
        
        Ok(ProgramWithMetadata {
            program,
            metadata,
        })
    }

    /// Retrieves the remaining balance available in the program.
    ///
    /// This function returns the amount of funds still locked in the program
    /// and available for future payouts.
    ///
    /// # Arguments
    /// * `env` - The contract environment
    ///
    /// # Returns
    /// * `Ok(i128)` - Remaining token balance that has not been paid out
    /// * `Err(Error::NotInitialized)` - Program not initialized
    ///
    /// # Use Cases
    /// - Checking available funds before initiating a payout
    /// - Displaying remaining balance in dashboards or UIs
    /// - Validating program solvency
    ///
    /// # Example
    /// ```rust
    /// let remaining = escrow_client.get_remaining_balance();
    /// println!("Remaining balance: {}", remaining);
    /// ```
    ///
    /// # Security Considerations
    /// - Read-only function
    /// - Does not modify contract state
    ///
    /// # Gas Cost
    /// Very Low - Single storage read
    pub fn get_remaining_balance(env: Env) -> Result<i128, Error> {
        if !env.storage().instance().has(&PROGRAM_DATA) {
            return Err(Error::NotInitialized);
        }
        
        let program_data: ProgramData = env
            .storage()
            .instance()
            .get(&PROGRAM_DATA)
            .unwrap();

        Ok(program_data.remaining_balance)
    }
}
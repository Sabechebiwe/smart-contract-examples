use access_controller::accounts::{
    AcceptOwnership,
    AddAccess,
    Initialize,
    RemoveAccess,
    TransferOwnership,
};
use access_controller::instruction::{
    AcceptOwnership as AcceptOwnershipInstruction,
    AddAccess as AddAccessInstruction,
    Initialize as InitializeInstruction,
    RemoveAccess as RemoveAccessInstruction,
    TransferOwnership as TransferOwnershipInstruction,
};
use solana_client::client_error::ClientError;
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcSendTransactionConfig;
use solana_sdk::commitment_config::CommitmentLevel;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature};
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;

use access_controller::AccessController;

use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};

pub struct AccessControllerClient {
    program_id: Pubkey,
    access_controller_data_account: Pubkey,
    rpc_client: RpcClient,
    payer: Keypair,
}

impl AccessControllerClient {
    pub fn new(
        program_id: Pubkey,
        access_controller_data_account: Pubkey,
        rpc_client: RpcClient,
        payer: Keypair,
    ) -> Self {
        Self {
            program_id,
            access_controller_data_account,
            rpc_client,
            payer,
        }
    }

    pub fn initialize(&self) -> Result<Signature, ClientError> {
        let data = InitializeInstruction {};

        let initialize_context = Initialize {
            state: self.access_controller_data_account,
            owner: self.payer.pubkey(),
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: initialize_context.to_account_metas(None),
            data: data.data(),
        };

        self.send_transaction(&[instruction], &[&self.payer])
    }

    pub fn add_access(&self, address: Pubkey) -> Result<Signature, ClientError> {
        let data = AddAccessInstruction {};

        let add_access_context = AddAccess {
            state: self.access_controller_data_account,
            owner: self.payer.pubkey(),
            address,
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: add_access_context.to_account_metas(None),
            data: data.data(),
        };

        self.send_transaction(&[instruction], &[&self.payer])
    }

    pub fn remove_access(&self, address: Pubkey) -> Result<Signature, ClientError> {
        let data = RemoveAccessInstruction {};

        let remove_access_context = RemoveAccess {
            state: self.access_controller_data_account,
            owner: self.payer.pubkey(),
            address,
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: remove_access_context.to_account_metas(None),
            data: data.data(),
        };

        self.send_transaction(&[instruction], &[&self.payer])
    }

    pub fn transfer_ownership(&self, proposed_owner: Pubkey) -> Result<Signature, ClientError> {
        let data = TransferOwnershipInstruction {
            proposed_owner,
        };

        let transfer_ownership_context = TransferOwnership {
            state: self.access_controller_data_account,
            authority: self.payer.pubkey(),
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: transfer_ownership_context.to_account_metas(None),
            data: data.data(),
        };

        self.send_transaction(&[instruction], &[&self.payer])
    }

    pub fn accept_ownership(&self) -> Result<Signature, ClientError> {
        let data = AcceptOwnershipInstruction {};

        let accept_ownership_context = AcceptOwnership {
            state: self.access_controller_data_account,
            authority: self.payer.pubkey(),
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: accept_ownership_context.to_account_metas(None),
            data: data.data(),
        };

        self.send_transaction(&[instruction], &[&self.payer])
    }

    pub fn read_access_controller_state(&self) -> Result<AccessController, ClientError> {
        let account = self.rpc_client.get_account(&self.access_controller_data_account)?;
        let state = AccessController::try_deserialize(&mut &account.data[..])
            .unwrap();

        Ok(state)
    }

    pub fn get_account_size_requirement() -> usize {
        size_of::<AccessController>() + 8 // Add 8 bytes for discriminator
    }

    fn send_transaction(
        &self,
        instructions: &[Instruction],
        signers: &[&Keypair],
    ) -> Result<Signature, ClientError> {
        let recent_blockhash = self.rpc_client.get_latest_blockhash()?;

        let config = RpcSendTransactionConfig {
            skip_preflight: false,
            preflight_commitment: Some(CommitmentLevel::Processed),
            encoding: None,
            max_retries: Some(3),
            min_context_slot: None,
        };

        let mut transaction = Transaction::new_with_payer(instructions, Some(&self.payer.pubkey()));
        transaction.sign(signers, recent_blockhash);

        self.rpc_client.send_transaction_with_config(&transaction, config)
    }
}
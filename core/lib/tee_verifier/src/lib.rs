//! Tee verifier
//!
//! Verifies that a L1Batch has the expected root hash after
//! executing the VM and verifying all the accessed memory slots by their
//! merkle path.

use std::{cell::RefCell, rc::Rc};

use anyhow::Context;
use multivm::{
    interface::{FinishedL1Batch, L1BatchEnv, L2BlockEnv, SystemEnv, VmInterface},
    vm_latest::HistoryEnabled,
    VmInstance,
};
use serde::{Deserialize, Serialize};
use vm_utils::execute_tx;
use zksync_crypto::hasher::blake2::Blake2Hasher;
use zksync_merkle_tree::{
    BlockOutputWithProofs, TreeInstruction, TreeLogEntry, TreeLogEntryWithProof,
};
use zksync_object_store::{serialize_using_bincode, Bucket, StoredObject};
use zksync_prover_interface::inputs::{PrepareBasicCircuitsJob, StorageLogMetadata};
use zksync_state::{InMemoryStorage, StorageView, WriteStorage};
use zksync_types::{
    block::L2BlockExecutionData, ethabi::ethereum_types::BigEndianHash, zk_evm_types::LogQuery,
    AccountTreeId, L1BatchNumber, StorageKey, H256,
};
use zksync_utils::{bytecode::hash_bytecode, u256_to_h256};

/// Version 1 of the data used as input for the TEE verifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V1TeeVerifierInput {
    prepare_basic_circuits_job: PrepareBasicCircuitsJob,
    l2_blocks_execution_data: Vec<L2BlockExecutionData>,
    l1_batch_env: L1BatchEnv,
    system_env: SystemEnv,
    used_contracts: Vec<(H256, Vec<u8>)>,
}

/// Data used as input for the TEE verifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum TeeVerifierInput {
    /// `V0` suppresses warning about irrefutable `let...else` pattern
    V0,
    V1(V1TeeVerifierInput),
}

impl TeeVerifierInput {
    pub fn new(
        prepare_basic_circuits_job: PrepareBasicCircuitsJob,
        l2_blocks_execution_data: Vec<L2BlockExecutionData>,
        l1_batch_env: L1BatchEnv,
        system_env: SystemEnv,
        used_contracts: Vec<(H256, Vec<u8>)>,
    ) -> Self {
        TeeVerifierInput::V1(V1TeeVerifierInput {
            prepare_basic_circuits_job,
            l2_blocks_execution_data,
            l1_batch_env,
            system_env,
            used_contracts,
        })
    }

    /// Verify that the L1Batch produces the expected root hash
    /// by executing the VM and verifying the merkle paths of all
    /// touch storage slots.
    ///
    /// # Errors
    ///
    /// Returns a verbose error of the failure, because any error is
    /// not actionable.
    pub fn verify(self) -> anyhow::Result<()> {
        let TeeVerifierInput::V1(V1TeeVerifierInput {
            prepare_basic_circuits_job,
            l2_blocks_execution_data,
            l1_batch_env,
            system_env,
            used_contracts,
        }) = self
        else {
            tracing::error!("TeeVerifierInput variant not supported");
            anyhow::bail!("TeeVerifierInput variant not supported");
        };

        let old_root_hash = l1_batch_env.previous_batch_hash.unwrap();
        let l2_chain_id = system_env.chain_id;
        let enumeration_index = prepare_basic_circuits_job.next_enumeration_index();

        let mut raw_storage = InMemoryStorage::with_custom_system_contracts_and_chain_id(
            l2_chain_id,
            hash_bytecode,
            Vec::with_capacity(0),
        );

        for (hash, bytes) in used_contracts.into_iter() {
            tracing::trace!("raw_storage.store_factory_dep({hash}, bytes)");
            raw_storage.store_factory_dep(hash, bytes)
        }

        let block_output_with_proofs =
            Self::get_bowp_and_set_initial_values(prepare_basic_circuits_job, &mut raw_storage);

        let storage_view = Rc::new(RefCell::new(StorageView::new(&raw_storage)));

        let vm = VmInstance::new(l1_batch_env, system_env, storage_view);

        let vm_out = Self::execute_vm(l2_blocks_execution_data, vm)?;

        let instructions: Vec<TreeInstruction> =
            Self::generate_tree_instructions(enumeration_index, &block_output_with_proofs, vm_out)?;

        block_output_with_proofs
            .verify_proofs(&Blake2Hasher, old_root_hash, &instructions)
            .context("Failed to verify_proofs {l1_batch_number} correctly!")?;

        Ok(())
    }

    /// Sets the initial storage values and returns `BlockOutputWithProofs`
    fn get_bowp_and_set_initial_values(
        prepare_basic_circuits_job: PrepareBasicCircuitsJob,
        raw_storage: &mut InMemoryStorage,
    ) -> BlockOutputWithProofs {
        let logs = prepare_basic_circuits_job
            .into_merkle_paths()
            .map(
                |StorageLogMetadata {
                     root_hash,
                     merkle_paths,
                     is_write,
                     first_write,
                     leaf_enumeration_index,
                     value_read,
                     leaf_hashed_key: leaf_storage_key,
                     ..
                 }| {
                    let root_hash = root_hash.into();
                    let merkle_path = merkle_paths.into_iter().map(|x| x.into()).collect();
                    let base: TreeLogEntry = match (is_write, first_write, leaf_enumeration_index) {
                        (false, _, 0) => TreeLogEntry::ReadMissingKey,
                        (false, _, _) => {
                            // This is a special U256 here, which needs `to_little_endian`
                            let mut hashed_key = [0_u8; 32];
                            leaf_storage_key.to_little_endian(&mut hashed_key);
                            raw_storage.set_value_hashed_enum(
                                hashed_key.into(),
                                leaf_enumeration_index,
                                value_read.into(),
                            );
                            TreeLogEntry::Read {
                                leaf_index: leaf_enumeration_index,
                                value: value_read.into(),
                            }
                        }
                        (true, true, _) => TreeLogEntry::Inserted,
                        (true, false, _) => {
                            // This is a special U256 here, which needs `to_little_endian`
                            let mut hashed_key = [0_u8; 32];
                            leaf_storage_key.to_little_endian(&mut hashed_key);
                            raw_storage.set_value_hashed_enum(
                                hashed_key.into(),
                                leaf_enumeration_index,
                                value_read.into(),
                            );
                            TreeLogEntry::Updated {
                                leaf_index: leaf_enumeration_index,
                                previous_value: value_read.into(),
                            }
                        }
                    };
                    TreeLogEntryWithProof {
                        base,
                        merkle_path,
                        root_hash,
                    }
                },
            )
            .collect();

        BlockOutputWithProofs {
            logs,
            leaf_count: 0,
        }
    }

    /// Executes the VM and returns `FinishedL1Batch` on success.
    fn execute_vm<S: WriteStorage>(
        l2_blocks_execution_data: Vec<L2BlockExecutionData>,
        mut vm: VmInstance<S, HistoryEnabled>,
    ) -> anyhow::Result<FinishedL1Batch> {
        let next_l2_blocks_data = l2_blocks_execution_data.iter().skip(1);

        let l2_blocks_data = l2_blocks_execution_data.iter().zip(next_l2_blocks_data);

        for (l2_block_data, next_l2_block_data) in l2_blocks_data {
            tracing::trace!(
                "Started execution of l2_block: {:?}, executing {:?} transactions",
                l2_block_data.number,
                l2_block_data.txs.len(),
            );
            for tx in &l2_block_data.txs {
                tracing::trace!("Started execution of tx: {tx:?}");
                execute_tx(tx, &mut vm)
                    .context("failed to execute transaction in TeeVerifierInputProducer")?;
                tracing::trace!("Finished execution of tx: {tx:?}");
            }
            vm.start_new_l2_block(L2BlockEnv::from_l2_block_data(next_l2_block_data));

            tracing::trace!("Finished execution of l2_block: {:?}", l2_block_data.number);
        }

        Ok(vm.finish_batch())
    }

    /// Map `LogQuery` and `TreeLogEntry` to a `TreeInstruction`
    fn map_log_tree(
        log_query: &LogQuery,
        tree_log_entry: &TreeLogEntry,
        idx: &mut u64,
    ) -> anyhow::Result<TreeInstruction> {
        let key = StorageKey::new(
            AccountTreeId::new(log_query.address),
            u256_to_h256(log_query.key),
        )
        .hashed_key_u256();
        Ok(match (log_query.rw_flag, *tree_log_entry) {
            (true, TreeLogEntry::Updated { leaf_index, .. }) => {
                TreeInstruction::write(key, leaf_index, H256(log_query.written_value.into()))
            }
            (true, TreeLogEntry::Inserted) => {
                let leaf_index = *idx;
                *idx += 1;
                TreeInstruction::write(key, leaf_index, H256(log_query.written_value.into()))
            }
            (false, TreeLogEntry::Read { value, .. }) => {
                if log_query.read_value != value.into_uint() {
                    tracing::error!(
                        "Failed to map LogQuery to TreeInstruction: {:#?} != {:#?}",
                        log_query.read_value,
                        value
                    );
                    anyhow::bail!(
                        "Failed to map LogQuery to TreeInstruction: {:#?} != {:#?}",
                        log_query.read_value,
                        value
                    );
                }
                TreeInstruction::Read(key)
            }
            (false, TreeLogEntry::ReadMissingKey { .. }) => TreeInstruction::Read(key),
            _ => {
                tracing::error!("Failed to map LogQuery to TreeInstruction");
                anyhow::bail!("Failed to map LogQuery to TreeInstruction");
            }
        })
    }

    /// Generates the `TreeInstruction`s from the VM executions.
    fn generate_tree_instructions(
        mut idx: u64,
        bowp: &BlockOutputWithProofs,
        vm_out: FinishedL1Batch,
    ) -> anyhow::Result<Vec<TreeInstruction>> {
        vm_out
            .final_execution_state
            .deduplicated_storage_log_queries
            .into_iter()
            .zip(bowp.logs.iter())
            .map(|(log_query, tree_log_entry)| {
                Self::map_log_tree(&log_query, &tree_log_entry.base, &mut idx)
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

impl StoredObject for TeeVerifierInput {
    const BUCKET: Bucket = Bucket::TeeVerifierInput;
    type Key<'a> = L1BatchNumber;

    fn encode_key(key: Self::Key<'_>) -> String {
        format!("tee_verifier_input_for_l1_batch_{key}.bin")
    }

    serialize_using_bincode!();
}

#[cfg(test)]
mod tests {
    use multivm::interface::TxExecutionMode;
    use zksync_basic_types::U256;
    use zksync_contracts::{BaseSystemContracts, SystemContractCode};

    use super::*;

    #[test]
    fn test_v1_serialization() {
        let tvi = TeeVerifierInput::new(
            PrepareBasicCircuitsJob::new(0),
            vec![],
            L1BatchEnv {
                previous_batch_hash: Some(H256([1; 32])),
                number: Default::default(),
                timestamp: 0,
                fee_input: Default::default(),
                fee_account: Default::default(),
                enforced_base_fee: None,
                first_l2_block: L2BlockEnv {
                    number: 0,
                    timestamp: 0,
                    prev_block_hash: H256([1; 32]),
                    max_virtual_blocks_to_create: 0,
                },
            },
            SystemEnv {
                zk_porter_available: false,
                version: Default::default(),
                base_system_smart_contracts: BaseSystemContracts {
                    bootloader: SystemContractCode {
                        code: vec![U256([1; 4])],
                        hash: H256([1; 32]),
                    },
                    default_aa: SystemContractCode {
                        code: vec![U256([1; 4])],
                        hash: H256([1; 32]),
                    },
                },
                bootloader_gas_limit: 0,
                execution_mode: TxExecutionMode::VerifyExecute,
                default_validation_computational_gas_limit: 0,
                chain_id: Default::default(),
            },
            vec![(H256([1; 32]), vec![0, 1, 2, 3, 4])],
        );

        let serialized = <TeeVerifierInput as StoredObject>::serialize(&tvi)
            .expect("Failed to serialize TeeVerifierInput.");
        let deserialized: TeeVerifierInput =
            <TeeVerifierInput as StoredObject>::deserialize(serialized)
                .expect("Failed to deserialize TeeVerifierInput.");

        assert_eq!(tvi, deserialized);
    }

    #[test]
    fn test_v1_bincode_snapshot() {
        let tst_tvi_json = r#"
            {
                "V1": {
                    "prepare_basic_circuits_job": {
                        "merkle_paths": [
                            {
                                "root_hash": [
                                    199, 231, 138, 237, 215, 168, 130, 194, 198, 6, 187, 237, 77, 26, 152, 210,
                                    88, 244, 103, 217, 198, 89, 54, 183, 3, 48, 12, 198, 157, 109, 17, 108
                                ],
                                "is_write": false,
                                "first_write": false,
                                "merkle_paths": [
                                    [
                                        14, 61, 115, 101, 43, 176, 68, 16, 107, 44, 117, 212, 243, 107, 174, 139,
                                        221, 199, 237, 48, 120, 145, 101, 195, 53, 184, 23, 176, 118, 216, 58, 141
                                    ]
                                ],
                                "leaf_hashed_key": "0xa792adc37510103905c79c23e63fc13938000f8acb1120dd8cc76d6f13a11577",
                                "leaf_enumeration_index": 2,
                                "value_written": [
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                                ],
                                "value_read": [
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                                ]
                            }
                        ],
                        "next_enumeration_index": 23577
                    },
                    "l2_blocks_execution_data": [
                        {
                            "number": 91,
                            "timestamp": 1715693104,
                            "prev_block_hash": "0x1ef787bfb1908c8a55d972375af69b74038bfb999cc4f46d5be582d945a3b2be",
                            "virtual_blocks": 1,
                            "txs": [
                                {
                                    "common_data": {
                                        "L1": {
                                            "sender": "0x62b13dd4f940b691a015d1b1e29cecd3cfec5d77",
                                            "serialId": 208,
                                            "deadlineBlock": 0,
                                            "layer2TipFee": "0x0",
                                            "fullFee": "0x0",
                                            "maxFeePerGas": "0x10642ac0",
                                            "gasLimit": "0x4c4b40",
                                            "gasPerPubdataLimit": "0x320",
                                            "opProcessingType": "Common",
                                            "priorityQueueType": "Deque",
                                            "ethHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                                            "ethBlock": 1727,
                                            "canonicalTxHash": "0x8f53c4d042e7931cbe43889f7992a86cd9d24db76ac0ff2dc4ceb55250059a92",
                                            "toMint": "0x4e28e2290f000",
                                            "refundRecipient": "0x62b13dd4f940b691a015d1b1e29cecd3cfec5d77"
                                        }
                                    },
                                    "execute": {
                                        "contractAddress": "0x350822d8850e1ce8894e4bb86ed7243baaa747fc",
                                        "calldata": "0xd542b16c000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001",
                                        "value": "0x0",
                                        "factoryDeps": [ [ 0 ] ]
                                    },
                                    "received_timestamp_ms": 1715693103904,
                                    "raw_bytes": null
                                }
                            ]
                        },
                        {
                            "number": 95,
                            "timestamp": 1715693108,
                            "prev_block_hash": "0x3ca40be0a54a377be77bd6ad87e376ae7ddb25090d2d32382e3c94759d1fc76d",
                            "virtual_blocks": 1,
                            "txs": []
                        }
                    ],
                    "l1_batch_env": {
                        "previous_batch_hash": "0xc7e78aedd7a882c2c606bbed4d1a98d258f467d9c65936b703300cc69d6d116c",
                        "number": 20,
                        "timestamp": 1715693104,
                        "fee_input": {
                            "PubdataIndependent": {
                                "fair_l2_gas_price": 100000000,
                                "fair_pubdata_price": 13600000000,
                                "l1_gas_price": 800000000
                            }
                        },
                        "fee_account": "0xde03a0b5963f75f1c8485b355ff6d30f3093bde7",
                        "enforced_base_fee": null,
                        "first_l2_block": {
                            "number": 91,
                            "timestamp": 1715693104,
                            "prev_block_hash": "0x1ef787bfb1908c8a55d972375af69b74038bfb999cc4f46d5be582d945a3b2be",
                            "max_virtual_blocks_to_create": 1
                        }
                    },
                    "system_env": {
                        "zk_porter_available": false,
                        "version": "Version24",
                        "base_system_smart_contracts": {
                            "bootloader": {
                                "code": [
                                    "0x2000000000002001c00000000000200000000030100190000006003300270"
                                ],
                                "hash": "0x010008e742608b21bf7eb23c1a9d0602047e3618b464c9b59c0fba3b3d7ab66e"
                            },
                            "default_aa": {
                                "code": [
                                    "0x4000000610355000500000061035500060000006103550007000000610355"
                                ],
                                "hash": "0x01000563374c277a2c1e34659a2a1e87371bb6d852ce142022d497bfb50b9e32"
                            }
                        },
                        "bootloader_gas_limit": 4294967295,
                        "execution_mode": "VerifyExecute",
                        "default_validation_computational_gas_limit": 4294967295,
                        "chain_id": 270
                    },
                    "used_contracts": [
                        [
                            "0x010001211b0c33353cdf7a320f768e3dc40bce1326d639fcac099bba9ecd8e34",
                            [ 0, 4, 0, 0 ]
                        ]
                    ]
                }
            }
        "#;

        let tvi_bin = vec![
            1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 199, 231, 138, 237, 215,
            168, 130, 194, 198, 6, 187, 237, 77, 26, 152, 210, 88, 244, 103, 217, 198, 89, 54, 183,
            3, 48, 12, 198, 157, 109, 17, 108, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0,
            0, 14, 61, 115, 101, 43, 176, 68, 16, 107, 44, 117, 212, 243, 107, 174, 139, 221, 199,
            237, 48, 120, 145, 101, 195, 53, 184, 23, 176, 118, 216, 58, 141, 66, 0, 0, 0, 0, 0, 0,
            0, 48, 120, 97, 55, 57, 50, 97, 100, 99, 51, 55, 53, 49, 48, 49, 48, 51, 57, 48, 53,
            99, 55, 57, 99, 50, 51, 101, 54, 51, 102, 99, 49, 51, 57, 51, 56, 48, 48, 48, 102, 56,
            97, 99, 98, 49, 49, 50, 48, 100, 100, 56, 99, 99, 55, 54, 100, 54, 102, 49, 51, 97, 49,
            49, 53, 55, 55, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 92, 0, 0, 0, 0, 0, 0, 2,
            0, 0, 0, 0, 0, 0, 0, 91, 0, 0, 0, 48, 102, 67, 102, 0, 0, 0, 0, 66, 0, 0, 0, 0, 0, 0,
            0, 48, 120, 49, 101, 102, 55, 56, 55, 98, 102, 98, 49, 57, 48, 56, 99, 56, 97, 53, 53,
            100, 57, 55, 50, 51, 55, 53, 97, 102, 54, 57, 98, 55, 52, 48, 51, 56, 98, 102, 98, 57,
            57, 57, 99, 99, 52, 102, 52, 54, 100, 53, 98, 101, 53, 56, 50, 100, 57, 52, 53, 97, 51,
            98, 50, 98, 101, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0,
            0, 48, 120, 54, 50, 98, 49, 51, 100, 100, 52, 102, 57, 52, 48, 98, 54, 57, 49, 97, 48,
            49, 53, 100, 49, 98, 49, 101, 50, 57, 99, 101, 99, 100, 51, 99, 102, 101, 99, 53, 100,
            55, 55, 208, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 48,
            120, 48, 3, 0, 0, 0, 0, 0, 0, 0, 48, 120, 48, 10, 0, 0, 0, 0, 0, 0, 0, 48, 120, 49, 48,
            54, 52, 50, 97, 99, 48, 8, 0, 0, 0, 0, 0, 0, 0, 48, 120, 52, 99, 52, 98, 52, 48, 5, 0,
            0, 0, 0, 0, 0, 0, 48, 120, 51, 50, 48, 0, 0, 0, 0, 0, 0, 0, 0, 66, 0, 0, 0, 0, 0, 0, 0,
            48, 120, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 191, 6, 0, 0, 0, 0, 0, 0, 66, 0, 0, 0, 0, 0, 0, 0, 48, 120, 56, 102, 53, 51, 99,
            52, 100, 48, 52, 50, 101, 55, 57, 51, 49, 99, 98, 101, 52, 51, 56, 56, 57, 102, 55, 57,
            57, 50, 97, 56, 54, 99, 100, 57, 100, 50, 52, 100, 98, 55, 54, 97, 99, 48, 102, 102,
            50, 100, 99, 52, 99, 101, 98, 53, 53, 50, 53, 48, 48, 53, 57, 97, 57, 50, 15, 0, 0, 0,
            0, 0, 0, 0, 48, 120, 52, 101, 50, 56, 101, 50, 50, 57, 48, 102, 48, 48, 48, 42, 0, 0,
            0, 0, 0, 0, 0, 48, 120, 54, 50, 98, 49, 51, 100, 100, 52, 102, 57, 52, 48, 98, 54, 57,
            49, 97, 48, 49, 53, 100, 49, 98, 49, 101, 50, 57, 99, 101, 99, 100, 51, 99, 102, 101,
            99, 53, 100, 55, 55, 42, 0, 0, 0, 0, 0, 0, 0, 48, 120, 51, 53, 48, 56, 50, 50, 100, 56,
            56, 53, 48, 101, 49, 99, 101, 56, 56, 57, 52, 101, 52, 98, 98, 56, 54, 101, 100, 55,
            50, 52, 51, 98, 97, 97, 97, 55, 52, 55, 102, 99, 196, 0, 0, 0, 0, 0, 0, 0, 213, 66,
            177, 108, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 0, 0, 0, 0, 0, 0, 0,
            48, 120, 48, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 32, 43, 71, 119,
            143, 1, 0, 0, 0, 95, 0, 0, 0, 52, 102, 67, 102, 0, 0, 0, 0, 66, 0, 0, 0, 0, 0, 0, 0,
            48, 120, 51, 99, 97, 52, 48, 98, 101, 48, 97, 53, 52, 97, 51, 55, 55, 98, 101, 55, 55,
            98, 100, 54, 97, 100, 56, 55, 101, 51, 55, 54, 97, 101, 55, 100, 100, 98, 50, 53, 48,
            57, 48, 100, 50, 100, 51, 50, 51, 56, 50, 101, 51, 99, 57, 52, 55, 53, 57, 100, 49,
            102, 99, 55, 54, 100, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 66, 0, 0, 0, 0, 0, 0, 0,
            48, 120, 99, 55, 101, 55, 56, 97, 101, 100, 100, 55, 97, 56, 56, 50, 99, 50, 99, 54,
            48, 54, 98, 98, 101, 100, 52, 100, 49, 97, 57, 56, 100, 50, 53, 56, 102, 52, 54, 55,
            100, 57, 99, 54, 53, 57, 51, 54, 98, 55, 48, 51, 51, 48, 48, 99, 99, 54, 57, 100, 54,
            100, 49, 49, 54, 99, 20, 0, 0, 0, 48, 102, 67, 102, 0, 0, 0, 0, 1, 0, 0, 0, 0, 225,
            245, 5, 0, 0, 0, 0, 0, 136, 159, 42, 3, 0, 0, 0, 0, 8, 175, 47, 0, 0, 0, 0, 42, 0, 0,
            0, 0, 0, 0, 0, 48, 120, 100, 101, 48, 51, 97, 48, 98, 53, 57, 54, 51, 102, 55, 53, 102,
            49, 99, 56, 52, 56, 53, 98, 51, 53, 53, 102, 102, 54, 100, 51, 48, 102, 51, 48, 57, 51,
            98, 100, 101, 55, 0, 91, 0, 0, 0, 48, 102, 67, 102, 0, 0, 0, 0, 66, 0, 0, 0, 0, 0, 0,
            0, 48, 120, 49, 101, 102, 55, 56, 55, 98, 102, 98, 49, 57, 48, 56, 99, 56, 97, 53, 53,
            100, 57, 55, 50, 51, 55, 53, 97, 102, 54, 57, 98, 55, 52, 48, 51, 56, 98, 102, 98, 57,
            57, 57, 99, 99, 52, 102, 52, 54, 100, 53, 98, 101, 53, 56, 50, 100, 57, 52, 53, 97, 51,
            98, 50, 98, 101, 1, 0, 0, 0, 0, 24, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 63, 0, 0, 0, 0, 0,
            0, 0, 48, 120, 50, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 50, 48, 48, 49, 99, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 50, 48, 48, 48, 48, 48, 48, 48, 48, 48, 51, 48,
            49, 48, 48, 49, 57, 48, 48, 48, 48, 48, 48, 54, 48, 48, 51, 51, 48, 48, 50, 55, 48, 66,
            0, 0, 0, 0, 0, 0, 0, 48, 120, 48, 49, 48, 48, 48, 56, 101, 55, 52, 50, 54, 48, 56, 98,
            50, 49, 98, 102, 55, 101, 98, 50, 51, 99, 49, 97, 57, 100, 48, 54, 48, 50, 48, 52, 55,
            101, 51, 54, 49, 56, 98, 52, 54, 52, 99, 57, 98, 53, 57, 99, 48, 102, 98, 97, 51, 98,
            51, 100, 55, 97, 98, 54, 54, 101, 1, 0, 0, 0, 0, 0, 0, 0, 63, 0, 0, 0, 0, 0, 0, 0, 48,
            120, 52, 48, 48, 48, 48, 48, 48, 54, 49, 48, 51, 53, 53, 48, 48, 48, 53, 48, 48, 48,
            48, 48, 48, 54, 49, 48, 51, 53, 53, 48, 48, 48, 54, 48, 48, 48, 48, 48, 48, 54, 49, 48,
            51, 53, 53, 48, 48, 48, 55, 48, 48, 48, 48, 48, 48, 54, 49, 48, 51, 53, 53, 66, 0, 0,
            0, 0, 0, 0, 0, 48, 120, 48, 49, 48, 48, 48, 53, 54, 51, 51, 55, 52, 99, 50, 55, 55, 97,
            50, 99, 49, 101, 51, 52, 54, 53, 57, 97, 50, 97, 49, 101, 56, 55, 51, 55, 49, 98, 98,
            54, 100, 56, 53, 50, 99, 101, 49, 52, 50, 48, 50, 50, 100, 52, 57, 55, 98, 102, 98, 53,
            48, 98, 57, 101, 51, 50, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 14, 1, 0,
            0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 66, 0, 0, 0, 0, 0, 0, 0, 48, 120, 48, 49, 48,
            48, 48, 49, 50, 49, 49, 98, 48, 99, 51, 51, 51, 53, 51, 99, 100, 102, 55, 97, 51, 50,
            48, 102, 55, 54, 56, 101, 51, 100, 99, 52, 48, 98, 99, 101, 49, 51, 50, 54, 100, 54,
            51, 57, 102, 99, 97, 99, 48, 57, 57, 98, 98, 97, 57, 101, 99, 100, 56, 101, 51, 52, 4,
            0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0,
        ];

        let tvi: TeeVerifierInput = serde_json::from_str(tst_tvi_json).unwrap();
        let bin = bincode::serialize(&tvi).unwrap();
        assert_eq!(tvi_bin, bin);
        let deser: TeeVerifierInput = bincode::deserialize(&bin).unwrap();
        assert_eq!(tvi, deser);
    }
}

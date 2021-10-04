use ring::digest::{digest, SHA256};
use super::hash::{Hashable, H256};

/// A Merkle tree.
#[derive(Debug, Default, Clone)]
struct MerkleTreeNode {
    left: Option<Box<MerkleTreeNode>>,
    right: Option<Box<MerkleTreeNode>>,
    hash: H256,
}

/// A Merkle tree.
#[derive(Debug, Default)]
pub struct MerkleTree {
    root: MerkleTreeNode,
    level_count: usize, // how many levels the tree has
}

/// Given the hash of the left and right nodes, compute the hash of the parent node.
fn hash_children(left: &H256, right: &H256) -> H256 {
    return digest(&SHA256, &([left.as_ref(), right.as_ref()].concat())).into();
}

/// Duplicate the last node in `nodes` to make its length even.
fn duplicate_last_node(nodes: &mut Vec<Option<MerkleTreeNode>>) {
    nodes.push(nodes[nodes.len() - 1].clone());
}

impl MerkleTree {
    pub fn new<T>(data: &[T]) -> Self where T: Hashable, {
        assert!(!data.is_empty());

        // create the leaf nodes:
        let mut curr_level: Vec<Option<MerkleTreeNode>> = Vec::new();
        for item in data {
            curr_level.push(Some(MerkleTreeNode {
                hash: item.hash(),
                left: None,
                right: None,
            }));
        }
        let mut level_count = 1;
        // create the upper levels of the tree:
        while curr_level.len() > 1 {
            // Whenever a level of the tree has odd number of nodes, duplicate the last node to make the number even:
            if curr_level.len() % 2 == 1 {
                duplicate_last_node(&mut curr_level);
            }
            assert_eq!(curr_level.len() % 2, 0); // make sure we now have even number of nodes.

            let mut next_level: Vec<Option<MerkleTreeNode>> = Vec::new();
            for i in 0..curr_level.len() / 2 {
                let left = curr_level[i * 2].take().unwrap();
                let right = curr_level[i * 2 + 1].take().unwrap();
                let hash = hash_children(&left.hash, &right.hash);
                next_level.push(Some(MerkleTreeNode {
                    hash,
                    left: Some(Box::new(left)),
                    right: Some(Box::new(right)),
                }));
            }
            curr_level = next_level;
            level_count += 1;
        }
        MerkleTree {
            root: curr_level[0].take().unwrap(),
            level_count,
        }
    }

    pub fn root(&self) -> H256 {
        return self.root.hash;
    }

    /// Returns the Merkle Proof of data at index i
    pub fn proof(&self, index: usize) -> Vec<H256> {
        let mut current_index = index.clone() as usize;
        let mut proof_vector: Vec<H256> = Vec::new();
        let mut leaf_size = 2_i32.pow((self.level_count - 1) as u32) as usize;
        let mut current_node = self.root.clone();
        while leaf_size > 1 {
            if current_index < (leaf_size / 2) {
                // Left subtree
                proof_vector.push(current_node.right.unwrap().hash);
                current_node = *current_node.left.unwrap();
            } else {
                // Right subtree
                proof_vector.push(current_node.left.unwrap().hash);
                current_node = *current_node.right.unwrap();
            }
            leaf_size /= 2;
            if current_index >= leaf_size {
                current_index -= leaf_size;
            }
        }
        proof_vector.reverse();
        return proof_vector;
    }
}


/// Verify that the datum hash with a vector of proofs will produce the Merkle root. Also need the
/// index of datum and `leaf_size`, the total number of leaves.
pub fn verify(root: &H256, datum: &H256, proof: &[H256], index: usize, leaf_size: usize) -> bool {
    // Check length of proof
    if proof.len() != (leaf_size as f64).log(2.0).ceil() as usize {
        return false;
    }
    // Check if index is valid
    if index >= leaf_size {
        return false;
    }
    let mut current_index = index.clone();
    let mut current_node = datum.clone();
    let mut remaining_proof = 0;
    while remaining_proof < proof.len() {
        if current_index % 2 == 0 {
            current_node = digest(&SHA256, &([current_node.as_ref(), proof[remaining_proof].as_ref
            ()].concat())).into()
        } else {
            current_node = digest(&SHA256, &([proof[remaining_proof].as_ref(), current_node.as_ref
            ()].concat())).into()
        }
        current_index /= 2;
        remaining_proof += 1;
    }
    println!("Calculated root Hash value is {}", current_node.hash());
    println!("Expected root Hash value is {}", root.hash());
    return current_node.hash() == root.hash();
}

#[cfg(test)]
mod tests {
    use crate::crypto::hash::H256;
    use super::*;

    macro_rules! gen_merkle_tree_data {
        () => {{
            vec![
                (hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d")).into(),
                (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            ]
        }};
    }

    #[test]
    fn root() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let root = merkle_tree.root();
        assert_eq!(
            root,
            (hex!("6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920")).into()
        );
        // "b69566be6e1720872f73651d1851a0eae0060a132cf0f64a0ffaea248de6cba0" is the hash of
        // "0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d"
        // "965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f" is the hash of
        // "0101010101010101010101010101010101010101010101010101010101010202"
        // "6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920" is the hash of
        // the concatenation of these two hashes "b69..." and "965..."
        // notice that the order of these two matters
    }

    #[test]
    fn proof() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert_eq!(proof,
                   vec![hex!("965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f").into()]
        );
        // "965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f" is the hash of
        // "0101010101010101010101010101010101010101010101010101010101010202"
    }

    #[test]
    fn verifying() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert!(verify(&merkle_tree.root(), &input_data[0].hash(), &proof, 0, input_data.len()));
    }
}

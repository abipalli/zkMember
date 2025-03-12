use ark_crypto_primitives::{Path, CRH};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dialoguer::{theme::ColorfulTheme, Select};
use zkmember::{
    ed_on_bls12_381::{
        circuit::MerkleTreeCircuit,
        common::{LeafHash, TwoToOneHash},
    },
    member::Member,
    membership::{new_membership_tree, MerkleConfig, Root},
};

fn main() {
    let mut members: Box<Vec<Member>> = Box::new(Vec::<Member>::new());

    let mut rng = ark_std::test_rng();

    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as CRH>::setup(&mut rng).unwrap();

    // public store
    let mut root: Option<Root>;

    loop {
        let options = &[
            "Register a new member",
            "Generate a proof for a member",
            "Verify proof",
            "Exit",
        ];
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose an option")
            .default(0)
            .items(&options[..])
            .interact()
            .unwrap();

        match selection {
            0 => {
                let id = dialoguer::Input::<String>::new()
                    .with_prompt("Enter ID")
                    .allow_empty(false)
                    .interact_text()
                    .unwrap();
                let email = dialoguer::Input::<String>::new()
                    .with_prompt("Enter Email")
                    .allow_empty(false)
                    .interact_text()
                    .unwrap();
                members.push(Member::new(id.into(), email.into(), None));
                println!("\x1b[0;32mNumber of Members: {}\x1b[0m", members.len());

                let tree = new_membership_tree(&leaf_crh_params, &two_to_one_crh_params, &members);
                root = Some(tree.root());

                let mut root_serialization = Vec::new();
                root.serialize(&mut root_serialization).unwrap();
                println!("root: {}", hex::encode(root_serialization));
            }
            1 => {
                let id = dialoguer::Input::<String>::new()
                    .with_prompt("Enter ID")
                    .interact_text()
                    .unwrap();

                if let Some(index) = members.iter().position(|member| member.id == id) {
                    let tree =
                        new_membership_tree(&leaf_crh_params, &two_to_one_crh_params, &members);

                    let root = tree.root();
                    let proof = tree.generate_proof(index).unwrap();

                    let circuit = MerkleTreeCircuit {
                        leaf_crh_params: &leaf_crh_params,
                        two_to_one_crh_params: &two_to_one_crh_params,
                        root,
                        leaf: members.get(index).unwrap(),
                        authentication_path: Some(proof.clone()),
                    };
                    let cs = ConstraintSystem::new_ref();
                    circuit.generate_constraints(cs.clone()).unwrap();

                    assert!(cs.is_satisfied().unwrap());

                    let mut root_serialization = Vec::new();
                    root.serialize(&mut root_serialization).unwrap();
                    println!("root: {}", hex::encode(root_serialization));

                    let mut compressed_path = Vec::new();
                    proof.serialize(&mut compressed_path).unwrap();
                    println!("path: {}", hex::encode(compressed_path));
                } else {
                    println!("\x1b[0;31mMember not found\x1b[0m");
                }
            }
            2 => {
                let member_id = dialoguer::Input::<String>::new()
                    .with_prompt("Enter member id")
                    .interact_text()
                    .unwrap();

                if let Some(index) = members.iter().position(|m| m.id == member_id) {
                    let root_hex = dialoguer::Input::<String>::new()
                        .with_prompt("Enter root (hex)")
                        .interact_text()
                        .unwrap();

                    let path_hex = dialoguer::Input::<String>::new()
                        .with_prompt("Enter path (hex)")
                        .interact_text()
                        .unwrap();

                    match (hex::decode(&root_hex), hex::decode(&path_hex)) {
                        (Ok(root_bytes), Ok(path_bytes)) => {
                            match (
                                Root::deserialize(&*root_bytes),
                                Path::<MerkleConfig>::deserialize(&*path_bytes),
                            ) {
                                (Ok(root), Ok(proof)) => {
                                    let circuit = MerkleTreeCircuit {
                                        leaf_crh_params: &leaf_crh_params,
                                        two_to_one_crh_params: &two_to_one_crh_params,
                                        root,
                                        leaf: members.get(index).unwrap(),
                                        authentication_path: Some(proof),
                                    };

                                    let cs = ConstraintSystem::new_ref();
                                    match circuit.generate_constraints(cs.clone()) {
                                Ok(_) => {
                                    match cs.is_satisfied() {
                                        Ok(true) => println!("\x1b[0;32mProof verification successful!\x1b[0m"),
                                        Ok(false) => println!("\x1b[0;31mProof verification failed: constraints not satisfied\x1b[0m"),
                                        Err(e) => println!("\x1b[0;31mError checking constraints: {}\x1b[0m", e),
                                    }
                                },
                                Err(e) => println!("\x1b[0;31mError generating constraints: {}\x1b[0m", e),
                                }
                                }
                                _ => {
                                    println!("\x1b[0;31mFailed to deserialize root or proof\x1b[0m")
                                }
                            }
                        }
                        _ => println!("\x1b[0;31mInvalid hex encoding\x1b[0m"),
                    }
                } else {
                    println!("\x1b[0;31mUnable to identify member\x1b[0m")
                }
            }
            _ => unreachable!(),
        }
        println!()
    }
}

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::CRH;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use dialoguer::{theme::ColorfulTheme, Select};
use zkmember::{
    member::Member,
    pedersen381::{
        common::{new_membership_tree, LeafHash, Pedersen381Field, Root, TwoToOneHash},
        constraint::MerkleTreeCircuit,
    },
};

fn main() {
    let mut members: Box<Vec<Member>> = Box::new(Vec::<Member>::new());
    let mut _last_circuit: Option<MerkleTreeCircuit>;

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
                    let path = tree.generate_proof(index).unwrap();
                    let member = members.get(index).unwrap();

                    let circuit = MerkleTreeCircuit {
                        leaf_crh_params: &leaf_crh_params,
                        two_to_one_crh_params: &two_to_one_crh_params,
                        root,
                        leaf: &member,
                        authentication_path: Some(path),
                    };

                    // let (pk, vk) = Groth16::<Bls12_381>::setup(circuit.clone(), &mut rng).unwrap();
                    let (pk, vk) =
                        Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng)
                            .unwrap();
                    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).unwrap();

                    let mut proof_serialization = Vec::new();
                    proof.serialize(&mut proof_serialization).unwrap();
                    println!("Generated proof: {}", hex::encode(&proof_serialization));

                    let mut vk_serialization = Vec::new();
                    vk.serialize(&mut vk_serialization).unwrap();
                    println!("Verification key: {}", hex::encode(&vk_serialization));

                    // Construct public input vector properly
                    let mut public_input = vec![root];
                    public_input
                        .extend(member.to_bytes().iter().map(|b| Pedersen381Field::from(*b)));

                    // Verify the proof with proper error handling
                    match Groth16::<Bls12_381>::verify(&vk, &public_input, &proof) {
                        Ok(true) => println!("\x1b[0;32mProof verified successfully!\x1b[0m"),
                        Ok(false) => println!("\x1b[0;31mProof verification failed\x1b[0m"),
                        Err(e) => println!("\x1b[0;31mVerification error: {:?}\x1b[0m", e),
                    }
                } else {
                    println!("\x1b[0;31mMember not found\x1b[0m");
                }
            }
            2 => {
                let member_hex = dialoguer::Input::<String>::new()
                    .with_prompt("Enter member (hex)")
                    .interact_text()
                    .unwrap();

                let root_hex = dialoguer::Input::<String>::new()
                    .with_prompt("Enter root (hex)")
                    .interact_text()
                    .unwrap();

                // let path_hex = dialoguer::Input::<String>::new()
                //     .with_prompt("Enter path (hex)")
                //     .interact_text()
                //     .unwrap();

                match (
                    hex::decode(&member_hex),
                    hex::decode(&root_hex),
                    // hex::decode(&path_hex),
                ) {
                    (Ok(member_bytes), Ok(root_bytes) /*, Ok(path_bytes)*/) => {
                        match (
                            serde_json::from_slice(member_bytes.as_slice()),
                            Root::deserialize(&*root_bytes),
                            // Path::<MerkleConfig>::deserialize(&*path_bytes),
                        ) {
                            (Ok(member), Ok(root) /*, Ok(proof)*/) => {
                                let circuit = MerkleTreeCircuit {
                                    leaf_crh_params: &leaf_crh_params,
                                    two_to_one_crh_params: &two_to_one_crh_params,
                                    root,
                                    leaf: &member,
                                    authentication_path: None,
                                    // authentication_path: Some(proof),
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
                                println!(
                                    "\x1b[0;31mFailed to deserialize member, root or proof\x1b[0m"
                                )
                            }
                        }
                    }
                    _ => println!("\x1b[0;31mInvalid hex encoding\x1b[0m"),
                }
            }
            3 => std::process::exit(0),
            _ => unreachable!(),
        }
        println!()
    }
}

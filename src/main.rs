use ark_crypto_primitives::CRH;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use dialoguer::{theme::ColorfulTheme, Select};
use zkmember::{
    ed_on_bls12_381::{
        circuit::MerkleTreeCircuit,
        common::{LeafHash, TwoToOneHash},
    },
    member::Member,
    membership::{new_membership_tree, Root},
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
            2 => break,
            _ => unreachable!(),
        }
        println!()
    }
}

use ark_crypto_primitives::CRH;
use chrono::{DateTime, Utc};
use serde::ser::SerializeStruct;

#[derive(Clone)]
pub struct Member {
    // private fields
    pub id: String,
    email: String,
    join_date: DateTime<Utc>,
    end_date: Option<DateTime<Utc>>,
    padding: Option<Vec<u8>>,
}

use ark_std::io::{Result as IoResult, Write};

impl ark_ff::bytes::ToBytes for Member {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        Ok((writer.write_all(&self.to_bytes()))?)
    }
}

impl Default for Member {
    fn default() -> Self {
        Member {
            id: "".to_string(),
            email: "".to_string(),
            join_date: chrono::offset::Utc::now(),
            end_date: None,
            padding: None,
        }
    }
}

impl Member {
    pub fn new(id: String, email: String, end_date: Option<DateTime<Utc>>) -> Self {
        Self {
            id,
            email,
            join_date: chrono::offset::Utc::now(),
            end_date,
            padding: None,
        }
    }

    pub fn new_with_padding(
        id: String,
        email: String,
        end_date: Option<DateTime<Utc>>,
        pad: usize,
    ) -> Self {
        Self {
            id,
            email,
            join_date: chrono::offset::Utc::now(),
            end_date,
            padding: Some(vec![0; pad]),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();

        bytes.extend_from_slice(self.id.as_bytes());
        bytes.extend_from_slice(self.email.as_bytes());
        bytes.extend_from_slice(&self.join_date.timestamp().to_be_bytes());

        if let Some(end_date) = self.end_date {
            bytes.extend_from_slice(&[1_u8]);
            bytes.extend_from_slice(&end_date.timestamp().to_be_bytes());
        } else {
            bytes.extend_from_slice(&[0_u8]);
        }

        if let Some(padding) = &self.padding {
            bytes.extend_from_slice(&[1_u8]);
            bytes.extend_from_slice(&padding); // does this work???
        } else {
            bytes.extend_from_slice(&[0_u8]);
        }

        bytes
    }

    pub fn hash<H: CRH>(&self, params: &H::Parameters) -> H::Output {
        H::evaluate(params, &self.to_bytes()).unwrap()
    }
}

impl serde::Serialize for Member {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Member", 4)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("email", &self.email)?;
        state.serialize_field("join_date", &self.join_date.to_rfc3339())?;
        state.serialize_field("end_date", &self.end_date.map(|d| d.to_rfc3339()))?;
        state.serialize_field(
            "padding",
            &"0".repeat(self.padding.as_ref().map_or(0, |vec| vec.len())),
        )?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for Member {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct MemberData {
            id: String,
            email: String,
            join_date: String,
            end_date: Option<String>,
            padding: Option<String>,
        }

        let data = MemberData::deserialize(deserializer)?;
        let join_date = DateTime::parse_from_rfc3339(&data.join_date)
            .map_err(serde::de::Error::custom)?
            .with_timezone(&Utc);
        let end_date = match data.end_date {
            Some(date) => Some(
                DateTime::parse_from_rfc3339(&date)
                    .map_err(serde::de::Error::custom)?
                    .with_timezone(&Utc),
            ),
            _ => None,
        };

        let padding = match data.padding {
            Some(pad) => Some(
                vec![0; pad.len()], // why does Vec<u8>! not work
            ),
            _ => None,
        }; // padding deserialized

        Ok(Member {
            id: data.id,
            email: data.email,
            join_date,
            end_date,
            padding,
        })
    }
}

pub fn generate_members(members: &mut Box<Vec<Member>>, amount: u32) {
    for i in 1..amount + 1 {
        let id = format!("{}", i);
        let email = format!("{}@usc.edu", i);
        members.push(Member::new(id, email, None));
    }
    println!("\x1b[0;34mNumber of Members: {}\x1b[0m", members.len());
    println!("\x1b[0;90mNumber of Padded Members: {}\x1b[0m", amount);
}
pub fn generate_members_with_padding(members: &mut Box<Vec<Member>>, amount: u32, padding: usize) {
    for i in 1..amount + 1 {
        let id = format!("{}", i);
        let email = format!("{}@usc.edu", i);
        members.push(Member::new_with_padding(id, email, None, padding));
    }
    println!("\x1b[0;32mNumber of Members: {}\x1b[0m", members.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialization() {
        let member = Member::default();
        let bytes = member.to_bytes();
        println!("Member serialized to {} bytes: {:?}", bytes.len(), bytes);

        // Verify that serialization includes all fields
        assert!(bytes.len() > member.id.len() + member.email.len());
    }

    #[test]
    fn test_serde_serialization() {
        let member = Member::default();
        let serialized = serde_json::to_string(&member).expect("Failed to serialize Member");
        println!("Serialized Member: {}", serialized);

        // Verify that the serialized JSON contains the expected fields
        assert!(serialized.contains(&member.id));
        assert!(serialized.contains(&member.email));
        assert!(serialized.contains(&member.join_date.to_rfc3339()));
    }

    #[test]
    fn test_serde_deserialization() {
        let json_data = r#"
        {
            "id": "987654321",
            "email": "test@usc.edu",
            "join_date": "2023-01-01T00:00:00Z",
            "end_date": "2023-12-31T23:59:59Z"
        }
        "#;

        let member: Member = serde_json::from_str(json_data).expect("Failed to deserialize Member");
        assert_eq!(member.id, "987654321");
        assert_eq!(member.email, "test@usc.edu");
        assert_eq!(
            member.join_date,
            DateTime::parse_from_rfc3339("2023-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(
            member.end_date,
            Some(
                DateTime::parse_from_rfc3339("2023-12-31T23:59:59Z")
                    .unwrap()
                    .with_timezone(&Utc)
            )
        );
    }

    #[test]
    fn test_serde_round_trip() {
        let member = Member::new(
            "123456789".to_string(),
            "roundtrip@usc.edu".to_string(),
            Some(
                DateTime::parse_from_rfc3339("2023-12-31T23:59:59Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
        );

        let serialized = serde_json::to_string(&member).expect("Failed to serialize Member");
        let deserialized: Member =
            serde_json::from_str(&serialized).expect("Failed to deserialize Member");

        assert_eq!(member.id, deserialized.id);
        assert_eq!(member.email, deserialized.email);
        assert_eq!(member.join_date, deserialized.join_date);
        assert_eq!(member.end_date, deserialized.end_date);
    }
}

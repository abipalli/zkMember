use chrono::{DateTime, Utc};

#[derive(Clone)]
pub struct Member {
    // private fields
    pub id: String,
    email: String,
    join_date: DateTime<Utc>,
    end_date: Option<DateTime<Utc>>,
    padding: Option<Vec::<u8>>,
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
        state.serialize_field("padding", &"0".repeat(self.padding.as_ref().map_or(0, |vec| vec.len()))); // serialized padding
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
                vec![0;pad.len()], // why does Vec<u8>! not work
            ),
            _ => None,
        }; // padding deserialized

        Ok(Member {
            id: data.id,
            email: data.email,
            join_date,
            end_date,
            padding
        })
    }
}

use ark_std::io::{Result as IoResult, Write};
use serde::ser::SerializeStruct;

impl ark_ff::bytes::ToBytes for Member {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        Ok((writer.write_all(&self.to_bytes()))?)
    }
}

impl Default for Member {
    fn default() -> Self {
        Member {
            id: "123456789".to_string(),
            email: "example@usc.edu".to_string(),
            join_date: chrono::offset::Utc::now(),
            end_date: None,
            padding: None,
        }
    }
}

impl Member {
    /// Create a new member
    
    pub fn new(id: String, email: String, end_date: Option<DateTime<Utc>>) -> Self {
        Self {
            id,
            email,
            join_date: chrono::offset::Utc::now(),
            end_date,
            padding: None
        }
    }

    pub fn with_padding(id: String, email: String, end_date: Option<DateTime<Utc>>, pad: usize) -> Self {
        Self {
            id,
            email,
            join_date: chrono::offset::Utc::now(),
            end_date,
            padding: Some(vec![0;pad])
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
        }
        else{
            bytes.extend_from_slice(&[0_u8]);
        }

        bytes
    }
}

pub fn generate_members(members: &mut Box<Vec<Member>>, amount: u32){
    for i in 0..amount{
        let id = i.to_string();
        let email = id.clone();
        members.push(Member::new(id, email, None));
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
}

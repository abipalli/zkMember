use chrono::{DateTime, Utc};

#[derive(Clone)]
pub(crate) struct Member<'a> {
    // private fields
    id: &'a str,
    email: &'a str,
    join_date: DateTime<Utc>,
    end_date: Option<DateTime<Utc>>,
}

use ark_std::io::{Result as IoResult, Write};

impl<'a> ark_ff::bytes::ToBytes for Member<'a> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        Ok((writer.write_all(&self.to_bytes()))?)
    }
}

impl<'a> Default for Member<'a> {
    fn default() -> Self {
        Member {
            id: "123456789",
            email: "example@usc.edu",
            join_date: chrono::offset::Utc::now(),
            end_date: None,
        }
    }
}

impl<'a> Member<'a> {
    /// Create a new member
    pub fn new(id: &'a str, email: &'a str, end_date: Option<DateTime<Utc>>) -> Self {
        Self {
            id,
            email,
            join_date: chrono::offset::Utc::now(),
            end_date,
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

        bytes
    }
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

use chrono::{self, DateTime, Utc};

pub(crate) struct Member<'a> {
    // private
    id: &'a str,
    email: &'a str,
    join_date: DateTime<Utc>,
    end_date: Option<DateTime<Utc>>,
    // public field will only be the generated proof of membership
}

impl<'a> Member<'a> {
    fn to_bytes(self) -> Vec<u8> {
        [
            self.id.as_bytes(),
            self.email.as_bytes(),
            &self.join_date.timestamp().to_be_bytes(),
        ]
        .concat()
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

#[test]
pub fn test_serialization() {
    let member = Member::default();
    println!("{:#?}", member.to_bytes());
}

pub mod unix_timestamp {
    use serde::{
        de::{Error as DeError, Visitor},
        Deserializer, Serializer,
    };

    use coarsetime::UnixTimeStamp;
    use std::fmt;

    struct TimestampVisitor;

    impl<'de> Visitor<'de> for TimestampVisitor {
        type Value = UnixTimeStamp;

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            Ok(UnixTimeStamp::from_secs(value as _))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            Ok(UnixTimeStamp::from_secs(value))
        }

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("Unix timestamp")
        }
    }

    pub fn serialize<S: Serializer>(
        time: &Option<UnixTimeStamp>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(time.unwrap().as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<UnixTimeStamp>, D::Error> {
        deserializer.deserialize_i64(TimestampVisitor).map(Some)
    }
}

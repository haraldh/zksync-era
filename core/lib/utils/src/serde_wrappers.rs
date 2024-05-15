use crate::{be_words_to_bytes, bytes_to_be_words};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::ops::Deref;
use zksync_basic_types::U256;

/// Trait for specifying prefix for bytes to hex serialization
pub trait Prefix {
    fn prefix() -> &'static str;
}

/// "0x" hex prefix
pub struct ZeroxPrefix;
impl Prefix for ZeroxPrefix {
    fn prefix() -> &'static str {
        "0x"
    }
}

/// Used to annotate `Vec<u8>` fields that you want to serialize like hex-encoded string with prefix
/// Use this struct in annotation like that `[serde(with = "BytesToHexSerde::<T>"]`
/// where T is concrete prefix type (e.g. `SyncBlockPrefix`)
pub struct BytesToHexSerde<P> {
    _marker: std::marker::PhantomData<P>,
}

impl<P: Prefix> BytesToHexSerde<P> {
    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // First, serialize to hexadecimal string.
            let hex_value = format!("{}{}", P::prefix(), hex::encode(value));

            // Then, serialize it using `Serialize` trait implementation for `String`.
            String::serialize(&hex_value, serializer)
        } else {
            <[u8]>::serialize(value, serializer)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let deserialized_string = String::deserialize(deserializer)?;

            if let Some(deserialized_string) = deserialized_string.strip_prefix(P::prefix()) {
                hex::decode(deserialized_string).map_err(de::Error::custom)
            } else {
                Err(de::Error::custom(format!(
                    "string value missing prefix: {:?}",
                    P::prefix()
                )))
            }
        } else {
            <Vec<u8>>::deserialize(deserializer)
        }
    }
}

pub type ZeroPrefixHexSerde = BytesToHexSerde<ZeroxPrefix>;

#[derive(Debug, Clone, PartialEq)]
pub struct BoxSliceU<T>(Box<[T]>);

impl<T> Deref for BoxSliceU<T> {
    type Target = Box<[T]>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<Vec<T>> for BoxSliceU<T> {
    fn from(value: Vec<T>) -> Self {
        Self(value.into_boxed_slice())
    }
}

impl<T> From<BoxSliceU<T>> for Vec<T> {
    fn from(value: BoxSliceU<T>) -> Self {
        value.0.into()
    }
}

impl Serialize for BoxSliceU<U256> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            self.0.serialize(serializer)
        } else {
            be_words_to_bytes(&self.0).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for BoxSliceU<U256> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            Ok(Self(Box::<[U256]>::deserialize(deserializer)?))
        } else {
            Ok(Self(
                bytes_to_be_words(Vec::<u8>::deserialize(deserializer)?).into_boxed_slice(),
            ))
        }
    }
}
#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use crate::ZeroPrefixHexSerde;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Execute {
        #[serde(with = "ZeroPrefixHexSerde")]
        pub calldata: Vec<u8>,
    }

    #[test]
    fn test_hex_serde_bincode() {
        let original = Execute {
            calldata: vec![0, 1, 2, 3, 4],
        };
        let encoded: Vec<u8> = vec![5, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4];
        let decoded: Execute = bincode::deserialize(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_hex_serde_json() {
        let original = Execute {
            calldata: vec![0, 1, 2, 3, 4],
        };
        let encoded = serde_json::to_string(&original).unwrap();
        assert_eq!(r#"{"calldata":"0x0001020304"}"#, encoded);
        let decoded: Execute = serde_json::from_str(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}

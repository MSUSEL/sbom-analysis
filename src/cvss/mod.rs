#![allow(dead_code)]

use std::collections::BTreeMap;

pub trait ComponentFromVector {
    fn from_vector(symbol: &str) -> Option<Self> where Self: Sized;
}

pub trait FromVector {
    fn from_vector(symbols: &BTreeMap<&str, &str>) -> Option<Self> where Self: Sized;
}

#[macro_export]
macro_rules! cvss_component {
    ($name:ident {
        $($variant:ident => $value:ident),*$(,)?
    }) => {
        #[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq, Hash)]
        pub enum $name {
            $($variant),*
        }

        impl crate::cvss::ComponentFromVector for $name {
            fn from_vector(symbol: &str) -> std::option::Option<Self> {
                match symbol {
                    $(stringify!($value) => std::option::Option::Some(Self::$variant)),*,
                    _ => std::option::Option::None,
                }
            }
        }
    }
}

// cvss_score!(BaseMetric {
//   attack_vector: AttackVector => AV,
//   attack_complexity: AttackComplexity => AC,
//   ...
// });
#[macro_export]
macro_rules! cvss_score {
    ($name:ident {
        $($field:ident: $ty:ty => $sym:ident),*$(,)?
    }) => {
        pub struct $name {
            $(pub $field: $ty),*
        }

        const _: () = {
            const fn assert_from_vec<T: crate::cvss::ComponentFromVector>() {}
            const fn assert_sized<T: Sized>() {}

            $(assert_from_vec::<$ty>();)*
            $(assert_sized::<$ty>();)*
        };

        impl crate::cvss::FromVector for $name {
            #[allow(unused_variables)]
            fn from_vector(symbols: &std::collections::BTreeMap<&str, &str>) -> std::option::Option<Self> {
                std::option::Option::Some($name {
                    $($field: <$ty as crate::cvss::ComponentFromVector>::from_vector(symbols.get(&stringify!($sym))?)?),*
                })
            }
        }
    }
}

pub mod v3_1;
pub mod v2_0;
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

        impl $name {
            pub fn vector_value(&self) -> &str {
                match self {
                    $(
                        Self::$variant => stringify!($value),
                    )*
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
    ($name:ident $(=> $prefix:literal)? {
        $($field:ident: $ty:ty => $sym:ident),*$(,)?
    }) => {
        mod cvss_score_decl {
            #![allow(unused, unused_mut, unused_assignments, unused_variables)]
            use super::*;

            #[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq, Hash)]
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
                fn from_vector(symbols: &::std::collections::BTreeMap<&str, &str>) -> ::std::option::Option<Self> {
                    ::std::option::Option::Some($name {
                        $($field: <$ty as crate::cvss::ComponentFromVector>::from_vector(symbols.get(&stringify!($sym))?)?),*
                    })
                }
            }


            impl $name {
                pub fn from_vector_string(val: &str) -> ::std::option::Option<Self> {
                    let mut iter = val.split('/');
                    $(if iter.next()? != $prefix {
                        return ::std::option::Option::None;
                    })?

                    let map = iter
                        .map(|v| {
                            let mut iter = v.split(':');
                            (iter.next(), iter.next())
                        })
                        .filter_map(|(a, b)| a.and_then(|a| b.map(|b| (a, b))))
                        .collect::<::std::collections::BTreeMap<_, _>>();
                    <Self as crate::cvss::FromVector>::from_vector(&map)
                }

                pub fn cvss_vector(&self) -> String {
                    let mut out = String::new();
                    $(
                        out.push_str($prefix);
                        out.push('/');
                    )?
                    let mut iota = 0;
                    $(
                    // AV:L/M/H
                        if iota > 0 {
                            out.push('/');
                        }
                        iota += 1;
                        out.push_str(stringify!($sym));
                        out.push(':');
                        out.push_str(self.$field.vector_value());
                    )*
                    out
                }
            }
        }
        pub use cvss_score_decl::*;
    }
}

pub mod v3_1;
pub mod v2_0;
#![allow(dead_code)]

use std::collections::BTreeMap;

/// An abstraction for CVSS Components.
pub trait ComponentFromVector {
    /// Parses a CVSS vector and returns a component.
    fn from_vector(symbol: &str) -> Option<Self> where Self: Sized;
}

/// An abstraction for CVSS Metrics
pub trait FromVector {
    /// Creates a CVSS metric from a map of symbols.
    fn from_vector(symbols: &BTreeMap<&str, &str>) -> Option<Self> where Self: Sized;

    /// Creates a CVSS metric from a cvss standard string.
    ///
    /// # Example
    /// ```
    /// use scayl::{FromVector, v3_1};
    ///
    /// let metric = v3_1::BaseMetric
    ///                    ::from_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    /// ```
    fn from_vector_string(str: &str) -> Option<Self> where Self: Sized;

    /// Creates a CVSS standard string
    ///
    /// # Example
    /// ```
    ///  use scayl::{FromVector, v3_1};
    ///
    ///  let metric = v3_1::BaseMetric {
    ///      attack_vector: v3_1::AttackVector::Network,
    ///      attack_complexity: v3_1::AttackComplexity::Low,
    ///      privileges_required: v3_1::PrivilegesRequired::None,
    ///      user_interaction: v3_1::UserInteraction::None,
    ///      scope: v3_1::Scope::Unchanged,
    ///      confidentiality_impact: v3_1::ImpactMetric::None,
    ///      integrity_impact: v3_1::ImpactMetric::None,
    ///      availability_impact: v3_1::ImpactMetric::None
    ///  };
    /// let str = metric.cvss_vector();
    /// ```
    fn cvss_vector(&self) -> String;
}

/// CVSS Component macro
///
/// This macro creates an enum for a CVSS Component and its values.
/// It also creates a `from_vector` method that allows string parsing from a cvss string
///
/// # Examples
/// ```
/// use scayl::cvss_component;
///
/// cvss_component!(AttackVector {
///     Network => N,
///     Adjacent => A,
///     Local => L,
///     Physical => P,
/// });
/// ```
#[macro_export]
macro_rules! cvss_component {
    ($name:ident {
        $($variant:ident => $value:ident),*$(,)?
    }) => {
        #[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq, Hash)]
        pub enum $name {
            $($variant),*
        }

        impl $crate::cvss::ComponentFromVector for $name {
            /// Parses a string into this component
            fn from_vector(symbol: &str) -> std::option::Option<Self> {
                match symbol {
                    $(stringify!($value) => std::option::Option::Some(Self::$variant)),*,
                    _ => std::option::Option::None,
                }
            }
        }

        impl $name {
            /// Returns the cvss metric representation of the enum
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
                const fn assert_from_vec<T: $crate::cvss::ComponentFromVector>() {}
                const fn assert_sized<T: Sized>() {}

                $(assert_from_vec::<$ty>();)*
                $(assert_sized::<$ty>();)*
            };

            impl $crate::cvss::FromVector for $name {
                fn from_vector(symbols: &::std::collections::BTreeMap<&str, &str>) -> ::std::option::Option<Self> {
                    ::std::option::Option::Some($name {
                        $($field: <$ty as $crate::cvss::ComponentFromVector>::from_vector(symbols.get(&stringify!($sym))?)?),*
                    })
                }

                fn from_vector_string(val: &str) -> ::std::option::Option<Self> {
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
                    <Self as $crate::cvss::FromVector>::from_vector(&map)
                }

                fn cvss_vector(&self) -> String {
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
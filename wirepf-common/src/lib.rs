#![no_std]

#[cfg(feature = "dto")]
extern crate alloc;

#[cfg(feature = "dto")]
pub mod dto {
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::net::Ipv4Addr;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    pub struct Mapping {
        pub orig: Ipv4Addr,
        pub new: Ipv4Addr,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InterfaceCfg {
        pub name: String,
        #[serde(default)]
        pub mappings: Vec<Mapping>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct IfaceView {
        pub name: String,
        pub mappings: Vec<Mapping>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CreateIfaceBody {
        pub name: String,
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct Health {
        pub ok: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ErrorResponse {
        pub error: String,
    }
}

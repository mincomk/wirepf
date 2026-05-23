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
    pub struct DnatMapping {
        pub orig: Ipv4Addr,
        pub new: Ipv4Addr,
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SnatMapping {
        pub orig: Ipv4Addr,
        pub new: Ipv4Addr,
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    pub struct Cidr {
        pub addr: Ipv4Addr,
        pub prefix_len: u8,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
    pub struct MasqueradeCfg {
        #[serde(default)]
        pub enabled: bool,
        #[serde(default)]
        pub src_cidrs: Vec<Cidr>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InterfaceCfg {
        pub name: String,
        #[serde(default)]
        pub dnat: Vec<DnatMapping>,
        #[serde(default)]
        pub snat: Vec<SnatMapping>,
        #[serde(default)]
        pub masquerade: MasqueradeCfg,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct IfaceView {
        pub name: String,
        pub dnat: Vec<DnatMapping>,
        pub snat: Vec<SnatMapping>,
        pub masquerade: MasqueradeCfg,
        #[serde(default)]
        pub iface_ip: Option<Ipv4Addr>,
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

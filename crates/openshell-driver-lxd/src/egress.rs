// SPDX-License-Identifier: AGPL-3.0-or-later

//! The network ACL that confines a sandbox's egress.
//!
//! Inside a sandbox the supervisor already forces the workload through its
//! policy proxy. The sandbox as a whole — the supervisor included — sits on an
//! ordinary network, though, and could otherwise reach the LAN, the LXD host,
//! other sandboxes and any other instance. With `--restrict-sandbox-egress`
//! every sandbox NIC gets an LXD network ACL that allows only:
//!
//! - the gateway endpoint (TCP to its address and port), and
//! - public internet addresses,
//!
//! and rejects everything else, inbound included (replies to allowed
//! connections are let back in by the ACL's connection tracking). DNS needs
//! no rule: LXD lets an OVN NIC reach the DNS servers its network hands out
//! whatever its ACLs say.
//!
//! "Public" is by address. A gateway, LXD host or LAN on public or global
//! IPv6 addresses is reachable through the public-internet rule.
//!
//! LXD orders rules by action — drop, then reject, then allow — so a "reject
//! private ranges" rule would also win over "allow the gateway" whenever the
//! gateway has a private address. The public internet is therefore spelled
//! out as the complement of the non-public ranges, and anything not allowed
//! falls to the NIC's default action.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use lxd_client::{AclProtocol, LxdNetworkAclRule};

/// Prefix of the ACL the driver manages for each network it places
/// sandboxes on; the network's name completes it.
const ACL_PREFIX: &str = "openshell-egress-";

/// IPv4 ranges that are not the public internet: private, shared, loopback,
/// link-local, documentation, benchmarking, multicast and reserved space
/// (the IANA special-purpose registry's non-global entries).
const NON_PUBLIC_IPV4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    (Ipv4Addr::new(192, 88, 99, 0), 24),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

/// Global unicast IPv6, which leaves out unique-local, link-local, loopback
/// and multicast addresses.
const PUBLIC_IPV6: &str = "2000::/3";

/// Name of the egress ACL for sandboxes on `network`.
pub(crate) fn acl_name(network: &str) -> String {
    format!("{ACL_PREFIX}{network}")
}

/// The egress rules for sandboxes that reach the gateway at `gateway`.
pub(crate) fn rules(gateway: &[SocketAddr]) -> Vec<LxdNetworkAclRule> {
    let mut rules = Vec::new();

    // One rule per port; a resolved endpoint normally has a single one.
    let mut ports: Vec<u16> = gateway.iter().map(SocketAddr::port).collect();
    ports.sort_unstable();
    ports.dedup();
    for port in ports {
        let addresses = join(
            gateway
                .iter()
                .filter(|a| a.port() == port)
                .map(SocketAddr::ip),
        );
        rules.push(
            LxdNetworkAclRule::allow_egress(&addresses, Some(AclProtocol::Tcp), &port.to_string())
                .described("OpenShell gateway"),
        );
    }

    rules.push(
        LxdNetworkAclRule::allow_egress(&public_ipv4_cidrs().join(","), None, "")
            .described("public IPv4 internet"),
    );
    rules.push(
        LxdNetworkAclRule::allow_egress(PUBLIC_IPV6, None, "").described("public IPv6 internet"),
    );
    rules
}

fn join(addresses: impl Iterator<Item = IpAddr>) -> String {
    let mut addresses: Vec<String> = addresses.map(|a| a.to_string()).collect();
    addresses.sort();
    addresses.dedup();
    addresses.join(",")
}

/// The public IPv4 internet as CIDRs: every address outside
/// [`NON_PUBLIC_IPV4`], in ascending order.
pub(crate) fn public_ipv4_cidrs() -> Vec<String> {
    // Inclusive [start, end] ranges, in u64 so the arithmetic cannot wrap.
    let mut ranges: Vec<(u64, u64)> = vec![(0, u64::from(u32::MAX))];
    for &(address, prefix) in NON_PUBLIC_IPV4 {
        let start = u64::from(u32::from(address));
        let end = start + (1u64 << (32 - prefix)) - 1;
        ranges = ranges
            .into_iter()
            .flat_map(|(lo, hi)| {
                let mut kept = Vec::with_capacity(2);
                if end < lo || start > hi {
                    kept.push((lo, hi));
                } else {
                    if start > lo {
                        kept.push((lo, start - 1));
                    }
                    if end < hi {
                        kept.push((end + 1, hi));
                    }
                }
                kept
            })
            .collect();
    }

    let mut cidrs = Vec::new();
    for (mut start, end) in ranges {
        while start <= end {
            // The largest block that starts at `start` (aligned to its lowest
            // set bit) and still fits before `end`.
            let aligned = if start == 0 {
                1u64 << 32
            } else {
                1u64 << start.trailing_zeros()
            };
            let mut size = aligned;
            while size > end - start + 1 {
                size >>= 1;
            }
            let prefix = 32 - size.trailing_zeros();
            let address = Ipv4Addr::from(u32::try_from(start).expect("within IPv4"));
            cidrs.push(format!("{address}/{prefix}"));
            start += size;
        }
    }
    cidrs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(cidr: &str) -> (u64, u64) {
        let (address, prefix) = cidr.split_once('/').expect("CIDR");
        let start = u64::from(u32::from(address.parse::<Ipv4Addr>().expect("address")));
        let prefix: u32 = prefix.parse().expect("prefix");
        assert_eq!(start % (1u64 << (32 - prefix)), 0, "{cidr} is not aligned");
        (start, start + (1u64 << (32 - prefix)) - 1)
    }

    fn contains(cidrs: &[String], address: &str) -> bool {
        let address = u64::from(u32::from(address.parse::<Ipv4Addr>().unwrap()));
        cidrs
            .iter()
            .map(|c| parse(c))
            .any(|(lo, hi)| (lo..=hi).contains(&address))
    }

    /// Together with the non-public ranges the CIDRs cover all of IPv4
    /// exactly once, in order and without overlap.
    #[test]
    fn public_ranges_are_the_exact_complement() {
        let cidrs = public_ipv4_cidrs();
        let mut blocks: Vec<(u64, u64)> = cidrs.iter().map(|c| parse(c)).collect();
        blocks.extend(
            NON_PUBLIC_IPV4
                .iter()
                .map(|(address, prefix)| parse(&format!("{address}/{prefix}"))),
        );
        blocks.sort_unstable();

        let mut next = 0;
        for (lo, hi) in blocks {
            assert_eq!(lo, next, "gap or overlap before {lo}");
            next = hi + 1;
        }
        assert_eq!(next, 1u64 << 32);
    }

    #[test]
    fn public_ranges_leave_out_lan_and_host_addresses() {
        let cidrs = public_ipv4_cidrs();
        for private in [
            "10.131.189.2",
            "192.168.1.166",
            "172.17.0.1",
            "127.0.0.1",
            "169.254.17.1",
            "100.64.0.1",
        ] {
            assert!(!contains(&cidrs, private), "{private} must not be allowed");
        }
        for public in ["1.1.1.1", "140.82.121.4", "8.8.8.8", "223.255.255.255"] {
            assert!(contains(&cidrs, public), "{public} must be allowed");
        }
    }

    #[test]
    fn rules_allow_the_gateway_and_the_internet_only() {
        let gateway: SocketAddr = "192.168.1.251:17671".parse().unwrap();
        let rules = rules(&[gateway]);

        let summary: Vec<(String, Option<AclProtocol>, String)> = rules
            .iter()
            .map(|r| {
                let destination = if r.destination.len() > 40 {
                    "<public ipv4>".to_string()
                } else {
                    r.destination.clone()
                };
                (destination, r.protocol, r.destination_port.clone())
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                (
                    "192.168.1.251".to_string(),
                    Some(AclProtocol::Tcp),
                    "17671".to_string()
                ),
                ("<public ipv4>".to_string(), None, String::new()),
                ("2000::/3".to_string(), None, String::new()),
            ]
        );
        assert!(rules
            .iter()
            .all(|r| r.action == lxd_client::AclAction::Allow));
    }

    #[test]
    fn gateway_addresses_are_grouped_by_port() {
        let rules = rules(&[
            "[fd42::5]:17670".parse().unwrap(),
            "10.0.0.5:17670".parse().unwrap(),
        ]);
        assert_eq!(rules[0].destination, "10.0.0.5,fd42::5");
        assert_eq!(rules[0].destination_port, "17670");
        // Gateway, IPv4, IPv6.
        assert_eq!(rules.len(), 3);
    }

    #[test]
    fn acl_is_named_after_the_network() {
        assert_eq!(acl_name("sandboxes"), "openshell-egress-sandboxes");
    }
}

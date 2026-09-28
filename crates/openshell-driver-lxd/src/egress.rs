// SPDX-License-Identifier: AGPL-3.0-or-later

//! The network ACL that confines a sandbox's egress.
//!
//! Inside a sandbox the boundary already forces the workload through its
//! policy proxy. The sandbox as a whole — its supervisor companion included —
//! sits on an ordinary network, though, and could otherwise reach the LAN, the
//! LXD host, other sandboxes and any other instance.
//!
//! Every sandbox NIC therefore carries two LXD network ACLs, and between them
//! they allow only:
//!
//! - public internet addresses, from [`network_rules`], one ACL per network
//!   and shared by every sandbox on it;
//! - the gateway endpoint, and the Sandbox Protocol between this sandbox's own
//!   two halves, from [`sandbox_rules`], one ACL per sandbox;
//!
//! and reject everything else, inbound included (replies to allowed
//! connections are let back in by the ACL's connection tracking).
//!
//! The split is not bookkeeping. Anything in the shared ACL is rewritten by
//! every sandbox that is created on that network, so a rule that depends on
//! this sandbox — its gateway's resolved addresses, its own two halves —
//! belongs in its own ACL, where its own lifecycle is the only thing that
//! touches it. What is left in the shared one is a constant, so after the
//! first create it is never rewritten at all.
//!
//! This is not an option. From OpenShell v0.1.0 it is the sandbox's *outer
//! network fence*, and both the supervisor companion and the in-workload
//! boundary refuse to run without one — see
//! [`crate::isolation::LxdFenceEvidence::project`] for what it has to
//! establish and why an ACL establishes it. DNS needs
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

/// Prefixes of the two ACLs the driver manages for each individual sandbox.
///
/// Recognizable on sight so clean-up can tell one of these from an ACL the
/// operator made. The rest is a digest, not the sandbox's name: LXD allows an
/// ACL name 63 characters and an instance name may already use all of them.
///
/// There are two because the halves are not entitled to the same things. The
/// `sbp` ACL is the sandbox's membership marker and carries the one rule the
/// *workload* is allowed — inbound Sandbox Protocol — so both halves carry it.
/// The `sbe` ACL carries everything only the companion may do, and only the
/// companion carries it.
pub(crate) const SANDBOX_PROTOCOL_ACL_PREFIX: &str = "openshell-sbp-";
pub(crate) const SANDBOX_EGRESS_ACL_PREFIX: &str = "openshell-sbe-";

/// Every per-sandbox prefix, for clean-up.
pub(crate) const SANDBOX_ACL_PREFIXES: [&str; 2] =
    [SANDBOX_PROTOCOL_ACL_PREFIX, SANDBOX_EGRESS_ACL_PREFIX];

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

/// Digest of `sandbox_name`, shared by both of its ACL names.
///
/// A digest rather than the name: LXD caps an ACL name at 63 characters and a
/// sandbox name may already be that long. Stable, so a restart finds the same
/// ACLs.
fn sandbox_digest(sandbox_name: &str) -> String {
    use sha2::{Digest as _, Sha256};

    Sha256::digest(sandbox_name.as_bytes())
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Name of the ACL both of `sandbox_name`'s halves carry.
pub(crate) fn sandbox_protocol_acl_name(sandbox_name: &str) -> String {
    format!(
        "{SANDBOX_PROTOCOL_ACL_PREFIX}{}",
        sandbox_digest(sandbox_name)
    )
}

/// Name of the ACL only `sandbox_name`'s companion carries.
pub(crate) fn sandbox_egress_acl_name(sandbox_name: &str) -> String {
    format!(
        "{SANDBOX_EGRESS_ACL_PREFIX}{}",
        sandbox_digest(sandbox_name)
    )
}

/// The rules every sandbox on a network shares: the public internet.
///
/// Carried by the **companion only**. A constant, deliberately: this ACL is
/// rewritten by every create on the network, so anything here that varied per
/// sandbox would be revoked for every other sandbox the moment one more was
/// created.
pub(crate) fn network_rules() -> Vec<LxdNetworkAclRule> {
    vec![
        LxdNetworkAclRule::allow_egress(&public_ipv4_cidrs().join(","), None, "")
            .described("public IPv4 internet"),
        LxdNetworkAclRule::allow_egress(PUBLIC_IPV6, None, "").described("public IPv6 internet"),
    ]
}

/// The one thing the workload half is allowed: its companion dialling in.
///
/// Returned as `(egress, ingress)`. Egress is **empty**, and that is the
/// point. Under RFC 0012 every connection and every DNS query a workload makes
/// is relayed to the companion, which dials out on its behalf — so the
/// workload's only legitimate traffic is replies on the connection the
/// companion opened, which the ACL's connection tracking already permits. A
/// workload with egress of its own would mean the outer fence does not
/// backstop an escape from the in-guest boundary, which is the only reason
/// the fence exists. Upstream says the same in its own terms: the Kubernetes
/// driver gives the workload pod `egress: Some(Vec::new())` — "allows no new
/// workload-initiated connections, including DNS" — and Podman runs it with
/// `network_mode: none`.
///
/// `self_acl` is this ACL's own name, used as a subject selector. LXD resolves
/// an ACL name to the NICs carrying that ACL, and the only NICs carrying this
/// one are the sandbox's own two halves, so the boundary port is reachable by
/// its own companion and by nothing else. That selector is what makes an
/// address unnecessary — the companion's is assigned by DHCP long after the
/// workload is created, and writing the rule against the network's subnets
/// instead would open every sandbox's boundary port to every instance on the
/// network.
pub(crate) fn sandbox_protocol_rules(
    self_acl: &str,
) -> (Vec<LxdNetworkAclRule>, Vec<LxdNetworkAclRule>) {
    let ingress =
        vec![
            LxdNetworkAclRule::allow_ingress_tcp(self_acl, crate::isolation::BOUNDARY_PORT)
                .described("OpenShell Sandbox Protocol"),
        ];
    (Vec::new(), ingress)
}

/// What only the companion may do: reach the gateway, and dial its workload's
/// boundary.
///
/// `protocol_acl` names the ACL both halves carry, so the boundary rule
/// resolves to this sandbox's own NICs without needing an address.
pub(crate) fn companion_egress_rules(
    gateway: &[SocketAddr],
    protocol_acl: &str,
) -> Vec<LxdNetworkAclRule> {
    let mut egress = Vec::new();

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
        egress.push(
            LxdNetworkAclRule::allow_egress(&addresses, Some(AclProtocol::Tcp), &port.to_string())
                .described("OpenShell gateway"),
        );
    }
    egress.push(
        LxdNetworkAclRule::allow_egress_tcp(protocol_acl, crate::isolation::BOUNDARY_PORT)
            .described("OpenShell Sandbox Protocol"),
    );
    egress
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
    /// The property the whole split exists for: the workload half is allowed
    /// *nothing* outbound. Its traffic is relayed by the companion, so an
    /// egress rule here would mean the outer fence stops backstopping an
    /// escape from the in-guest boundary. Upstream's Kubernetes driver says
    /// the same with `egress: Some(Vec::new())`.
    #[test]
    fn the_workload_half_is_allowed_no_egress() {
        let acl = sandbox_protocol_acl_name("my-sandbox");
        let (egress, ingress) = sandbox_protocol_rules(&acl);

        assert!(
            egress.is_empty(),
            "workload egress must be empty: {egress:?}"
        );
        assert_eq!(ingress.len(), 1);
        assert_eq!(ingress[0].source, acl);
        assert_eq!(
            ingress[0].destination_port,
            crate::isolation::BOUNDARY_PORT.to_string()
        );
        assert_eq!(ingress[0].protocol, Some(AclProtocol::Tcp));
    }

    /// The hole the subject selector closes: the boundary port used to be
    /// open to the whole sandbox subnet, so any instance on the network — a
    /// different tenant's untrusted workload included — could reach any
    /// sandbox's boundary. An ACL name resolves to the NICs carrying that
    /// ACL, and only this sandbox's two halves carry this one.
    #[test]
    fn the_sandbox_protocol_names_an_acl_and_never_an_address() {
        let gateway: SocketAddr = "10.0.0.5:17670".parse().unwrap();
        let protocol = sandbox_protocol_acl_name("my-sandbox");
        let (_, ingress) = sandbox_protocol_rules(&protocol);
        let companion = companion_egress_rules(&[gateway], &protocol);

        let boundary: Vec<&LxdNetworkAclRule> = companion
            .iter()
            .filter(|rule| rule.destination_port == crate::isolation::BOUNDARY_PORT.to_string())
            .collect();
        assert_eq!(boundary.len(), 1);
        assert_eq!(boundary[0].destination, protocol);

        for rule in ingress.iter().chain(&companion) {
            assert!(!rule.destination.contains('/'), "{rule:?}");
            assert!(!rule.source.contains('/'), "{rule:?}");
        }
    }

    /// The gateway is the companion's to reach, not the workload's.
    #[test]
    fn only_the_companion_reaches_the_gateway_and_the_internet() {
        let gateway: SocketAddr = "192.168.1.251:17671".parse().unwrap();
        let protocol = sandbox_protocol_acl_name("sb");
        let (workload_egress, _) = sandbox_protocol_rules(&protocol);
        let companion = companion_egress_rules(&[gateway], &protocol);

        assert!(workload_egress.is_empty());
        assert!(
            companion
                .iter()
                .any(|r| r.destination == "192.168.1.251" && r.destination_port == "17671"),
            "{companion:?}"
        );
        // The public internet is the shared ACL, which only the companion
        // carries; it must not name a port or a source. Spelled out rather
        // than compared to itself: `network_rules() == network_rules()` is
        // true of any pure function and proves nothing about the rules.
        assert_eq!(network_rules().len(), 2);
        assert_eq!(network_rules()[1].destination, PUBLIC_IPV6);
        for rule in network_rules() {
            assert_eq!(rule.action, lxd_client::AclAction::Allow);
            assert!(rule.source.is_empty(), "{rule:?}");
            assert!(rule.destination_port.is_empty(), "{rule:?}");
        }
    }

    #[test]
    fn gateway_addresses_are_grouped_by_port() {
        let egress = companion_egress_rules(
            &[
                "[fd42::5]:17670".parse().unwrap(),
                "10.0.0.5:17670".parse().unwrap(),
            ],
            "openshell-sbp-abc",
        );
        assert_eq!(egress[0].destination, "10.0.0.5,fd42::5");
        assert_eq!(egress[0].destination_port, "17670");
        // The gateway, then the Sandbox Protocol.
        assert_eq!(egress.len(), 2);
    }

    /// LXD caps an ACL name at 63 characters and an instance name may use all
    /// of them, so the names are digests — stable, prefixed so clean-up
    /// recognizes them, and distinct from each other.
    #[test]
    fn a_sandbox_acl_name_fits_whatever_the_sandbox_is_called() {
        let long = "s".repeat(63);
        let protocol = sandbox_protocol_acl_name(&long);
        let egress = sandbox_egress_acl_name(&long);

        for name in [&protocol, &egress] {
            assert!(name.len() <= 63, "{name} is {} characters", name.len());
        }
        assert_ne!(protocol, egress);
        assert_eq!(protocol, sandbox_protocol_acl_name(&long), "must be stable");
        assert_ne!(protocol, sandbox_protocol_acl_name("other"));
        assert!(SANDBOX_ACL_PREFIXES.iter().any(|p| protocol.starts_with(p)));
        assert!(SANDBOX_ACL_PREFIXES.iter().any(|p| egress.starts_with(p)));
    }

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
    fn acl_is_named_after_the_network() {
        assert_eq!(acl_name("sandboxes"), "openshell-egress-sandboxes");
    }
}

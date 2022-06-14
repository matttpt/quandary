// Copyright 2022 Matthew Ingwersen.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you
// may not use this file except in compliance with the License. You may
// obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Implementation of response rate-limiting (RRL).
//!
//! The actual rate-limiting logic is implemented by [`Rrl`], but see
//! the public API documentation of [`RrlParams`] for details on how RRL
//! is implemented and how it may be configured.

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::Rng;

use super::{Context, Transport};
use crate::message::{Opcode, ExtendedRcode};

////////////////////////////////////////////////////////////////////////
// RRL PARAMETERS                                                     //
////////////////////////////////////////////////////////////////////////

/// Parameters for response rate-limiting.
///
/// Response rate-limiting (RRL) is a technique for mitigating DNS
/// amplification attacks. Such attacks involve sending DNS queries over
/// UDP with a forged source IP address, tricking DNS servers into
/// inundating the supposed source with unwanted responses. Since the
/// responses are almost always larger than the queries, more data is
/// sent to the target than the attacker sends (hence "amplification").
/// RRL tries to render these attacks ineffective by limiting the rate
/// at which "equivalent" responses are sent.
///
/// This response rate-limiting implementation follows the same general
/// principles as other authoritative DNS servers. In this
/// implementation, responses are split into three categories:
///
/// * Responses with RCODE NOERROR. Such responses are considered
///   equivalent if they share the same destination network and QNAME.
///   (The QNAME used when records are generated by wildcard synthesis
///   is the wildcard domain name that is the source of synthesis; see
///   [RFC 4592 § 3.3.1].) Each stream of equivalent responses is
///   limited by a `noerror_rate` parameter.
/// * Responses with RCODE NXDOMAIN. Such responses are considered
///   equivalent if they share the same destination network. Each stream
///   is limited by an `nxdomain_rate` parameter.
/// * Responses with other error RCODEs. Such responses are considered
///   equivalent if they share the same destination network. Each stream
///   is limited by an `error_rate` parameter.
///
/// The rate parameters are expressed in terms of responses per second
/// and must be non-zero.
///
/// To perform the rate-limiting, each stream of equivalent responses
/// has a counter which keeps track of the number of such responses
/// sent. Once a limit is reached, further responses are either dropped
/// or slipped (see below). Each second, the counter is decremented by
/// the appropriate rate parameter, allowing responses to be sent at up
/// to that rate. The limit is determined by multiplying the appropriate
/// rate by a (non-zero) `window` parameter, which is expressed in
/// seconds. This allows bursts in the response rate so long as the rate
/// remains at or below the target over intervals of `window` seconds.
///
/// When a response is affected by rate limiting, it may be dropped
/// outright, but then the attack victim will struggle to make
/// legitimate queries to the server (since, in a real-world scenario,
/// almost all of the legitimate responses will be dropped). An
/// alternative is to "slip" rate-limited responses, meaning that a
/// truncated response is sent. Although more unrequested responses will
/// be sent to the victim, the attack target will still be able to query
/// the server: seeing the truncated responses, the target will retry
/// queries over TCP, which is not subject to RRL. Furthermore, the
/// truncated responses are small, so they have little amplification
/// value. The `slip` parameter controls this behavior. A value of 0
/// means always drop/never slip. A value of 1 means always slip/never
/// drop. A value of *n* (where *n* > 1) means to randomly slip 1 out of
/// *n* responses, and to drop the rest.
///
/// Note that dropping rate-limited responses makes it easier for an
/// attacker to carry out a cache-poisoning attack by supplying
/// fraudulent answers to queries whose legitimate responses were
/// dropped. Thus there is a trade-off between minimizing unwanted data
/// transmitted to an attack victim and minimizing the possibility for
/// cache-poisoning attacks against them. Hence the typically chosen
/// values for `slip` are 1 and 2; setting `slip` to 0 or to larger
/// values is not advisable.
///
/// The `ipv4_prefix_len` and `ipv6_prefix_len` parameters determine the
/// size of a destination network for RRL classification. They must be
/// valid prefix sizes for their respective IP versions, and
/// additionally `ipv6_prefix_len` cannot be more than 64 (a single IPv6
/// subnetwork).
///
/// RRL is implemented using a fixed-size hash table containing entries
/// for each stream of equivalent responses. The `size` parameter
/// controls the number of entries. At present, in the event of a hash
/// collision, the current entry is simply discarded. More advanced
/// hash-collision and eviction handling is planned for the future.
///
/// The three rate parameters and `window` must be explicitly
/// configured. The remaining parameters have defaults, and can be
/// explicitly configured with the appropriate setter methods. The
/// defaults are:
///
/// * `slip`: 2 (slip every other rate-limited response)
/// * `ipv4_prefix_len`: 24
/// * `ipv6_prefix_len`: 56
/// * `size`: 65,537 entries
///
/// [RFC 4592 § 3.3.1]: https://datatracker.ietf.org/doc/html/rfc4592#section-3.3.1
pub struct RrlParams {
    noerror_rate: u32,
    nxdomain_rate: u32,
    error_rate: u32,
    window: u32,
    slip: usize,
    ipv4_netmask: u32,
    ipv6_netmask: u64,
    size: usize,
}

impl RrlParams {
    /// Creates a new `RrlParams`. The rate limits and window must be
    /// provided; other parameters are set to their defaults. See the
    /// [structure-level documentation](`RrlParams`).
    pub fn new(
        noerror_rate: u32,
        nxdomain_rate: u32,
        error_rate: u32,
        window: u32,
    ) -> Result<RrlParams, RrlParamError> {
        if noerror_rate == 0 {
            Err(RrlParamError::NoerrorRateIsZero)
        } else if nxdomain_rate == 0 {
            Err(RrlParamError::NxdomainRateIsZero)
        } else if error_rate == 0 {
            Err(RrlParamError::ErrorRateIsZero)
        } else if window == 0 {
            Err(RrlParamError::WindowIsZero)
        } else if noerror_rate.checked_mul(window).is_none()
            || nxdomain_rate.checked_mul(window).is_none()
            || error_rate.checked_mul(window).is_none()
        {
            Err(RrlParamError::WindowIsTooLargeForRates)
        } else {
            Ok(Self {
                noerror_rate,
                nxdomain_rate,
                error_rate,
                window,
                slip: 2,
                ipv4_netmask: 0xffffff00,
                ipv6_netmask: 0xffffffffffffff00,
                size: 65_537,
            })
        }
    }

    /// Sets the slip rate.
    pub fn set_slip(&mut self, slip: usize) {
        self.slip = slip;
    }

    /// Sets the size of an IPv4 network in RRL classification.
    pub fn set_ipv4_prefix_len(&mut self, len: u8) -> Result<(), RrlParamError> {
        if len > 32 {
            Err(RrlParamError::InvalidIpv4PrefixLen)
        } else if len == 0 {
            self.ipv4_netmask = 0;
            Ok(())
        } else {
            self.ipv4_netmask = u32::MAX << (32 - len);
            Ok(())
        }
    }

    /// Sets the size of an IPv6 network in RRL classification. This
    /// must not be greater than 64.
    pub fn set_ipv6_prefix_len(&mut self, len: u8) -> Result<(), RrlParamError> {
        if len > 64 {
            Err(RrlParamError::InvalidIpv6PrefixLen)
        } else if len == 0 {
            self.ipv6_netmask = 0;
            Ok(())
        } else {
            self.ipv6_netmask = u64::MAX << (64 - len);
            Ok(())
        }
    }

    /// Sets the size of the RRL hash table.
    pub fn set_size(&mut self, size: usize) -> Result<(), RrlParamError> {
        if size == 0 {
            Err(RrlParamError::SizeIsZero)
        } else {
            self.size = size;
            Ok(())
        }
    }
}

/// Errors that may arise when setting RRL parameters.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RrlParamError {
    NoerrorRateIsZero,
    NxdomainRateIsZero,
    ErrorRateIsZero,
    WindowIsZero,
    WindowIsTooLargeForRates,
    InvalidIpv4PrefixLen,
    InvalidIpv6PrefixLen,
    SizeIsZero,
}

impl fmt::Display for RrlParamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NoerrorRateIsZero => f.write_str("the NOERROR rate limit cannot be zero"),
            Self::NxdomainRateIsZero => f.write_str("the NXDOMAIN rate limit cannot be zero"),
            Self::ErrorRateIsZero => f.write_str("the error rate limit cannot be zero"),
            Self::WindowIsZero => f.write_str("the window cannot be zero"),
            Self::WindowIsTooLargeForRates => {
                f.write_str("the window is too large for the rates (counters may overflow)")
            }
            Self::InvalidIpv4PrefixLen => f.write_str("invalid IPv4 prefix length"),
            Self::InvalidIpv6PrefixLen => f.write_str("invalid IPv6 prefix length"),
            Self::SizeIsZero => f.write_str("the table size cannot be zero"),
        }
    }
}

////////////////////////////////////////////////////////////////////////
// RRL IMPLEMENTATION                                                 //
////////////////////////////////////////////////////////////////////////

/// A response rate-limiter. For details on how this works and how it is
/// configured, see the documentation for [`RrlParams`].
pub struct Rrl {
    params: RrlParams,
    buckets: Vec<Mutex<Entry>>,
    random_state: RandomState,
}

/// The key for a stream of equivalent responses in the RRL table.
///
/// Note that the QNAME (or source of synthesis, when wildcard synthesis
/// occurred) is actually represented by its 32-bit hash. Thus hash
/// collisions are possible when computing keys; however, we (like other
/// RRL implementations that do this) prefer to keep the table memory
/// usage down.
#[derive(Clone, Eq, Hash, PartialEq)]
struct Key {
    dest: u64,
    ipv6: bool,
    qname_hash: u32,
    category: Category,
}

/// An entry in the RRL table.
struct Entry {
    key: Key,
    count: u32,
    last_refill: Instant,
}

/// The category of a response used in RRL classification.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum Category {
    NoError,
    NxDomain,
    Error,
}

/// The action to take with a DNS message after response rate-limiting.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum Action {
    Send,
    Slip,
    Drop,
}

impl Rrl {
    /// Creates a new response rate-limiter with the provided
    /// [parameters](`RrlParams`).
    pub(super) fn new(params: RrlParams) -> Self {
        let mut buckets = Vec::with_capacity(params.size);
        let now = Instant::now();
        for _ in 0..params.size {
            // New entries replace old ones when hashes collide, so the
            // initial values really don't matter here.
            buckets.push(Mutex::new(Entry {
                key: Key {
                    dest: 0,
                    ipv6: false,
                    qname_hash: 0,
                    category: Category::NoError,
                },
                count: 0,
                last_refill: now,
            }));
        }
        Self {
            params,
            buckets,
            random_state: RandomState::new(),
        }
    }

    /// Determines whether to send, slip, or drop a response with the
    /// provided destination, QNAME (or source of synthesis for
    /// responses generated through wildcard synthesis), and RCODE. The
    /// RRL tracking table is updated in the process.
    pub(super) fn process_response(&self, context: &mut Context) {
        if !subject_to_rrl(context) {
            return;
        }

        // Determine the key. Only non-error responses include the QNAME
        // in the key. NXDOMAIN and other error messages do not, since
        // otherwise an attacker could evade rate-limiting by sending
        // queries with many different QNAMEs that all produce NXDOMAIN
        // or other error responses.
        let category = context.response.extended_rcode().into();
        let dest = context.received_info.source;
        let qname_hash = if category == Category::NoError {
            let qname = if let Some(source_of_synthesis) = context.source_of_synthesis {
                source_of_synthesis
            } else {
                // If this response passed subject_to_rrl and is in this
                // category, it must have opcode QUERY and there must be
                // a question available, so the unwrap is okay.
                &context.question.as_ref().unwrap().qname
            };
            let mut qname_hasher = self.random_state.build_hasher();
            qname.hash(&mut qname_hasher);
            qname_hasher.finish() as u32
        } else {
            0
        };
        let key = Key {
            dest: self.ip_to_dest_u64(dest),
            ipv6: dest.is_ipv6(),
            qname_hash,
            category,
        };

        // Find the right bucket.
        let mut key_hasher = self.random_state.build_hasher();
        key.hash(&mut key_hasher);
        let idx = (key_hasher.finish() % self.buckets.len() as u64) as usize;
        let mutex = &self.buckets[idx];
        let mut entry = mutex.lock().unwrap();

        if entry.key == key {
            let (rate, limit) = self.rate_and_limit_for_category(category);

            let now = Instant::now();
            let since_last_refill = now.duration_since(entry.last_refill);
            if since_last_refill >= Duration::from_secs(1) {
                // We refill only in increments of the rate, so we round
                // since_last_refill to the nearest second for
                // calculating the refill quantity and compensate by
                // subtracting the fractional part when we update the
                // last refill time.
                entry.count = entry
                    .count
                    .saturating_sub(rate * since_last_refill.as_secs() as u32);
                entry.last_refill =
                    now - Duration::from_nanos(since_last_refill.subsec_nanos() as u64);
            }

            if entry.count >= limit {
                if self.should_slip() {
                    context.rrl_action = Some(Action::Slip);
                    context.response.clear_rrs();
                    context.response.set_tc(true);
                } else {
                    context.rrl_action = Some(Action::Drop);
                    context.send_response = false;
                }
            } else {
                entry.count += 1;
                context.rrl_action = Some(Action::Send);
            }
        } else {
            // There is a hash collision. We forget the old entry.
            *entry = Entry {
                key,
                count: 1,
                last_refill: Instant::now(),
            };
            context.rrl_action = Some(Action::Send);
        }
    }

    /// Determines (randomly) whether to slip or drop a response.
    fn should_slip(&self) -> bool {
        if self.params.slip == 0 {
            false
        } else if self.params.slip == 1 {
            true
        } else {
            rand::thread_rng().gen_range(0..self.params.slip) == 0
        }
    }

    /// Converts an IP address into a [`u64`] used to represent the
    /// destination, first applying the configured netmask for the
    /// address family.
    fn ip_to_dest_u64(&self, ip: IpAddr) -> u64 {
        match ip {
            IpAddr::V4(ipv4) => (u32::from(ipv4) & self.params.ipv4_netmask) as u64,
            IpAddr::V6(ipv6) => ((u128::from(ipv6) >> 64) as u64) & self.params.ipv6_netmask,
        }
    }

    /// Based on the [`Rrl`]'s parameters, returns the maximum rate and
    /// the bucket count limit (the rate multiplied by the window) for a
    /// given [`Category`].
    fn rate_and_limit_for_category(&self, category: Category) -> (u32, u32) {
        match category {
            Category::NoError => (
                self.params.noerror_rate,
                self.params.noerror_rate * self.params.window,
            ),
            Category::NxDomain => (
                self.params.nxdomain_rate,
                self.params.nxdomain_rate * self.params.window,
            ),
            Category::Error => (
                self.params.error_rate,
                self.params.error_rate * self.params.window,
            ),
        }
    }
}

impl From<ExtendedRcode> for Category {
    fn from(rcode: ExtendedRcode) -> Self {
        match rcode {
            ExtendedRcode::NOERROR => Self::NoError,
            ExtendedRcode::NXDOMAIN => Self::NxDomain,
            _ => Self::Error,
        }
    }
}

/// Determines whether the response being prepared in `context` is
/// subject to RRL.
fn subject_to_rrl(context: &Context) -> bool {
    context.send_response
        && context.received_info.transport == Transport::Udp
        && context.received.opcode() == Opcode::Query
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_constructor_rejects_zero_args() {
        assert!(matches!(
            RrlParams::new(0, 1, 1, 1),
            Err(RrlParamError::NoerrorRateIsZero),
        ));
        assert!(matches!(
            RrlParams::new(1, 0, 1, 1),
            Err(RrlParamError::NxdomainRateIsZero),
        ));
        assert!(matches!(
            RrlParams::new(1, 1, 0, 1),
            Err(RrlParamError::ErrorRateIsZero),
        ));
        assert!(matches!(
            RrlParams::new(1, 1, 1, 0),
            Err(RrlParamError::WindowIsZero),
        ));
    }

    #[test]
    fn params_constructor_rejects_overflows() {
        assert!(matches!(
            RrlParams::new(2, 1, 1, u32::MAX),
            Err(RrlParamError::WindowIsTooLargeForRates),
        ));
        assert!(matches!(
            RrlParams::new(1, 2, 1, u32::MAX),
            Err(RrlParamError::WindowIsTooLargeForRates),
        ));
        assert!(matches!(
            RrlParams::new(2, 1, 2, u32::MAX),
            Err(RrlParamError::WindowIsTooLargeForRates),
        ));
    }

    #[test]
    fn set_ipv4_prefix_len_works() {
        let mut params = RrlParams::new(1, 1, 1, 1).unwrap();
        assert!(params.set_ipv4_prefix_len(0).is_ok());
        assert_eq!(params.ipv4_netmask, 0);
        assert!(params.set_ipv4_prefix_len(17).is_ok());
        assert_eq!(params.ipv4_netmask, 0xffff8000);
    }

    #[test]
    fn set_ipv4_prefix_len_rejects_long_prefixes() {
        let mut params = RrlParams::new(1, 1, 1, 1).unwrap();
        assert_eq!(
            params.set_ipv4_prefix_len(33),
            Err(RrlParamError::InvalidIpv4PrefixLen)
        );
    }

    #[test]
    fn set_ipv6_prefix_len_works() {
        let mut params = RrlParams::new(1, 1, 1, 1).unwrap();
        assert!(params.set_ipv6_prefix_len(0).is_ok());
        assert_eq!(params.ipv6_netmask, 0);
        assert!(params.set_ipv6_prefix_len(17).is_ok());
        assert_eq!(params.ipv6_netmask, 0xffff800000000000);
    }

    #[test]
    fn set_ipv6_prefix_len_rejects_long_prefixes() {
        let mut params = RrlParams::new(1, 1, 1, 1).unwrap();
        assert_eq!(
            params.set_ipv6_prefix_len(65),
            Err(RrlParamError::InvalidIpv6PrefixLen)
        );
    }

    #[test]
    fn set_size_rejects_zero() {
        let mut params = RrlParams::new(1, 1, 1, 1).unwrap();
        assert_eq!(params.set_size(0), Err(RrlParamError::SizeIsZero));
    }
}

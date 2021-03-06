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

//! Handling of DNS QUERY messages.

use arrayvec::ArrayVec;

use super::{Context, ProcessingError, ProcessingResult, Server, Transport};
use crate::class::Class;
use crate::message::{writer, Qclass, Qtype, Rcode, Writer};
use crate::name::Name;
use crate::rr::{Rdata, Rrset, RrsetList, Ttl, Type};
use crate::zone::{CatalogEntry, LookupAllResult, LookupResult, Zone};

impl Server {
    /// Handles a DNS message with opcode QUERY.
    pub(super) fn handle_query<'s>(&'s self, context: &mut Context<'s, '_>) {
        // If there is no question, then that's a FORMERR.
        let question = match context.question {
            Some(ref q) => q,
            None => {
                context.response.set_rcode(Rcode::FORMERR);
                return;
            }
        };

        // Currently, the only special QTYPE we handle is * (ANY).
        if matches!(
            question.qtype,
            Qtype::IXFR | Qtype::AXFR | Qtype::MAILB | Qtype::MAILA
        ) {
            context.response.set_rcode(Rcode::NOTIMP);
            return;
        }

        // We do not support QCLASS * (ANY).
        if question.qclass == Qclass::ANY {
            context.response.set_rcode(Rcode::NOTIMP);
            return;
        }

        // Find which zone (if any) in our catalog is the longest match
        // for the QNAME and QCLASS.
        let zone = match context
            .catalog
            .lookup(&question.qname, Class::from(question.qclass))
        {
            Some(CatalogEntry::Loaded(zone)) => zone,
            Some(CatalogEntry::NotYetLoaded(_, _) | CatalogEntry::FailedToLoad(_, _)) => {
                context.response.set_rcode(Rcode::SERVFAIL);
                return;
            }
            None => {
                context.response.set_rcode(Rcode::REFUSED);
                return;
            }
        };

        self.handle_non_axfr_query(zone, context);
    }

    /// Handles a non-AXFR DNS query.
    fn handle_non_axfr_query<'c>(&self, zone: &'c Zone, context: &mut Context<'c, '_>) {
        let question = context.question.as_ref().unwrap();
        let result = if question.qtype == Qtype::ANY {
            answer_any(zone, context)
        } else {
            answer(zone, context)
        };

        match result {
            Ok(()) => (),
            Err(ProcessingError::ServFail) => {
                context.response.set_aa(false);
                context.response.set_rcode(Rcode::SERVFAIL);
                context.response.clear_rrs();
            }
            Err(ProcessingError::Truncation) => {
                context.response.clear_rrs();
                if context.received_info.transport == Transport::Tcp {
                    // We can't ask the client to retry over TCP, since
                    // we are already over TCP.
                    context.response.set_aa(false);
                    context.response.set_rcode(Rcode::SERVFAIL);
                } else {
                    context.response.set_tc(true);
                }
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////
// ANSWERING LOGIC                                                    //
////////////////////////////////////////////////////////////////////////

/// Answers a query for a specific RR type once the appropriate zone to
/// search has been determined.
fn answer<'c>(zone: &'c Zone, context: &mut Context<'c, '_>) -> ProcessingResult<()> {
    let question = context.question.as_ref().unwrap();
    let qname = &question.qname;
    let rr_type = question.qtype.into();

    match zone.lookup(qname, rr_type) {
        LookupResult::Found(found) => {
            context.source_of_synthesis = found.source_of_synthesis;
            context.response.set_aa(true);
            context.response.add_answer_rrset(qname, found.rrset)?;
            do_additional_section_processing(zone, found.rrset, &mut context.response)
        }
        LookupResult::Cname(cname) => {
            context.source_of_synthesis = cname.source_of_synthesis;
            do_cname(zone, qname, cname.rrset, rr_type, &mut context.response)
        }
        LookupResult::Referral(referral) => do_referral(
            zone,
            referral.child_zone,
            referral.ns_rrset,
            &mut context.response,
        ),
        LookupResult::NoRecords(no_records) => {
            context.source_of_synthesis = no_records.source_of_synthesis;
            context.response.set_aa(true);
            add_negative_caching_soa(zone, &mut context.response)
        }
        LookupResult::NxDomain => {
            context.response.set_rcode(Rcode::NXDOMAIN);
            context.response.set_aa(true);
            add_negative_caching_soa(zone, &mut context.response)
        }
        LookupResult::WrongZone => panic!("tried to look up a name in the wrong zone"),
    }
}

/// Answers a query with QTYPE * (ANY) once the appropriate zone to
/// search has been determined.
fn answer_any<'c>(zone: &'c Zone, context: &mut Context<'c, '_>) -> ProcessingResult<()> {
    let question = context.question.as_ref().unwrap();
    let qname = &question.qname;

    match zone.lookup_all(qname) {
        LookupAllResult::Found(found) => {
            context.source_of_synthesis = found.source_of_synthesis;
            context.response.set_aa(true);
            let mut n_added = 0;
            for rrset in found.rrsets.iter() {
                context.response.add_answer_rrset(qname, rrset)?;
                n_added += 1;
            }
            if n_added == 0 {
                add_negative_caching_soa(zone, &mut context.response)?;
            }
            Ok(())
        }
        LookupAllResult::Referral(referral) => do_referral(
            zone,
            referral.child_zone,
            referral.ns_rrset,
            &mut context.response,
        ),
        LookupAllResult::NxDomain => {
            context.response.set_rcode(Rcode::NXDOMAIN);
            context.response.set_aa(true);
            add_negative_caching_soa(zone, &mut context.response)
        }
        LookupAllResult::WrongZone => panic!("tried to look up a name in the wrong zone"),
    }
}

////////////////////////////////////////////////////////////////////////
// ANSWERING LOGIC - CNAME HANDLING                                   //
////////////////////////////////////////////////////////////////////////

/// The maximum number of links in a CNAME chain that we will follow
/// before giving up and returning SERVFAIL.
///
/// By "links" we mean the number of CNAME records seen before reaching
/// the actual canonical name. For instance, the following answer shows
/// three links by our reckoning:
///
/// ```text
/// a.quandary.test.        3600    IN      CNAME   b.quandary.test.
/// b.quandary.test.        3600    IN      CNAME   c.quandary.test.
/// c.quandary.test.        3600    IN      CNAME   d.quandary.test.
/// d.quandary.test.        3600    IN      A       127.0.0.1
/// ```
const MAX_CNAME_CHAIN_LEN: usize = 8;

/// A fixed-capacity vector that can contain up to
/// [`MAX_CNAME_CHAIN_LEN`]???1 domain names.
///
/// As we follow a CNAME chain, we conceptually add the current owner
/// to a list of previously seen owners before we re-run the query with
/// the CNAME as the new owner. Each time we begin the lookup process
/// with a new owner, we check whether it was previously seen, to ensure
/// that there are no loops. Furthermore, in order not to follow more
/// than [`MAX_CNAME_CHAIN_LEN`] links in the chain, this list must not
/// exceed [`MAX_CNAME_CHAIN_LEN`] previous owners.
///
/// The [`PreviousOwners`] type is an [`ArrayVec`] that fulfills this
/// need, with one important difference from the conceptual list in the
/// last paragraph. Since [`do_cname`] is passed the original QNAME as
/// a `&Name`, not a `Box<Name>`, the QNAME (which would be the first
/// element added to the previous owners list) is considered separately.
/// To compensate, [`PreviousOwners`] actually has a capacity of
/// [`MAX_CNAME_CHAIN_LEN`]???1.
type PreviousOwners = ArrayVec<Box<Name>, { MAX_CNAME_CHAIN_LEN - 1 }>;

/// Follows a CNAME chain to produce an answer when there is CNAME RRset
/// present at QNAME.
///
/// At most [`MAX_CNAME_CHAIN_LEN`] links in a CNAME chain will be
/// processed before this gives up and signals to respond with SERVFAIL.
/// Additionally, loops in the chain will be detected and will trigger a
/// SERVFAIL.
fn do_cname(
    zone: &Zone,
    qname: &Name,
    cname_rrset: &Rrset,
    rr_type: Type,
    response: &mut Writer,
) -> ProcessingResult<()> {
    // RFC 6604 ?? 2.1 reiterates RFC 1035: the AA bit is set based on
    // the first owner name in the answer section. Thus, the AA bit
    // should be set here.
    response.set_aa(true);
    response.add_answer_rrset(qname, cname_rrset)?;
    follow_cname_1(zone, qname, cname_rrset, rr_type, response, ArrayVec::new())
}

/// Step 1 of the CNAME-following process. This includes parsing a
/// `Box<Name>` from the CNAME RRset and checking that the CNAME has not
/// already been looked up while processing the current chain.
fn follow_cname_1(
    zone: &Zone,
    qname: &Name,
    cname_rrset: &Rrset,
    rr_type: Type,
    response: &mut Writer,
    owners_seen: PreviousOwners,
) -> ProcessingResult<()> {
    if let Some(cname) = cname_rrset
        .rdatas()
        .next()
        .map(|rdata| Name::try_from_uncompressed_all(rdata.octets()))
        .and_then(Result::ok)
    {
        if cname.as_ref() == qname || owners_seen.contains(&cname) {
            // The CNAME chain contains a loop.
            Err(ProcessingError::ServFail)
        } else {
            follow_cname_2(zone, qname, cname, rr_type, response, owners_seen)
        }
    } else {
        Err(ProcessingError::ServFail)
    }
}

/// Step 2 of the CNAME-following process. This is the point where we
/// actually re-run the query with the CNAME as the new QNAME.
fn follow_cname_2(
    zone: &Zone,
    qname: &Name,
    cname: Box<Name>,
    rr_type: Type,
    response: &mut Writer,
    mut owners_seen: PreviousOwners,
) -> ProcessingResult<()> {
    // NOTE: RFC 1034 ?? 3.4.2 indicates that we should restart the query
    // from the very beginning, even going into other available zones.
    // (A possible motivation behind this instruction is the possibility
    // that we might provide recursive service.) This is *not* the
    // procedure that we follow. Rather, we re-run the query within the
    // original QNAME's zone. This appears to be the behavior of some
    // other authoritative servers, such as Knot.
    //
    // There is a good reason for this decision. Even if we did follow
    // a CNAME chain into another zone for which we are authoritative,
    // resolvers likely don't know that we are also authoritative for
    // that other zone. A smart resolver, therefore, won't trust any
    // records from the other zone that we might include. (See e.g. the
    // scrub_sanitize subroutine in Unbound.)
    match zone.lookup(&cname, rr_type) {
        LookupResult::Found(found) => {
            response.add_answer_rrset(&cname, found.rrset)?;
            do_additional_section_processing(zone, found.rrset, response)
        }
        LookupResult::Cname(next_cname) => {
            // The CNAME chain continues. If the CNAME chain is getting
            // too long, we refuse to go any further; otherwise we
            // restart the CNAME-following process with the next CNAME
            // in the chain.
            if owners_seen.is_full() {
                Err(ProcessingError::ServFail)
            } else {
                response.add_answer_rrset(&cname, next_cname.rrset)?;
                owners_seen.push(cname);
                follow_cname_1(
                    zone,
                    qname,
                    next_cname.rrset,
                    rr_type,
                    response,
                    owners_seen,
                )
            }
        }
        LookupResult::Referral(referral) => {
            do_referral(zone, referral.child_zone, referral.ns_rrset, response)
        }
        // Per RFC 6604 ?? 3, the RCODE is set based on the last query
        // cycle. Therefore, the no-records case should be NOERROR and
        // the nonexistent-name case should be NXDOMAIN. Note that this
        // seems to be a change from RFC 1034 ?? 3.4.2, whose step 3(c)
        // calls for an authoritative name error (NXDOMAIN) only when
        // the failed lookup is for the original QNAME.
        LookupResult::NoRecords(_) => add_negative_caching_soa(zone, response),
        LookupResult::NxDomain => {
            response.set_rcode(Rcode::NXDOMAIN);
            add_negative_caching_soa(zone, response)
        }
        LookupResult::WrongZone => Ok(()),
    }
}

////////////////////////////////////////////////////////////////////////
// ANSWERING LOGIC - REFERRAL HANDLING                                //
////////////////////////////////////////////////////////////////////////

/// Creates a referral response.
///
/// When a lookup would take us out of authoritative data (that is,
/// when we reach a non-apex node with an NS RRset), [RFC 1034 ?? 4.3.2]
/// instructs us to create a referral response. This involves copying
/// the NS RRset into the authority section and available addresses for
/// the nameservers specified by the NS records into the additional
/// section.
///
/// [RFC 1034 ?? 4.3.2]: https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.2
fn do_referral(
    parent_zone: &Zone,
    child_zone: &Name,
    ns_rrset: &Rrset,
    response: &mut Writer,
) -> ProcessingResult<()> {
    response.add_authority_rrset(child_zone, ns_rrset)?;

    // Now, we *must* include glue records; otherwise the delgation
    // would not work. If glue records do not fit, we fail (and allow
    // upstream error-handling code to send a response with the TC bit
    // set).
    //
    // Additionally, we *try* to include any other nameserver addresses
    // that are available within the parent zone's hierarchy, including
    // so-called "sibling glue" (glue records in *another* zone
    // delegated from the same parent zone). If they don't fit, we just
    // don't include them.
    //
    // TODO: the "DNS Referral Glue Requirements" Internet Draft is
    // relevant here. Depending on how it turns out, we may need to
    // change our policies. The latest draft as of this writing is draft
    // 4, in which ?? 3.2 states that sibling glue is NOT REQUIRED to
    // be included if it does not fit???an allowance that we make use of
    // here.
    let mut glues = Vec::new();
    let mut additionals = Vec::new();
    for rdata in ns_rrset.rdatas() {
        let nsdname = read_name_from_rdata(rdata, 0)?;
        if nsdname.eq_or_subdomain_of(child_zone) {
            glues.push(nsdname);
        } else {
            additionals.push(nsdname);
        }
    }
    for nsdname in glues {
        add_referral_additional_addresses(parent_zone, &nsdname, response)?;
    }
    for nsdname in additionals {
        execute_allowing_truncation(|| {
            add_referral_additional_addresses(parent_zone, &nsdname, response)
        })?;
    }
    Ok(())
}

/// Looks up `name` in `zone`, *including in non-authoritative data*,
/// and adds any address (A or AAAA) RRsets found to the additional
/// section of `response`. Note that, on error, some of the addresses
/// may have been successfully written.
fn add_referral_additional_addresses(
    parent_zone: &Zone,
    name: &Name,
    response: &mut Writer,
) -> writer::Result<()> {
    if let LookupAllResult::Found(found) = parent_zone.lookup_all_raw(name, false) {
        add_additional_address_rrsets(name, found.rrsets, response)
    } else {
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////
// HELPERS - ADDITIONAL SECTION PROCESSING                            //
////////////////////////////////////////////////////////////////////////

/// Performs "additional section processing," if any, for the given
/// RRset.
///
/// For certain RR types, RFCs 1034 and 1035 call for "additional
/// section processing," in which any available A records for domain
/// names embedded in the RDATA are included in the additional section
/// of the response. The goal is to reduce the number of queries a
/// resolver must make by preemptively including address information
/// that will very likely be needed next. Some later RFCs defining new
/// RR types (e.g. [RFC 2782] for SRV) also ask for this behavior. With
/// the advent of IPv6, [RFC 3596] includes AAAA records for IPv6
/// addresses in additional section processing as well.
///
/// Any address records are considered extra information, and should be
/// omitted if there is insufficent room (see [RFC 2181 ?? 9]). In
/// practice, some servers have "minimal responses" configuration
/// options that disable additional section processing altogether.
///
/// [RFC 2782]: https://datatracker.ietf.org/doc/html/rfc2782
/// [RFC 2181 ?? 9]: https://datatracker.ietf.org/doc/html/rfc2181#section-9
fn do_additional_section_processing(
    zone: &Zone,
    rrset: &Rrset,
    response: &mut Writer,
) -> ProcessingResult<()> {
    match rrset.rr_type {
        Type::MB | Type::MD | Type::MF | Type::NS => {
            for rdata in rrset.rdatas() {
                let name = read_name_from_rdata(rdata, 0)?;
                execute_allowing_truncation(|| add_additional_addresses(zone, &name, response))?;
            }
        }
        Type::MX => {
            for rdata in rrset.rdatas() {
                let name = read_name_from_rdata(rdata, 2)?;
                execute_allowing_truncation(|| add_additional_addresses(zone, &name, response))?;
            }
        }
        Type::SRV => {
            for rdata in rrset.rdatas() {
                let name = read_name_from_rdata(rdata, 6)?;
                execute_allowing_truncation(|| add_additional_addresses(zone, &name, response))?;
            }
        }
        _ => (),
    };
    Ok(())
}

/// Looks up `name` in `zone` and adds any address (A or AAAA) RRsets
/// found to the additional section of `response`. Note that, on error,
/// some of the addresses may have been successfully written.
fn add_additional_addresses(zone: &Zone, name: &Name, response: &mut Writer) -> writer::Result<()> {
    if let LookupAllResult::Found(found) = zone.lookup_all(name) {
        add_additional_address_rrsets(name, found.rrsets, response)
    } else {
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////
// HELPERS - NEGATIVE CACHING SOA (RFC 2308 ?? 3)                      //
////////////////////////////////////////////////////////////////////////

/// Adds the SOA record from `zone` to the authority section of
/// `response` for negative caching [RFC 2308 ?? 3].
///
/// [RFC 2308 ?? 3]: https://datatracker.ietf.org/doc/html/rfc2308#section-3
fn add_negative_caching_soa(zone: &Zone, response: &mut Writer) -> ProcessingResult<()> {
    // Note that per RFC 2308 ?? 3, the TTL we are to use is not the TTL
    // of the SOA record itself, but rather the SOA MINIMUM field.
    let soa_rrset = zone.soa().ok_or(ProcessingError::ServFail)?;
    let soa_rdata = soa_rrset.rdatas().next().ok_or(ProcessingError::ServFail)?;
    let ttl = Ttl::from(read_soa_minimum(soa_rdata)?);
    response
        .add_authority_rr(
            zone.name(),
            soa_rrset.rr_type,
            soa_rrset.class,
            ttl,
            soa_rdata,
        )
        .map_err(Into::into)
}

/// Reads the MINIMUM field from the provided SOA RDATA.
fn read_soa_minimum(rdata: &Rdata) -> ProcessingResult<u32> {
    let mname_len =
        Name::validate_uncompressed(rdata.octets()).or(Err(ProcessingError::ServFail))?;
    let rname_len = Name::validate_uncompressed(&rdata.octets()[mname_len..])
        .or(Err(ProcessingError::ServFail))?;
    let octets = rdata
        .octets()
        .get(mname_len + rname_len + 16..)
        .ok_or(ProcessingError::ServFail)?;
    let array: [u8; 4] = octets.try_into().or(Err(ProcessingError::ServFail))?;
    Ok(u32::from_be_bytes(array))
}

////////////////////////////////////////////////////////////////////////
// HELPERS - MISCELLEANEOUS                                           //
////////////////////////////////////////////////////////////////////////

/// A helper that adds A and AAAA RRsets in `rrsets` to the additional
/// section of `response`. On error (including truncation), note that some
/// addresses may have been successfully written.
fn add_additional_address_rrsets(
    name: &Name,
    rrsets: &RrsetList,
    response: &mut Writer,
) -> writer::Result<()> {
    for rrset in rrsets.iter() {
        if rrset.rr_type == Type::A || rrset.rr_type == Type::AAAA {
            response.add_additional_rrset(name, rrset)?;
        }
    }
    Ok(())
}

/// Executes `f`, without returning an error if `f` itself fails with
/// [`writer::Error::Truncation`]. On success, this returns `Ok(true)`
/// if truncation occurred and `Ok(false)` if not.
fn execute_allowing_truncation(f: impl FnOnce() -> writer::Result<()>) -> writer::Result<bool> {
    match f() {
        Err(writer::Error::Truncation) => Ok(true),
        result => result.and(Ok(false)),
    }
}

/// Reads a serialized domain name from `rdata`, starting at `start` and
/// running to the end of `rdata`.
fn read_name_from_rdata(rdata: &Rdata, start: usize) -> ProcessingResult<Box<Name>> {
    rdata
        .octets()
        .get(start..)
        .map(Name::try_from_uncompressed_all)
        .and_then(Result::ok)
        .ok_or(ProcessingError::ServFail)
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::GluePolicy;

    ////////////////////////////////////////////////////////////////////
    // CNAME-FOLLOWING TESTS                                          //
    ////////////////////////////////////////////////////////////////////

    #[test]
    fn cname_handling_rejects_loops() {
        let mut zone = new_zone();
        add_cname_to_zone(&mut zone, 'a', 'b');
        add_cname_to_zone(&mut zone, 'b', 'a');
        test_cname(zone, new_name('a'), Err(ProcessingError::ServFail));
    }

    #[test]
    fn cname_handling_allows_almost_too_long_chains() {
        let mut zone = new_zone();
        make_chain(&mut zone, MAX_CNAME_CHAIN_LEN);
        test_cname(zone, new_name('a'), Ok(()));
    }

    #[test]
    fn cname_handling_rejects_long_chains() {
        let mut zone = new_zone();
        make_chain(&mut zone, MAX_CNAME_CHAIN_LEN + 1);
        test_cname(zone, new_name('a'), Err(ProcessingError::ServFail));
    }

    fn test_cname(zone: Zone, owner: Box<Name>, expected_result: ProcessingResult<()>) {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(&mut buf[..]).unwrap();
        let cname_rrset = match zone.lookup(&owner, Type::CNAME) {
            LookupResult::Found(found) => found.rrset,
            _ => panic!(),
        };
        assert_eq!(
            do_cname(&zone, &owner, cname_rrset, Type::A, &mut writer),
            expected_result
        );
    }

    fn make_chain(zone: &mut Zone, len: usize) {
        let owners = ('a'..'z').collect::<Vec<char>>();
        for i in 0..len {
            add_cname_to_zone(zone, owners[i], owners[i + 1]);
        }
    }

    fn new_zone() -> Zone {
        let apex: Box<Name> = "quandary.test.".parse().unwrap();
        let rdata = <&Rdata>::try_from(&[0; 22]).unwrap();
        let mut zone = Zone::new(apex.clone(), Class::IN, GluePolicy::Narrow);
        zone.add(&apex, Type::SOA, Class::IN, Ttl::from(0), rdata)
            .unwrap();
        zone
    }

    fn new_name(owner: char) -> Box<Name> {
        (owner.to_string() + ".quandary.test.").parse().unwrap()
    }

    fn add_cname_to_zone(zone: &mut Zone, owner: char, target: char) {
        let owner = new_name(owner);
        let target = new_name(target);
        let rdata = <&Rdata>::try_from(target.wire_repr()).unwrap();
        zone.add(&owner, Type::CNAME, Class::IN, Ttl::from(0), rdata)
            .unwrap();
    }
}

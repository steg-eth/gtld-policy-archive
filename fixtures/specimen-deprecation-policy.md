# Specimen deprecation policy

**This document is a test fixture. It is not a real deprecation policy, it does not describe a
real registry operator, and no gTLD has adopted it.** It exists to give the policy archival tool a
real document at a real URL, published under a DNSSEC signed TXT record, so that the fetch, the
hash comparison and the archive write can be demonstrated end to end.

The structure follows the four commitments and the four capacity fronts set out in
[t/22020 #6](https://discuss.ens.domains/t/temp-check-authorize-tldminter-as-root-controller/22020/6).
Nothing here is a proposal. The requirements that a real policy must meet are a governance
question for the ENS DAO, and they are not set by this document.

- **Specimen version:** 1
- **Published:** 6 November 2026
- **Applies to:** a hypothetical TLD operated by a hypothetical operator
- **Supersedes:** nothing

---

## 1. Notice and timeline

The operator gives public notice before it stops operating the alternative naming integration for
the TLD. The notice period is 24 months. The notice is published at this URL and announced in the
TLD's own zone with a TXT record at `_ens.nic.<tld>`.

The timeline has three dates. The notice date is when the operator publishes its intent to stop.
The freeze date is 12 months after the notice date, and after it the operator makes no new
registrations in the alternative system. The end date is 24 months after the notice date, and
after it the operator runs no integration service.

The operator does not shorten any of the three periods. The operator can extend them, and it
publishes a new version of this document when it does.

## 2. Successor

The operator names a successor before the freeze date. The successor is an organisation that
agrees in writing to take the integration, and that meets the capacity bar in the second half of
this document.

If the operator names no successor by the freeze date, the operator says so in a new version of
this document, and the ENS DAO can treat the integration as unsuccessed from that date.

The successor's control is proved the same way the operator's control was proved. The successor
publishes its own address in the TLD's `_ens` record, signed by the TLD's own DNSSEC keys. No
off-chain assertion transfers control.

## 3. User migration

Every name registered through the integration keeps resolving until the end date.

The operator publishes a machine-readable list of every name it registered through the
integration, at the notice date and again at the freeze date. The list carries the name, the
controller, and the date of registration.

The operator does not charge a fee for a user to leave the integration, at any point between the
notice date and the end date.

## 4. Governance

The operator publishes a new version of this document when any commitment in it changes. Each
version carries a version number and a date, and the operator keeps every earlier version
reachable at a stable URL.

The hash of the current version is published in the TLD's `_ens` record as `policy_hash`. The
operator updates that record in the same change that publishes a new version.

A dispute about whether the operator has met a commitment is a matter for the ENS DAO's own
process. This document creates no private right of action and no arbitration forum.

---

## Organisational capacity

### Funding and runway

The operator holds funds sufficient to run the integration for the full 24 month notice period
without new revenue, and it states the basis for that figure.

### Operational posture

The operator runs the integration with documented procedures for key management, incident
response and succession. The procedures name roles rather than individuals.

### Identity and governance

The operator is a legal entity with a published jurisdiction, a published registered address, and
a governing body that is identifiable from public records.

### Track record and standing

The operator states how long it has operated the TLD, and whether it has been subject to a
termination, a transition to an emergency back-end registry operator, or a redelegation.

---

## What this specimen does not do

It does not define what counts as reasonable for any of the eight fronts above. Those thresholds
are policy, they belong to the ENS DAO and to the Foundation, and they are the open question this
fixture is meant to support rather than answer.

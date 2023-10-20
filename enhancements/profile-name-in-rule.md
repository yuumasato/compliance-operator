---
title: profile-name-in-rule
authors:
  - Vincent056
reviewers: # Include a comment about what domain expertise a reviewer is expected to bring and what area of the enhancement you expect them to focus on. For example: - "@networkguru, for networking aspects, please look at IP bootstrapping aspect"
  - TBD
approvers:
  - TBD
api-approvers: # In case of new or modified APIs or API extensions (CRDs, aggregated apiservers, webhooks, finalizers). If there is no API change, use "None"
  - TBD
creation-date: 2023-08-29
last-updated: yyyy-mm-dd
tracking-link: # link to the tracking ticket (for example: Jira Feature or Epic ticket) that corresponds to this enhancement
  - TBD
see-also:
  - "/enhancements/this-other-neat-thing.md"
replaces:
  - "/enhancements/that-less-than-great-idea.md"
superseded-by:
  - "/enhancements/our-past-effort.md"
---

# Profile Name in Rule

## Summary

Let's add `Profile Name` to the `Rule` (CRD) as an annotation so it's easier 
for users to know the rule is used in what profiles.

## Motivation

Currently, the `Rule` CRD does not contain any Profile name information.
This makes it difficult for users to know what profiles are using this rule.

### Goals

There are two main goals of this enhancement.

1. Determine where to add the `Profile Name` property in the `Rule`
   CRD.
2. Determine how to populate the `Profile Name` property in the `Rule` CRD.

### Non-Goals

This enhancement does not have any non-goals.

## Proposal

Steps:
1. At end of profile parsers parsing, gather all profile objects and find out what rules are used in what profiles
2. Generate a lookup table for rule name to profile name list
3. For each rule, we add a new annotation called `compliance.openshift.io/profiles` to the `Rule` CRD and use the lookup table to populate the value

example of the Rule CRD with the profile name annotation:

```yaml
instructions: |-
  For each pod in the cluster, review the pod specification and
  ensure that pods that do not need to explicitly communicate with
  the API server have automountServiceAccountToken
  configured to false.
metadata:
  annotations:
    compliance.openshift.io/image-digest: pb-ocp4rzfcz
    compliance.openshift.io/rule: accounts-restrict-service-account-tokens
    control.compliance.openshift.io/CIS-OCP: 5.1.6
    control.compliance.openshift.io/NERC-CIP: CIP-003-8 R6;CIP-004-6 R3;CIP-007-3 R6.1
    control.compliance.openshift.io/NIST-800-53: CM-6;CM-6(1)
    control.compliance.openshift.io/PCI-DSS: Req-2.2
    policies.open-cluster-management.io/controls: 'CIP-003-8 R6,CIP-004-6 R3,CIP-007-3 R6.1,CM-6,CM-6(1),Req-2.2,5.1.6'
    policies.open-cluster-management.io/standards: 'NERC-CIP,NIST-800-53,PCI-DSS,CIS-OCP'
    compliance.openshift.io/profiles: ocp4-cis,ocp4-nerc-cip,ocp4-pci-dss,ocp4-moderate,ocp4-high
  name: ocp4-accounts-restrict-service-account-tokens
  namespace: openshift-compliance
  labels:
    compliance.openshift.io/profile-bundle: ocp4
kind: Rule
rationale: >-
  Mounting service account tokens inside pods can provide an avenue for
  privilege escalation attacks where an attacker is able to compromise a single
  pod in the cluster.
title: Restrict Automounting of Service Account Tokens
id: xccdf_org.ssgproject.content_rule_accounts_restrict_service_account_tokens
description: >-
  Service accounts tokens should not be mounted in pods except where the
  workload running in the pod explicitly needs to communicate with the API
  server. To ensure pods do not automatically mount tokens, set
  automountServiceAccountToken to false.
severity: medium
apiVersion: compliance.openshift.io/v1alpha1
```

### User Stories

1. As a cluster administrator, I want to see what profiles are using a specific rule
2. As a cluster administrator, I want to be able to see what rules are used by a given profile.
   This is already covered by current implementation 
3. As a cluster administrator, I want to be able to see all rules that are not being used in any profiles.



### API Extensions

This enhancement does not require any API changes.


### Implementation Details/Notes/Constraints [optional]

What are the caveats to the implementation? What are some important details that
didn't come across above. Go in to as much detail as necessary here. This might
be a good place to talk about core concepts and how they relate.

### Risks and Mitigations

What are the risks of this proposal and how do we mitigate. Think broadly. For
example, consider both security and how this will impact the larger OKD
ecosystem.

How will security be reviewed and by whom?

How will UX be reviewed and by whom?

Consider including folks that also work outside your immediate sub-project.

## Design Details

### Open Questions [optional]

1. Is `compliance.openshift.io/profiles` a good annotation name?
2. What happens if users annotate a rule with a Profile?
   We don't prevent users from doing that, but we should document what we use
   the annotation and stop users from annotating rules with that annotation key.

### Test Plan

**Note:** *Section not required until targeted at a release.*

Consider the following in developing a test plan for this enhancement:
- Will there be e2e and integration tests, in addition to unit tests?
- How will it be tested in isolation vs with other components?

No need to outline all of the test cases, just the general strategy. Anything
that would count as tricky in the implementation and anything particularly
challenging to test should be called out.

All code is expected to have adequate tests (eventually with coverage
expectations).

### Upgrade / Downgrade Strategy

We do not expect any upgrade or downgrade issues with this enhancement.

### Version Skew Strategy

Not applicable to this particular enhancement given the Compliance Operator is
a single installation within a single cluster.

### Operational Aspects of API Extensions

This enhancement does not require any API changes.

#### Failure Modes

Any failure with this enhancement during the profile parsing phase will block
the user from using the Compliance Operator.

#### Support Procedures

This enhancement does not require any support procedures.

## Implementation History

Major milestones in the life cycle of a proposal should be tracked in `Implementation
History`.

1. Only the ProfileBundle information is available in the `Rule` CRD
2. Implement the new feature, and add the profile name information to the `Rule` CRD as an annotation
3. Add a CI end-to-end test that fails if a rule does not contain the correct profile name information
4. Document the meaning of new annotation `compliance.openshift.io/profiles` in the `Rule` CRD

## Drawbacks

No current drawbacks.

## Alternatives

No current alternatives, short of not supplying a solution for users.

## Infrastructure Needed [optional]

CI resources for the Compliance Operator and content testing, similar to what
we rely on today for CI.
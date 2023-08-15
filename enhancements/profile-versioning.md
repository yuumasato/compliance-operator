---
title: profile-versioning
authors:
  - rhmdnd
reviewers: # Include a comment about what domain expertise a reviewer is expected to bring and what area of the enhancement you expect them to focus on. For example: - "@networkguru, for networking aspects, please look at IP bootstrapping aspect"
  - TBD
approvers:
  - TBD
api-approvers: # In case of new or modified APIs or API extensions (CRDs, aggregated apiservers, webhooks, finalizers). If there is no API change, use "None"
  - TBD
creation-date: 2023-08-15
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

# Profile Versioning

## Summary

Let's add a `version` attribute to the `Profile` custom resource definition
(CRD) so it's easier for users to know which profile they're using.

## Motivation

Currently, the `Profile` CRD does not contain version information about the
benchmark it implements. This makes it difficult for users to know which
version of benchmark they are using. For example, the Compliance Operator
supports profiles for CIS OpenShift, but it does not have an attribute for
which version of the benchmark it supports, like 1.0.0, 1.1.0, 1.2.0, 1.3.0, or
1.4.0. One common work around is to put the benchmark version in the
`description` property. This is not ideal, since it's harder for machines to
parse version information from descriptions, assuming it is even there.

Providing a `version` property as a first-class attribute will make it easier
for end users to know which profile they are using, and unlocks potential
features that reason about profile differences between versions.

### Goals

Profile versioning can be a complex topic. For example, how should we support
profiles with multiple versions? Should we support versions that allow users to
determine profile changes between operator releases?

Because we don't know the answer to some of these questions, we're going to
break the work into phases that allow us to deliver profile versioning
incrementally. The following goals describe the overall goals of a versioning implementation:

1. Determine where and how to implement the `version` property in the `Profile` CRD.
2. Add a initial version for each profile

### Non-Goals

1. Implement the ability to automatically version profiles based on their
   content (e.g., CIS OpenShift `1.4.0-12-b1166b1e`)

The reason for this is that addressing the non-goals above are non-trivial and
require signficant changes to the Compliance Operator and the
[ComplianceAsCode/content](https://github.com/ComplianceAsCode/content) build
system. Until we have feedback from users, we can defer these goals, and
deliver a mechanism that's simpler.

## Proposal

Steps:
1. Add a `version` string attribute to the `Profile` CRD
2. Version each currently supported profile
3. Update profile parsers to parse versions from content data stream, and persist version in `Profile` CRD

The [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content)
project allows contributors to version profiles using the `metadata.version`
attribute of the profile file. During the content build process, this version
is populated in the data stream.

The Compliance Operator profile parser will look for this attribute in the data
stream while it processes the content at installation time. If a profile in the
data stream contains `metadata.version`, the profile parser will persist the
`Profile` CRD with a version attribute set.

Because the profile version is ultimately coming from the content, we need to
have a process or automation in place to ensure the profile version is accurate
across releases.

### User Stories

1. As a cluster administrator, I want to be able to see the version of a
   particular profile supported by the Compliance Operator.
2. As a cluster administrator, I want to be able to scan my cluster against a
   particular version of a profile.
3. As a cluster administrator, I want to be able to opt into having the latest
   benchmark scanning my cluster at all times.

### API Extensions

This enhancement focuses solely on adding a version to the `Profile` CRD,
either through a formal attribute, label, or annotation. No other resources
will be modified as a result of this implementation.

The implementation should be backwards compatible so that if a profile does not
have a version in the data stream, the resulting `Profile` resource will have
an empty value for `version`.

### Version Evaluation

Profile version semantics should follow [semantic versioning
v2.0.0](https://semver.org/spec/v2.0.0.html), where the upstream standard
version allows. Some catalogs don't follow semantic versioning. A summary of
the differences between version 1.0.0 and 2.0.0 are available in a [GitHub
issue](https://github.com/semver/semver/issues/231).

This would allow us to use the following strings to represent profile versions:

* `1.2.0` being the most basic form of versions we see in compliance benchmarks
* `1.2.0-1` includes flexibility to denote differences across the same profile version
* `1.2.0-1+e076b1d7ac` include the content of the profile as a SHA

Initially, we may choose to only implement simple versions (e.g., 1.2.0, or
4.0.0). Depending on user feedback, we have the option to include support for
more complex version strings that use pre-release or build metadata within the
semantic version specification to denote changes to a profile between operator
releases. If we do decide to support pre-release or build metadata as part of
the version string, we should ensure version string evaluation considers
`1.2.0` older than `1.2.0-1` or `1.2.0-2+e076b1d7ac`. This detail will be
covered in a future enhancement if we decide to implement granular profile
versions, as noted in the non-goals section above.

Note that we can't strictly enforce semantic versioning because the version is
ultimately set by the authoring body of the standard (e.g., NIST SP 800-53 is
versioned using `Revision $INT`, which doesn't meet strict semantic versioning
guidance).

### Implementation Details/Notes/Constraints [optional]

There are two considerations for how versions interact with profiles.

The first is if there is only one profile, and it has a single version. For
example, supporting the CIS OpenShift 1.4.0 benchmark. The second is if there
is a single profile, but multiple versions. For example, PCI-DSS version 3.2.1
and version 4.0.0.

#### Single Profile & Single Version

This case can be implemented in the following steps:

1. Associate a version to the profile in
   [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content)
   using the `metadata.version` attribute of the profile
2. Update the operator's profile parser to parse the version from the data
   stream, and set the appropriate attribute on the `Profile` custom resource

This will look similar to the following after the profiles are parsed by the
operator on start-up:

```console
$ oc get profiles.compliance
NAME                             AGE   VERSION
ocp4-cis                         21s   1.4.0
ocp4-cis-node                    22s   1.4.0
ocp4-pci-dss                     21s   3.2.1
ocp4-pci-dss-node                21s   3.2.1
```

Profiles in the
[ComplianceAsCode/content](https://github.com/ComplianceAsCode/content) that do
not have a `metadata.version`, will not have that attribute set in the
`Profile` custom resource (using `ocp4-nerc-cip` purely as an example below):

```console
$ oc get profiles.compliance
NAME                             AGE   VERSION
ocp4-cis                         21s   1.4.0
ocp4-cis-node                    22s   1.4.0
ocp4-e8                          21s
ocp4-pci-dss                     21s   3.2.1
ocp4-pci-dss-node                21s   3.2.1
rhcos4-e8                        11s
```

#### Single Profile & Multiple Versions

The operator must account for cases where a profile has multiple versions.

Due to limitations of the data stream, each profile can only have one version.
Additionally, there can only be one profile using a given name in the data
stream.

The operator can expose multiple versions for a single profile using the following approach:

1. Version each profile to the initially supported version, keeping the profile name the same
2. When a new version is released, implement it using the versionless profile named
3. Implement a new profile for the older version under a new name

For example, this would look like the following in practice:

1. Version the current CIS OpenShift benchmark at version 1.4.0
2. When version 1.5.0 is implemented, move version 1.4.0 to a new profile named `ocp4-cis-1.4.0`)
3. Create a new profile named `ocp4-cis-1.5.0`
4. Release the operator with `ocp4-cis` as version 1.5.0, so that the versionless name always references the latest version

Users that want to pin to the latest version of a profile can do so with the
latest versioned release of a profile (e.g., `ocp4-cis-1.5.0`). This will
prevent them from automatically adopting the CIS 1.6.0 version profile when
that is released. However, if they want an automatic update of the profile
content, the can use the `ocp4-cis` profile, which will always point to the
latest version of a profile.

```console
$ oc get profiles.compliance
NAME                             AGE   VERSION
ocp4-cis                         21s   1.5.0
ocp4-cis-node                    22s   1.5.0
ocp4-cis-1.4.0                   21s   1.4.0
ocp4-cis-node-1.4.0              22s   1.4.0
ocp4-cis-1.5.0                   21s   1.5.0
ocp4-cis-node-1.5.0              22s   1.5.0
ocp4-e8                          21s
ocp4-pci-dss                     21s   3.2.1
ocp4-pci-dss-node                21s   3.2.1
rhcos4-e8                        11s
```

This approach gives user the ability to roll forward with new versions of a
profile, while providing the flexibility to pin to specific versions of release
profiles.

From a [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content)
perspective, the profiles are completely separate.

Users should be able to create a `ScanSettingBinding` without specifying a version:

```yaml
---
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSettingBinding
metadata:
  name: cis
  namespace: openshift-compliance
profiles:
  - name: ocp4-cis
    kind: Profile
    apiGroup: compliance.openshift.io/v1alpha1
  - name: ocp4-cis-node
    kind: Profile
    apiGroup: compliance.openshift.io/v1alpha1
settingsRef:
  name: default
  kind: ScanSetting
  apiGroup: compliance.openshift.io/v1alpha1
```

This will result in the scan using the latest version of a benchmark. This is
the default behavior that the Compliance Operator exposes today, where updates
to profiles are always rolled forward. This behavior must be explicitly
documented, even though it was the default prior to supporting multiple
versions.

However, users have the ability to reference a specific scan name to scan using
an older version of the profile.

```yaml
---
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSettingBinding
metadata:
  name: cis
  namespace: openshift-compliance
profiles:
  - name: ocp4-cis-1.4.0
    kind: Profile
    apiGroup: compliance.openshift.io/v1alpha1
  - name: ocp4-cis-node-1.4.0
    kind: Profile
    apiGroup: compliance.openshift.io/v1alpha1
settingsRef:
  name: default
  kind: ScanSetting
  apiGroup: compliance.openshift.io/v1alpha1
```

The above binding would only run scans using the `ocp4-cis-1.4.0` profile.

#### Immutability

By default, the `version` attribute, label, or annotation of a `Profile` should
be owned by the operator, which is responsible for parsing the data stream. At
this point, we're not going to support users setting, or overriding, the
profile version.

### Risks and Mitigations

Contributors updating profile content will need to be mindful of the profile
version they're implementing. Failure to update the version of a profile will
result in new content being delivered in an version. While this isn't riskier
than anything we do today, it will be misleading for users.

## Design Details

### Open Questions [optional]

1. What happens when a `Profile` extended by a `TailoredProfile` changes?

Users can now extend an older version of a profile, but this profile won't
receive updates or new features. Users extending a versionless profile name
will always be extending the latest version, which is how `TailoredProfiles`
work today.

### Test Plan

We can thoroughly test the goals outlined in this enhancement with the existing
end-to-end testing. The tests don't necessarily need to assert a `Profile` is a
particular version, just that the version string is populated.

For testing profile versioning on upgrade, we can do the following:

1. Install the Compliance Operator at version `N`, which includes a profile at version `M`
2. Create a `ScanSettingBinding` with `profileName`
3. Assert the scan uses the latest version of the profile `M` (ensure versionless profile names resolve to the latest profile version)
4. Create a separate `ScanSettingBinding` with `profileName-M`, where `M` is the latest supported version
5. Assert the scan uses the latest version of the profile `M` when pinned
6. Upgrade the Compliance Operator to version `N+1`, which includes a profile at version `M+1`
7. Assert `ScanSettingBinding` with `profileName` points to `M+1` (ensure the rolling update worked)
8. Assert the `ScanSettingBinding` with `profileName-M` points to version `M` of the profile (ensure pinning worked)

### Upgrade / Downgrade Strategy

The Compliance Operator currently supports upgrades, where fixes are rarely, if
ever, backported. Due to this, the Compliance Operator does not support
downgrades. The operator will upgrade automatically if configured to do so. To
best support users, the upgrade to a version of the Compliance Operator with
this enhancement must do one of two things.

1. Version all supported profiles and make `version` a required property of the `Profile` CRD
2. Make `version` an optional property, and version profiles incrementally

In either case, it is expected that user can gracefully upgrade to a release of
the Compliance Operator that includes this enhancement.

Once a profile is versioned, it is expected to remain versioned for its life
cycle. This expectation matches reality, where profiles are versiond in some
way from an authoring body (e.g., PCI-DSS 3.2.1 to 4.0.0, or CIS OpenShift
1.3.0 to 1.4.0).

### Version Skew Strategy

Not applicable to this particular enhancement given the Compliance Operator is
a single installation within a single cluster.

### Operational Aspects of API Extensions

Operational impact on this change should be minimal considering the profiles
need to be parsed regardless, and this change is limited to setting one
additional property on a CRD.

The compliance content shipped with the Compliance Operator by default may
change, which will still be true with this enhancement. Users should expect to
use `Profile` CRDs in the same way they have in the past.

#### Failure Modes

The `Profile` version attribute should be optional. This will ensure that
profiles without a version are not required to have one when the content is
parsed by the operator. If and when the profile is versioned, it will
automatically advertise the version upon upgrade of the Compliance Operator.

#### Support Procedures

In the case above, users supplying their own content must ensure they're
setting the profile version in the data stream. Otherwise, they will not be
able to use custom content with the compliance operator.

Verbose logging will be added to the profile parser to detail the `Profile`
CRDs being created, and the versions parsed from the data stream so these
failure scenarios are traceable, and easy to detect.

## Implementation History

Major milestones in the life cycle of a proposal should be tracked in `Implementation
History`.

1. Update each profile version for OpenShift profiles in [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content)
2. Implement a new property called `version` for the `Profile` CRD
3. Add a CI end-to-end test that fails if a profile does not contain a `version`
4. Document profile life cycles across content and the operator, including versioning

## Drawbacks

A potential drawback is how to best maintain versions across profiles, or if
single profiles should have multiple versions. These questions will come with
additional maintenance cost for existing compliance content.

To counter this, the `version` property should at the very least match the
benchmark, as noted in the goals section above. In more complicated scenarios,
the version could be expanded to handle changes between content, making it
easier for users to see changes between Compliance Operator updates. In this
case, version evaluation should be backwards compatible (e.g., `1.4.0` is older
than `1.4.0-1`), which can be addressed in a subsequent enhancement.

## Alternatives

An alternative to this versioning proposal is to have the `Profile` CRD support
multiple versions of the same profile, with a list of versions. This would
require more complex changes to the `Profile` CRD to support merging of
profiles from the same data stream into a single `Profile` object, with multiple
versions.

One complicated aspect of this approach is how a user should get the rules
necessary to implement only one version of the profile. For example, today
users can list all the rules used in a given profile. With a profile that
supports multiple versions, should the Compliance Operator return all rules
used across all profiles, or only a subset? If it's only returning a subset,
which version should it return? Additionally, the Compliance Operator would
need to supply a way to write `ScanSettingBinding` objects with version
notation. The following is a simple example of what that might look like:

```yaml
---
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSettingBinding
metadata:
  name: cis
  namespace: openshift-compliance
profiles:
  - name: ocp4-cis@1.4.0
    kind: Profile
    apiGroup: compliance.openshift.io/v1alpha1
  - name: ocp4-cis-node@1.4.0
    kind: Profile
    apiGroup: compliance.openshift.io/v1alpha1
settingsRef:
  name: default
  kind: ScanSetting
  apiGroup: compliance.openshift.io/v1alpha1
```

This is perhaps overly complicated if the Compliance Operator already relies on
profiles being separate, and if we only use simple strings for versions.
Because of the more complicated logic necessary for merging profiles, this
proposal is focused on the simplier approach detailed above.

## Infrastructure Needed [optional]

CI resources for the Compliance Operator and content testing, similar to what
we rely on today for CI.

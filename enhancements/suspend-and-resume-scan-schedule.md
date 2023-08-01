---
title: suspend-and-resume-scan-schedule
authors:
  - rhmdnd (Lance Bragstad)
reviewers: # Include a comment about what domain expertise a reviewer is expected to bring and what area of the enhancement you expect them to focus on. For example: - "@networkguru, for networking aspects, please look at IP bootstrapping aspect"
  - TBD
approvers:
  - TBD
api-approvers: # In case of new or modified APIs or API extensions (CRDs, aggregated apiservers, webhooks, finalizers). If there is no API change, use "None"
  - TBD
creation-date: 2023-08-01
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

# Suspend and Resume Scan Schedule

## Summary

Currently, users have the ability to create scans that follow a schedule.
Schedules are baked into the default `ScanSetting` instances available
out-of-the-box (e.g., `default` and `default-auto-apply`).

Once a user creates a scan, by binding a `Profile` or `TailoredProfile` to a
`ScanSetting`, they don't have a way to suspend the schedule short of deleting
the `ScanSettingBinding` entirely.

This enhancement describes the need and implementation details for a more
ergonomic way of suspending and resuming scan schedules.

## Motivation

While making a cluster compliant, there may be times when a cluster
administrator does not want to run a particular scan, but they don't
necessarily want to completely delete the `ScanSettingBinding` either.

For example, imagine there is a planned maintenance window set for when a
compliance scan is scheduled to run. When the scan runs, it will return
inaccurate results. Another example is if an organization is working through
compliance findings and wants to prevent subsequent scans until particular
actions are taken that address the findings.

To deal with this, cluster administrators can either delete the binding, or
manually pause the `CronJob` using the `Suspend` attribute.

Deleting the binding is arguably heavy-handed, and requires users to recreate
the binding when they're ready to resume scanning. Conversely, digging into the
implementation details of `CronJob` isn't ideal because it requires underlying
knowledge about that particular Kubernetes feature.

The Compliance Operator can help here by orchestrating a change to suspend scan
schedules for applicable `ScanSetting` objects.

### Goals

The goal is to make it easy for a cluster administrator to suspend and resume
scan schedules with a single API call. For example, suspending an existing scan
should be as easy as modifying a detail of the scan schedule. Similarly,
resuming a scan should be as easy as updating an attribute of the schedule.

### Non-Goals

This enhancement is not focused on stopping a scan that's already in progress.
It is only focused on suspending, or resuming, a scan that is going to take
place in the future.

## Proposal

### User Stories

- As a cluster administrator, I can suspend a scan, or scans, preventing it
  from automatically running according to its predefined schedule.
- As a cluster administrator, I can resume a paused scan, or scans, allowing it
  to run automatically according to its predefined schedule.
- As a cluster administrator, I can identify which scans are paused.

### API Extensions

This change will require an additional `ScanSetting` attribute called `suspend`
that will default to `False`. The following is a condensed reference using the
`default` `ScanSetting`:

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSetting
metadata:
  name: default
  namespace: openshift-compliance
schedule: 0 1 * * *
suspend: False
```

By default, when a `ScanSetting` is bound to one or more `Profile` objects
using a `ScanSettingBinding`, the schedule from the `ScanSetting` is active by
default. This means it will run automatically according to the schedule.
Defaulting the new attribute `ScanSetting.suspend` to `False` allows for
backwards compatibility.

### Implementation Details/Notes/Constraints [optional]

To understand the implementation, let's first start with the relationship
between existing CRDs.

The scan schedule is currently an implementation detail of `ScanSetting`
objects.

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSetting
metadata:
  name: default
  namespace: openshift-compliance
schedule: 0 1 * * *
```

Schedules are associated to one or more `Profile` objects by binding the
`ScanSetting` to a `Profile` using a `ScanSettingBinding`.

A `ScanSettingBinding` creates a `ComplianceSuite`, which acts as a container
for one or more `ComplianceScan` objects. A `ComplianceSuite` creates a
`CronJob` with the schedule from the `ScanSetting` referenced from the
`ScanSettingBinding`.

The `ComplianceSuite` has a one-to-one mapping to `CronJob` objects.

This means all `ComplianceScan` objects within a single `ComplianceSuite` rely
on the same `CronJob`, and run on the same schedule. It's not possible to
suspend a single `ComplianceScan` without refactoring the operator's
`suitererunner` functionality. At this time, we're not convinced that pausing a
single scan is valuable. For example, pausing a single `ComplianceScan`
wouldn't prevent other scans on the same schedule from running within a
particular maintenance window.

Given the details above, we feel the most straight-forward solution is to
implement suspend and resume scan schedule functionality inside the
`ScanSetting`, where the `schedule` is implemented.

This means that if two `ScanSettingBinding` objects reference the same
`ScanSetting`, and it is suspended, both `ComplianceSuite` objects will be
suspended.

For example, let's assume you want to scan your cluster using the OpenShift CIS
(`ocp4-cis`) and the Australian Essential Eight (`ocp4-e8`) profiles and you
bind both to the `default` `ScanSetting`. If you suspending the `default`
`ScanSetting`, your cluster will not scan using either profile until the
`default` `ScanSetting` is resumed.

If this behavior is undesirable, you can create a separate `ScanSetting` for
each profile, allowing you to suspend them independently.

### Risks and Mitigations

From a continuous compliance perspective, it's not ideal to suspend scan
schedules. However, providing the ability to easily suspend and resume scans
through the operator does make the overall experience more palatable. In some
cases, where clusters are going through significant changes or maintenance,
suspending compliance scans is a more appropriate option than deleting the scan
completely.

From a user experience perspective, providing this functionality through the
`ScanSetting` custom resource is easier to consume than modifying `CronJob`
objects directly.

## Design Details

### Open Questions [optional]

None. All open questions were addressed during review.

### Test Plan

This feature can be easily tested using our existing end-to-end test suite. We
don't necessarily need to rely on testing the functionality of `CronJob`, but
we can certainly test that the Compliance Operator updates the `suspend`
attribute according to the `ScanSetting`.

We should have an end-to-end test that performs the following:

1. Creates a new `ScanSetting`, where the actual scan schedule doesn't necessarily matter, but `suspend` is set to `False`
2. Assert the `CronJob` associated with the `ComplianceScan` is set to `suspend=false`
3. Suspend the `ScanSetting` using the `suspend` attribute
4. Assert the `CronJob` associated with the `ComplianceSuite` is set to `suspend=true`
5. Resume the `ComplianceScan` by updating the `ScanSetting.suspend` attribute to `False`
6. Assert the `CronJob` associated with the `ComplianceScan` is set to `suspend=false`

Another test case would be:

1. Creates a new `ScanSetting` with `suspend` set to `True`
2. Bind the new `ScanSetting` to a `Profile`
3. Assert that no scan takes place
4. Update the `ScanSetting.suspend` attribute to `False`
5. Assert the scan is performed

### Upgrade / Downgrade Strategy

Considering the Compliance Operator has typically followed a rolling release
strategy, where fixes and features are never backported, that same concept will
apply to this features.

Attempting to suspend a scan schedule on an older release will simply not work.
Suspending a scan schedule and downgrading the operator will result in the same
behavior, where the older operator will not support suspending or resuming a
scan.

In the case where a cluster administrator suspends a scan, then downgrades the
operator, the `CronJob` associated with the scan rerunner will already be in a
suspended state. This will remain true even after the Compliance Operator is
downgraded. However, a cluster administrator will not be able to resume a scan
from an older version of the Compliance Operator that doesn't support the
feature. Cluster administrators will need to modify the `CronJob.suspend`
property directly to resume the scan schedule.

### Version Skew Strategy

This feature relies on `CronJob` semantics, which are currently considered a
stable feature of Kubernetes.

### Operational Aspects of API Extensions

The life cycle of the affect resources, `ScanSetting`, `ScanSettingBinding`,
`ComplianceSuite`, `ComplianceScan`, will not be affected as a result of this
feature. Cluster administrators should be able to interact with, and delete
these resources even if the `ScanSetting` is suspended.

#### Failure Modes

- Describe the possible failure modes of the API extensions.
- Describe how a failure or behaviour of the extension will impact the overall cluster health
  (e.g. which kube-controller-manager functionality will stop working), especially regarding
  stability, availability, performance and security.
- Describe which OCP teams are likely to be called upon in case of escalation with one of the failure modes
  and add them as reviewers to this enhancement.

#### Support Procedures

Logs will emit information logging when scan schedules are suspended and
resumed. Knowing when a scan schedule is suspended or resumed is important from
a compliance perspective, and warrants a higher log level than debug.

In the event of an error while suspending or resuming a scan schedule, the
`ComplianceSuite` status will be updated to `ERROR`, with an appropriate log
message.

If an error is encountered, a cluster administrator can update the
`CronJob.status` manually.

## Implementation History

Since this is a relatively small feature, the main milestone will be extending
the `ScanSetting` to support an additional attribute called `suspend` that maps
to the `CronJob`.

## Drawbacks

The idea is to find the best form of an argument why this enhancement should
_not_ be implemented.

## Alternatives

There are three alternative approaches to this proposal.

1. Annotate the `ComplianceSuite`

Annotate the `ComplianceSuite` directly to suspend the `CronJob`. This is a
viable solution and would solve the use case, but decouples the suspend
functionality (implemented in the `ComplianceSuite`) from the schedule
(implemented in the `ScanSetting`). Additionally, suspending all scans for a
single schedule would require annotating each `ComplianceSuite`.

Another aspect of this approach is that if the `ComplianceSuite` is deleted,
the annotation is also removed, meaning the recreated `ComplianceSuite` will
automatically start rescanning the environment.

2. Annotate the `ComplianceScan`

Similar to approach #1, but needs to be implemented in the `suitererunner` and
doesn't reuse the `CronJob` suspend functionality.

3. Annotate the `ScanSettingBinding`

This is effectively the same solution as approach #1, but ensures the
annotation is persistent, even if the `ComplianceSuite` is deleted. This means
a user could suspend a `ScanSettingBinding` and delete the `ComplianceSuite`,
and the recreated `ComplianceSuite` wouldn't automatically scan the
environment. It also means a user would need to suspend each binding
individually if they all use the same `ScanSetting`.

## Infrastructure Needed [optional]

Testing infrastructure for this feature will use the same CI configuration as
the standard end-to-end infrastructure we use today.

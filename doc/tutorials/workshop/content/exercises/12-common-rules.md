---
Title: All types of rules
PrevPage: 11-node-rules
NextPage:  13-complex-yaml.md
---
Common types of rules
===================

The rules we created in the previous chapters leveraged the `yamlfile_value`,
`file_permissions` and `sysctl` template from CaC/content project. There are
many more templates available in the project and each one enable us to quickly
create rules with a specific behavior.

In this section we will go through the most common types of checks when
assessing the security posture of a cluster and the templates used to
implement them.

## Platform checks

The Platform checks are directed towards Kubernetes, a.k.a. the platform.

The check is invoked only once and they evaluate the state of the platform.
For example, checking the value of a particular Kubernetes resource, or cluster
configuration option.

### Checking Kubernetes resources

Checking the configuration of a Kubernetes resource is the obvious task when
one wants to check the cluster's security posture.
This type of check is handled by the [yamlfile_value](https://complianceascode.readthedocs.io/en/latest/templates/template_reference.html#yamlfile-value)
template.

You can write a rule and make use of the template by yourself, or
use the `./utils/add_platform_rule.py` script showcased in past sections.
Note that more advanced uses of the template will require you to write the
input data manualy, check the template's documentation.

One example of this type of rule is a check whether any registry configured
for import allows the use of insecure protocols. The rule checks the Cluster
API and assess whether any `allowedRegistriesForImport` has `'{"insecure": true}':
[ocp_insecure_allowed_registries_for_import](https://github.com/ComplianceAsCode/content/blob/master/applications/openshift/registry/ocp_insecure_allowed_registries_for_import/rule.yml)

Another example is checking whether RBAC roles are defined. 
[rbac_roles_defined](https://github.com/ComplianceAsCode/content/blob/master/applications/openshift/rbac/rbac_roles_defined/rule.yml)

## Node checks

The Node checks are directed towards the Nodes composing the cluster.
They can assess the configuration of the node's OS and any Platform configuration that is relevant to the node.

The check is invoked once per applicable node.
For example, a node rule can evaluate an `etcd` configuration across all master nodes.
Or a node rule may check the permissions of `/etc/sshd_config` (which isn't specific to OpenShift), on all nodes.

### Checking for a KubeletConfig setting

With Kubelet being the primary agent on the node it is important to
assess its configuration.

You can also use the [yamlfile_value](https://complianceascode.readthedocs.io/en/latest/templates/template_reference.html#yamlfile-value)
template for this. Note though that these checks are Node checks, not Platform checks.

For example, this rule ensures that the node does not have a `kubelet.conf` that defines
a `KubeletConfiguration` with an `authorization.mode` with value equal to `AllowAll`:

[kubelet_authorization_mode](https://github.com/ComplianceAsCode/content/blob/master/applications/openshift/kubelet/kubelet_authorization_mode/rule.yml)


### Checking ownership and permissions of files

A very common requirement is to ensure that files in the cluster node have
appropriate ownership and permissions.

To check the owner, group owner or permissions in files use the following
templates,
[file_owner](https://complianceascode.readthedocs.io/en/latest/templates/template_reference.html#file-owner),
[file_groupowner](https://complianceascode.readthedocs.io/en/latest/templates/template_reference.html#file-groupowner),
[file_permissions](https://complianceascode.readthedocs.io/en/latest/templates/template_reference.html#file-permissions)
respectivetly

For example, to ensure the permissions of file `/etc/passwd` in the node is
'0644' write a new rule and use the template `file_permissions`:

```
template:
    name: file_permissions
    vars:
        filepath: /etc/passwd
        filemode: '0644'
```

Check rule [file_permissions_etc_passwd](https://github.com/ComplianceAsCode/content/blob/cc4375ca0cb7f8aa3a789ba619504c7590e7af21/linux_os/guide/system/permissions/files/permissions_important_account_files/file_permissions_etc_passwd/rule.yml) for a complete example.

### Checking kernel parameters 

The Kernel parameters are also an important setting that can be checked.

### sysctl
To check for sysctl parameters on the node use the the
[sysctl](https://complianceascode.readthedocs.io/en/latest/templates/template_reference.html#sysctl) template.
For example, to ensure that `kernel.panic_on_oops` is set to one, write a rule
with the following template.

```
template:
    name: sysctl
    vars:
        sysctlvar: kernel.panic_on_oops
        sysctlval: '1'
        datatype: int
```
Check rule [kubelet_enable_protect_kernel_sysctl_kernel_panic_on_oops](https://github.com/ComplianceAsCode/content/blob/master/applications/openshift/kubelet/kubelet_enable_protect_kernel_sysctl_kernel_panic_on_oops/rule.yml) for a complete example.

In the next section we will look at a way to handle [more complex checks](13-complex-yaml.md)
and resources.

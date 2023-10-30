---
Title: Node Rules
PrevPage: 10-rule-parametrization
NextPage: 12-common-rules
---

Node Rules
===================

## Platform vs Node rules

One important distinction to make is whether the configuration being checked is
a Kubernetes resource (a Platform check) or a setting in the node of the
cluster (a node check).

The Platform rules check the Kubernetes API Resources.
While the node rules check configuration of the node's operating system.

So far the rules we created were Platform rules, they checked a Kubernetes
configuration. But one can also check configurations of the operating
system at the node level, and that is what we'll be doing in this section.

## Creating Node rules

Let's create a rule that checks whether the file `/etc/system-release` is
owned by root in our cluster's nodes.

To create this node rule, execute the following `create node` command:
```
$ ./utils/add_kubernetes_rule.py create node \
    --rule file_owner_etc_system_release \
    --title "File /etc/system-release must be owned by root" \
    --description "We need to ensure that root owns the system release file"  \
    --template file_owner \
    --template-vars "filepath: /etc/system-release, fileuid: 0"
```

We already know the `rule`, `title` and `description` are for, they are
the same arguments passed when creating a `Platform` rule.
The `template` argument is used to specify which template to use, and
`template-vars` is a comma separated string with the values to be used.

If you are curious about what templates are available, don't worry,
in the next section we will go through the most used templates and their
input arguments.

Here is another example of how to quickly generate a a node rule that checks
the sysctl `kernel.randomize_va_space` value:
```
$ ./utils/add_kubernetes_rule.py create node \
    --rule sysctl_kernel_randomize_va_space \
    --title "Ensure ASLR is fully enabled" \
    --description "Make it harder to exploit vulnerabilities by employing full address space layout randomization"  \
    --template sysctl \
    --template-vars "sysctlvar: kernel.randomize_va_space, sysctlval: 2, datatype: int"
```

### Selecting the nodes to check

The node rules created with `./utils/add_kubernetes_rule.py create node ...`
are by default applicable to all nodes in the cluster,  i.e.: `worker` and
`master` nodes.

To restrict a node rule to scan only on master nodes, you need to change the
`platform` key in the `rule.yml` to `ocp4-master-node`.

To set a node check to run on all nodes, set the rule's platform to:
`platform: {{{ product }}}-node`, or more explicitly `platform: ocp4-node`

To set a node check to run on only on master nodes, set the rule's platform to:
`platform: {{{ product }}}-master-node`

### Use of yamlfile_value on node rules

The `yamlfile_value` template is a template like any other in CaC/content
project, its purpose is to assert whether a yaml key's value satisfies a
certain criteria.

The use of this template is not limited to platform rules, it is very handy
to check configurations defined in yaml file on the node.

One such example is the Kubelet configuration in each node. The
`/etc/kubernetes/kubelet.conf` is a yaml that can be checked using the
`yamlfile_value` template.

Check the rule [kubelet_enable_cert_rotation](https://github.com/ComplianceAsCode/content/blob/master/applications/openshift/kubelet/kubelet_enable_cert_rotation/rule.yml)
for an example of how the `yamlfile_value` template is used.

Let's now take a look at the [most common types of rules](12-common-rules.md) and the templates used when writing rules for Kubernetes.

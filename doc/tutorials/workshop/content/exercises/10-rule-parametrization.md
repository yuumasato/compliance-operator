---
Title: Rule parametrization
PrevPage: 09-writing-rules
NextPage: 11-node-rules
---

Rule parametrization
====================

In this section we will learn how one can make their rules more flexible with
parametrization, which allows us to slightly alter what a rule is checking for.
We will leverage `TailoredProfiless` to create our own `Profile` that enables a
`Rule` and tailors a `Variable`.

Additionally, we will go through more advanced testing procedures which will
be required to test our `TailoredProfile`.

## Variable parametrization

The rule we created initially accepted only `yep` as a compliant value, and
later we extended it to accept anything that matched a regular expression.

What if we had two different sets of clusters with distinct compliance needs.
One cluster needs to have a `compliant` value of `yep`, and the other the
value of `yes`. 

The usual way of checking for different needs is to have different profiles.
So in our scenarios we would have one profile for each cluster.

But our rule, with its regular expression, accepts both values as compliant.
We cannot simply use the rule for both profiles and be sure that compliance
requirements for each cluster is met, as both values lead the rule to a
`COMPLIANT` result.

We could have two separate rules, each checking for one of the values, and
add them to their respective profiles.
But this creates two seemingly identical rules and increases our maintenance
costs. What if we had more clusters each with its different compliance needs?

The better approach is to parametrize the rule with a variable, and tailor
the variable to the value we want to assess in each profile.

### Creating the variable and testing basic functionality

So lets first create a variable named `var-my-compliant-value` as follows:
```
$ cat << EOF > applications/openshift/var-my-compliant-value.var
documentation_complete: true

title: 'My compliant value'

description: |-
    The value that 'my-compliant-configmap' should have in the key 'compliant'.

    Default value is 'yep'.
    Other possible values are 'yes' and 'definitely.

type: string

operator: equals

options:
    default: yep
    yep: yep
    yes: yes
    definitely: definitely
EOF
```

Then run the following command to change the rule to use the variable
we just created:
```
$ ./utils/add_platform_rule.py create platform\
    --rule must_have_compliant_cm \
    --name my-compliance-configmap --namespace openshift --type configmap \
    --title "Must have compliant CM" \
    --description "The deployment must have a CM that's compliant with.... life!" \
    --match-entity "at least one" \
    --yamlpath '.data.compliant' \
    --variable "var-my-compliant-value"
```

Our `ConfigMap` still has an incompliant value, if we test the rule right now
it will evaluate to `NON-COMPLIANT`.

Let's update it to one of the selections available in the variable.
The default value is `yep`, and that is the variable's value if used without any tailoring.
```
$ oc patch -n openshift configmap my-compliance-configmap \
   -p '{"data": {"compliant": "yep"}}' --type=merge
```
```
$ ./utils/add_platform_rule.py cluster-test --rule must_have_compliant_cm
...
* The result is 'COMPLIANT'
```

### Testing Rules with Profile Tailorings

So far we have been using the `./utils/add_platform_rule.py` script to test
our rule. It creates very specific `ComplianceScans` that cannot cover all the use
cases.

For that reason we will now leverage the `ProfileBundles` created by the
`utils/build_ds_container.py` to test the rule customization with
`TailoredProfiles`.

Build and push the content to you cluster while creating `ProfileBundles` with
the following command:
```
$ ./utils/build_ds_container.py -p
```

One aspect to note though, is that `Profiles`, `Rules`, `Variables` and `Remediations`
created by this command will have the `upstream` prefix.
For example, our rule will be named `upstream-ocp4-must-have-compliant-cm`.

First, let's update the `ConfigMap` to one of the compliant values from the
variable:
```
$ oc patch -n openshift configmap my-compliance-configmap \
   -p '{"data": {"compliant": "definitely"}}' --type=merge
```

Create a `TailoredProfile` that enables only our rule and changes the value of
the variable to check for `definitely`:
```
$ cat << EOF > my-own-profile.yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: TailoredProfile
metadata:
  name: my-own-profile
  namespace: openshift-compliance
spec:
  description: My compliance profile for OCP4
  title: OCP4 profile with customized compliance value 
  enableRules:
    - name: upstream-ocp4-must-have-compliant-cm
      rationale: Scan with our new rule.
  setValues:
    - name: upstream-ocp4-var-my-compliant-value
      rationale: The cluster scanned needs to be definitely compliant.
      value: definitely
EOF
```

In the `TailoredProfile` above we are enabling rule `upstream-ocp4-must-have-compliant-cm`
and customizing the value of variable `upstream-ocp4-var-my-compiant-value`.

Then, to enable scans with our `TailoredProfile` bind it to a `ScanSetting` of your
choice, we will use the `default` `ScanSetting` which is available right after
install.
```
$ cat << EOF > default-own-profile.yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSettingBinding
metadata:
  name: default-own-profile
  namespace: openshift-compliance
profiles:
  - name: my-own-profile
    kind: TailoredProfile
    apiGroup: compliance.openshift.io/v1alpha1
settingsRef:
  name: default
  kind: ScanSetting
  apiGroup: compliance.openshift.io/v1alpha1
EOF
```

```
$ oc create -f my-own-profile.yaml
tailoredprofile.compliance.openshift.io/my-own-profile created
$ oc create -f default-own-profile.yaml
scansettingbinding.compliance.openshift.io/default-own-profile created
```

After the `ScanSettingBinding` creation is processed a `ComplianceSuite`
will be created and evaluation with our `TailoredProfile` started.

After a few minutes check that the scan finished with result `COMPLIANT`
```
$ oc get compliancescan
NAME             PHASE   RESULT
my-own-profile   DONE    COMPLIANT
```

Our rule is ready to be enabled in multiple profiles checking different values
in each `Profile`.

Next we will learn what are [node rules](11-node-rules.md) and how do they differ from platform rules.

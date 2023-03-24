package parallel_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	"k8s.io/apimachinery/pkg/types"
)

var brokenContentImagePath string

func TestMain(m *testing.M) {
	f := framework.NewFramework()
	err := f.SetUp()
	if err != nil {
		log.Fatal(err)
	}

	brokenContentImagePath = os.Getenv("BROKEN_CONTENT_IMAGE")

	if brokenContentImagePath == "" {
		fmt.Println("Please set the 'BROKEN_CONTENT_IMAGE' environment variable")
		os.Exit(1)
	}

	exitCode := m.Run()
	if exitCode == 0 || (exitCode > 0 && f.CleanUpOnError()) {
		if err = f.TearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

func TestProfileModification(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const (
		removedRule         = "chronyd-no-chronyc-network"
		unlinkedRule        = "chronyd-client-only"
		moderateProfileName = "moderate"
	)
	var (
		baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_baseline")
		modifiedImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_mod")
	)

	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	pbName := framework.GetObjNameFromTest(t)
	origPb := &compv1alpha1.ProfileBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pbName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ProfileBundleSpec{
			ContentImage: baselineImage,
			ContentFile:  framework.RhcosContentFile,
		},
	}
	// Pass nil in as the cleanupOptions since so we don't invoke all the
	// cleanup function code in Create. Use defer to cleanup the
	// ProfileBundle at the end of the test, instead of at the end of the
	// suite.
	if err := f.Client.Create(context.TODO(), origPb, nil); err != nil {
		t.Fatalf("failed to create ProfileBundle: %s", err)
	}
	// This should get cleaned up at the end of the test
	defer f.Client.Delete(context.TODO(), origPb)

	if err := f.WaitForProfileBundleStatus(pbName); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}
	if err := f.AssertMustHaveParsedProfiles(pbName, string(compv1alpha1.ScanTypeNode), "redhat_enterprise_linux_coreos_4"); err != nil {
		t.Fatalf("failed checking profiles in ProfileBundle: %s", err)
	}

	// Check that the rule we removed exists in the original profile
	removedRuleName := prefixName(pbName, removedRule)
	err, found := f.DoesRuleExist(origPb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found != true {
		t.Fatalf("expected rule %s to exist in namespace %s", removedRuleName, origPb.Namespace)
	}

	// Check that the rule we unlined in the modified profile is linked in the original
	profileName := prefixName(pbName, moderateProfileName)
	profilePreUpdate := &compv1alpha1.Profile{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: origPb.Namespace, Name: profileName}, profilePreUpdate); err != nil {
		t.Fatalf("failed to get profile %s", profileName)
	}
	unlinkedRuleName := prefixName(pbName, unlinkedRule)
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePreUpdate)
	if found == false {
		t.Fatalf("failed to find rule %s in profile %s", unlinkedRule, profileName)
	}

	// update the image with a new hash
	modPb := origPb.DeepCopy()
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: modPb.Namespace, Name: modPb.Name}, modPb); err != nil {
		t.Fatalf("failed to get ProfileBundle %s", modPb.Name)
	}

	modPb.Spec.ContentImage = modifiedImage
	if err := f.Client.Update(context.TODO(), modPb); err != nil {
		t.Fatalf("failed to update ProfileBundle %s: %s", modPb.Name, err)
	}

	// Wait for the update to happen, the PB will flip first to pending, then to valid
	if err := f.WaitForProfileBundleStatus(pbName); err != nil {
		t.Fatalf("failed to parse ProfileBundle %s: %s", pbName, err)
	}

	if err := f.AssertProfileBundleMustHaveParsedRules(pbName); err != nil {
		t.Fatal(err)
	}

	// We removed this rule in the update, is must no longer exist
	err, found = f.DoesRuleExist(origPb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatalf("rule %s unexpectedly found", removedRuleName)
	}

	// This rule was unlinked
	profilePostUpdate := &compv1alpha1.Profile{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: origPb.Namespace, Name: profileName}, profilePostUpdate); err != nil {
		t.Fatalf("failed to get profile %s: %s", profileName, err)
	}
	framework.IsRuleInProfile(unlinkedRuleName, profilePostUpdate)
	if found {
		t.Fatalf("rule %s unexpectedly found", unlinkedRuleName)
	}
}

func TestProfileISTagUpdate(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const (
		removedRule         = "chronyd-no-chronyc-network"
		unlinkedRule        = "chronyd-client-only"
		moderateProfileName = "moderate"
	)
	var (
		baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_baseline")
		modifiedImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_mod")
	)

	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	pbName := framework.GetObjNameFromTest(t)
	iSName := pbName

	s, err := f.CreateImageStream(iSName, f.OperatorNamespace, baselineImage)
	if err != nil {
		t.Fatalf("failed to create image stream %s", iSName)
	}
	defer f.Client.Delete(context.TODO(), s)

	pb := &compv1alpha1.ProfileBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pbName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ProfileBundleSpec{
			ContentImage: fmt.Sprintf("%s:%s", iSName, "latest"),
			ContentFile:  framework.RhcosContentFile,
		},
	}

	if err := f.Client.Create(context.TODO(), pb, nil); err != nil {
		t.Fatalf("failed to create ProfileBundle %s", pbName)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName); err != nil {
		t.Fatalf("failed waiting for the ProfileBundle to become available: %s", err)
	}
	if err := f.AssertMustHaveParsedProfiles(pbName, string(compv1alpha1.ScanTypeNode), "redhat_enterprise_linux_coreos_4"); err != nil {
		t.Fatalf("failed checking profiles in ProfileBundle: %s", err)
	}

	// Check that the rule we removed exists in the original profile
	removedRuleName := prefixName(pbName, removedRule)
	err, found := f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("failed to find rule %s in ProfileBundle %s", removedRuleName, pbName)
	}

	// Check that the rule we unlined in the modified profile is linked in the original
	profilePreUpdate := &compv1alpha1.Profile{}
	profileName := prefixName(pbName, moderateProfileName)
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: pb.Namespace, Name: profileName}, profilePreUpdate); err != nil {
		t.Fatalf("failed to get profile %s", profileName)
	}
	unlinkedRuleName := prefixName(pbName, unlinkedRule)
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePreUpdate)
	if !found {
		t.Fatalf("failed to find rule %s in ProfileBundle %s", unlinkedRuleName, pbName)
	}

	// Update the reference in the image stream
	if err := f.UpdateImageStreamTag(iSName, modifiedImage, f.OperatorNamespace); err != nil {
		t.Fatalf("failed to update image stream %s: %s", iSName, err)
	}

	modifiedImageDigest, err := f.GetImageStreamUpdatedDigest(iSName, f.OperatorNamespace)
	if err != nil {
		t.Fatalf("failed to get digest for image stream %s: %s", iSName, err)
	}

	// Note that when an update happens through an imagestream tag, the operator doesn't get
	// a notification about it... It all happens on the Kube Deployment's side.
	// So we don't need to wait for the profile bundle's statuses
	if err := f.WaitForDeploymentContentUpdate(pbName, modifiedImageDigest); err != nil {
		t.Fatalf("failed waiting for content to update: %s", err)
	}

	if err := f.AssertProfileBundleMustHaveParsedRules(pbName); err != nil {
		t.Fatal(err)
	}

	// We removed this rule in the update, it must no longer exist
	err, found = f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatalf("rule %s unexpectedly found", removedRuleName)
	}

	// This rule was unlinked
	profilePostUpdate := &compv1alpha1.Profile{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: pb.Namespace, Name: profileName}, profilePostUpdate); err != nil {
		t.Fatalf("failed to get profile %s", profileName)
	}
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePostUpdate)
	if found {
		t.Fatalf("rule %s unexpectedly found", unlinkedRuleName)
	}
}

func TestProfileISTagOtherNs(t *testing.T) {
	t.Parallel()
	f := framework.Global
	const (
		removedRule         = "chronyd-no-chronyc-network"
		unlinkedRule        = "chronyd-client-only"
		moderateProfileName = "moderate"
	)
	var (
		baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_baseline")
		modifiedImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_mod")
	)

	prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

	pbName := framework.GetObjNameFromTest(t)
	iSName := pbName
	otherNs := "openshift"

	stream, err := f.CreateImageStream(iSName, otherNs, baselineImage)
	if err != nil {
		t.Fatalf("failed to create image stream %s\n", iSName)
	}
	defer f.Client.Delete(context.TODO(), stream)

	pb := &compv1alpha1.ProfileBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pbName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ProfileBundleSpec{
			ContentImage: fmt.Sprintf("%s/%s:%s", otherNs, iSName, "latest"),
			ContentFile:  framework.RhcosContentFile,
		},
	}

	if err := f.Client.Create(context.TODO(), pb, nil); err != nil {
		t.Fatalf("failed to create ProfileBundle %s: %s", pbName, err)
	}
	defer f.Client.Delete(context.TODO(), pb)

	if err := f.WaitForProfileBundleStatus(pbName); err != nil {
		t.Fatalf("failed waiting for ProfileBundle to parse: %s", err)
	}
	if err := f.AssertMustHaveParsedProfiles(pbName, string(compv1alpha1.ScanTypeNode), "redhat_enterprise_linux_coreos_4"); err != nil {
		t.Fatalf("failed to assert profiles in ProfileBundle %s: %s", pbName, err)
	}

	// Check that the rule we removed exists in the original profile
	removedRuleName := prefixName(pbName, removedRule)
	err, found := f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if !found {
		t.Fatalf("expected rule %s to exist", removedRuleName)
	}

	// Check that the rule we unlined in the modified profile is linked in the original
	profilePreUpdate := &compv1alpha1.Profile{}
	profileName := prefixName(pbName, moderateProfileName)
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: pb.Namespace, Name: profileName}, profilePreUpdate); err != nil {
		t.Fatalf("failed to get profile %s: %s", profileName, err)
	}
	unlinkedRuleName := prefixName(pbName, unlinkedRule)
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePreUpdate)
	if !found {
		t.Fatalf("expected to find rule %s in profile %s", unlinkedRuleName, profileName)
	}

	// Update the reference in the image stream
	if err := f.UpdateImageStreamTag(iSName, modifiedImage, otherNs); err != nil {
		t.Fatalf("failed to update image stream %s: %s", iSName, err)
	}

	modifiedImageDigest, err := f.GetImageStreamUpdatedDigest(iSName, otherNs)
	if err != nil {
		t.Fatalf("failed to get digest for image stream %s: %s", iSName, err)
	}

	// Note that when an update happens through an imagestream tag, the operator doesn't get
	// a notification about it... It all happens on the Kube Deployment's side.
	// So we don't need to wait for the profile bundle's statuses
	if err := f.WaitForDeploymentContentUpdate(pbName, modifiedImageDigest); err != nil {
		t.Fatalf("failed waiting for content to update: %s", err)
	}

	if err := f.AssertProfileBundleMustHaveParsedRules(pbName); err != nil {
		t.Fatal(err)
	}
	// We removed this rule in the update, it must no longer exist
	err, found = f.DoesRuleExist(pb.Namespace, removedRuleName)
	if err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatalf("rule %s unexpectedly found", removedRuleName)
	}

	// This rule was unlinked
	profilePostUpdate := &compv1alpha1.Profile{}
	if err := f.Client.Get(context.TODO(), types.NamespacedName{Namespace: pb.Namespace, Name: profileName}, profilePostUpdate); err != nil {
		t.Fatalf("failed to get profile %s", profileName)
	}
	found = framework.IsRuleInProfile(unlinkedRuleName, profilePostUpdate)
	if found {
		t.Fatalf("rule %s unexpectedly found", unlinkedRuleName)
	}

}

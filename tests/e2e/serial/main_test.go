package serial_e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"testing"

	mcfgv1 "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
)

var brokenContentImagePath string
var contentImagePath string

func TestMain(m *testing.M) {
	f := framework.NewFramework()
	err := f.SetUp()
	if err != nil {
		log.Fatal(err)
	}

	contentImagePath = os.Getenv("CONTENT_IMAGE")
	if contentImagePath == "" {
		fmt.Println("Please set the 'CONTENT_IMAGE' environment variable")
		os.Exit(1)
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

func TestScanStorageOutOfQuotaRangeFails(t *testing.T) {
	f := framework.Global
	rq := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pvc-resourcequota",
			Namespace: f.OperatorNamespace,
		},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				corev1.ResourceRequestsStorage: resource.MustParse("5Gi"),
			},
		},
	}
	if err := f.Client.Create(context.TODO(), rq, nil); err != nil {
		t.Fatalf("failed to create ResourceQuota: %s", err)
	}
	defer f.Client.Delete(context.TODO(), rq)

	scanName := framework.GetObjNameFromTest(t)
	testScan := &compv1alpha1.ComplianceScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceScanSpec{
			Profile: "xccdf_org.ssgproject.content_profile_moderate",
			Content: framework.RhcosContentFile,
			Rule:    "xccdf_org.ssgproject.content_rule_no_netrc_files",
			ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
				RawResultStorage: compv1alpha1.RawResultStorageSettings{
					Size: "6Gi",
				},
				Debug: true,
			},
		},
	}
	// use Context's create helper to create the object and add a cleanup function for the new object
	err := f.Client.Create(context.TODO(), testScan, nil)
	if err != nil {
		t.Fatalf("failed ot create scan %s: %s", scanName, err)
	}
	defer f.Client.Delete(context.TODO(), testScan)
	err = f.WaitForScanStatus(f.OperatorNamespace, scanName, compv1alpha1.PhaseDone)
	if err != nil {
		t.Fatal(err)
	}

	err = f.AssertScanIsInError(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
}

// NOTE(jaosorior): This was made a serial test because it runs the long-running, resource-taking and
// big AF moderate profile
func TestSuiteScan(t *testing.T) {
	f := framework.Global
	suiteName := "test-suite-two-scans"
	workerScanName := fmt.Sprintf("%s-workers-scan", suiteName)
	selectWorkers := map[string]string{
		"node-role.kubernetes.io/worker": "",
	}

	masterScanName := fmt.Sprintf("%s-masters-scan", suiteName)
	selectMasters := map[string]string{
		"node-role.kubernetes.io/master": "",
	}

	exampleComplianceSuite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			ComplianceSuiteSettings: compv1alpha1.ComplianceSuiteSettings{
				AutoApplyRemediations: false,
			},
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						NodeSelector: selectWorkers,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: workerScanName,
				},
				{
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Content:      framework.RhcosContentFile,
						NodeSelector: selectMasters,
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
						},
					},
					Name: masterScanName,
				},
			},
		},
	}

	err := f.Client.Create(context.TODO(), exampleComplianceSuite, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Client.Delete(context.TODO(), exampleComplianceSuite)

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// At this point, both scans should be non-compliant given our current content
	err = f.AssertScanIsNonCompliant(workerScanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertScanIsNonCompliant(masterScanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	// Each scan should produce two remediations
	workerRemediations := []string{
		fmt.Sprintf("%s-no-empty-passwords", workerScanName),
		fmt.Sprintf("%s-no-direct-root-logins", workerScanName),
	}
	err = f.AssertHasRemediations(suiteName, workerScanName, "worker", workerRemediations)
	if err != nil {
		t.Fatal(err)
	}

	masterRemediations := []string{
		fmt.Sprintf("%s-no-empty-passwords", masterScanName),
		fmt.Sprintf("%s-no-direct-root-logins", masterScanName),
	}
	err = f.AssertHasRemediations(suiteName, masterScanName, "master", masterRemediations)
	if err != nil {
		t.Fatal(err)
	}

	checkWifiInBios := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-wireless-disable-in-bios", workerScanName),
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_wireless_disable_in_bios",
		Status:   compv1alpha1.CheckResultManual,
		Severity: compv1alpha1.CheckResultSeverityUnknown, // yes, it's really uknown in the DS
	}

	err = f.AssertHasCheck(suiteName, workerScanName, checkWifiInBios)
	if err != nil {
		t.Fatal(err)
	}
	err = f.AssertCheckRemediation(checkWifiInBios.Name, checkWifiInBios.Namespace, false)
	if err != nil {
		t.Fatal(err)
	}

	if runtime.GOARCH == "amd64" {
		// the purpose of this check is to make sure that also INFO-level checks produce remediations
		// as of now, the only one we have is the vsyscall check that is x86-specific.
		checkVsyscall := compv1alpha1.ComplianceCheckResult{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-coreos-vsyscall-kernel-argument", workerScanName),
				Namespace: f.OperatorNamespace,
				Labels: map[string]string{
					compv1alpha1.ComplianceCheckResultHasRemediation: "",
				},
			},
			ID:       "xccdf_org.ssgproject.content_rule_coreos_vsyscall_kernel_argument",
			Status:   compv1alpha1.CheckResultInfo,
			Severity: compv1alpha1.CheckResultSeverityMedium,
		}

		err = f.AssertHasCheck(suiteName, workerScanName, checkVsyscall)
		if err != nil {
			t.Fatal(err)
		}
		// even INFO checks generate remediations, make sure the check was labeled appropriately
		// even INFO checks generate remediations, make sure the check was labeled appropriately
		f.AssertCheckRemediation(checkVsyscall.Name, checkVsyscall.Namespace, true)
	}

}

func TestTolerations(t *testing.T) {
	f := framework.Global
	workerNodes, err := f.GetNodesWithSelector(map[string]string{
		"node-role.kubernetes.io/worker": "",
	})
	if err != nil {
		t.Fatal(err)
	}

	taintedNode := &workerNodes[0]
	taintKey := "co-e2e"
	taintVal := "val"
	taint := corev1.Taint{
		Key:    taintKey,
		Value:  taintVal,
		Effect: corev1.TaintEffectNoSchedule,
	}
	if err := f.TaintNode(taintedNode, taint); err != nil {
		t.Fatalf("failed to taint node %s: %s", taintedNode.Name, err)
	}

	removeTaintClosure := func() {
		removeTaintErr := f.UntaintNode(taintedNode.Name, taintKey)
		if removeTaintErr != nil {
			t.Fatalf("failed to remove taint: %s", removeTaintErr)
			// not much to do here
		}
	}
	defer removeTaintClosure()

	suiteName := framework.GetObjNameFromTest(t)
	scanName := suiteName
	suite := &compv1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Spec: compv1alpha1.ComplianceSuiteSpec{
			Scans: []compv1alpha1.ComplianceScanSpecWrapper{
				{
					ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
						ContentImage: contentImagePath,
						Profile:      "xccdf_org.ssgproject.content_profile_moderate",
						Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
						Content:      framework.RhcosContentFile,
						NodeSelector: map[string]string{
							// Schedule scan in this specific host
							corev1.LabelHostname: taintedNode.Labels[corev1.LabelHostname],
						},
						ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
							Debug: true,
							ScanTolerations: []corev1.Toleration{
								{
									Key:      taintKey,
									Operator: corev1.TolerationOpExists,
									Effect:   corev1.TaintEffectNoSchedule,
								},
							},
						},
					},
					Name: scanName,
				},
			},
		},
	}
	if err := f.Client.Create(context.TODO(), suite, nil); err != nil {
		t.Fatalf("failed to create suite %s: %s", suiteName, err)
	}
	defer f.Client.Delete(context.TODO(), suite)

	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAutoRemediate(t *testing.T) {
	f := framework.Global
	// FIXME, maybe have a func that returns a struct with suite name and scan names?
	suiteName := "test-remediate"
	scanName := fmt.Sprintf("%s-e2e", suiteName)

	tp := &compv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
			Annotations: map[string]string{
				compv1alpha1.ProductTypeAnnotation: "Node",
			},
		},
		Spec: compv1alpha1.TailoredProfileSpec{
			Title:       "Test Auto Remediate",
			Description: "A test tailored profile to auto remediate",
			EnableRules: []compv1alpha1.RuleReferenceSpec{
				{
					Name:      "rhcos4-no-direct-root-logins",
					Rationale: "To be tested",
				},
			},
		},
	}

	createTPErr := f.Client.Create(context.TODO(), tp, nil)
	if createTPErr != nil {
		t.Fatalf("failed to create TailoredProfile %s: %s", tp.Name, createTPErr)
	}
	defer f.Client.Delete(context.TODO(), tp)

	ssb := &compv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      suiteName,
			Namespace: f.OperatorNamespace,
		},
		Profiles: []compv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     suiteName,
			},
		},
		SettingsRef: &compv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     "e2e-default-auto-apply",
		},
	}
	err := f.Client.Create(context.TODO(), ssb, nil)
	if err != nil {
		t.Fatalf("failed to create ScanSettingBinding %s: %s", ssb.Name, err)
	}
	defer f.Client.Delete(context.TODO(), ssb)

	// Get the MachineConfigPool before a scan or remediation has been applied
	// This way, we can check that it changed without race-conditions
	poolBeforeRemediation := &mcfgv1.MachineConfigPool{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: framework.TestPoolName}, poolBeforeRemediation)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
	if err != nil {
		t.Fatal(err)
	}

	// We need to check that the remediation is auto-applied and save
	// the object so we can delete it later
	remName := fmt.Sprintf("%s-no-direct-root-logins", scanName)
	err = f.WaitForRemediationToBeAutoApplied(remName, f.OperatorNamespace, poolBeforeRemediation)
	if err != nil {
		t.Fatal(err)
	}

	// We can re-run the scan at this moment and check that it's now compliant
	// and it's reflected in a CheckResult
	err = f.ReRunScan(scanName, f.OperatorNamespace)
	if err != nil {
		t.Fatal(err)
	}

	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseRunning, compv1alpha1.ResultNotAvailable)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that all the scans in the suite have finished and are marked as Done
	log.Printf("waiting for scan %s to finish\n", scanName)
	err = f.WaitForSuiteScansStatus(f.OperatorNamespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("scan %s re-run has finished\n", scanName)

	// Now the check should be passing
	checkNoDirectRootLogins := compv1alpha1.ComplianceCheckResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-no-direct-root-logins", scanName),
			Namespace: f.OperatorNamespace,
		},
		ID:       "xccdf_org.ssgproject.content_rule_no_direct_root_logins",
		Status:   compv1alpha1.CheckResultPass,
		Severity: compv1alpha1.CheckResultSeverityMedium,
	}
	err = f.AssertHasCheck(suiteName, scanName, checkNoDirectRootLogins)
	if err != nil {
		t.Fatal(err)
	}

	// The test should not leave junk around, let's remove the MC and wait for the nodes to stabilize
	// again
	log.Printf("Removing applied remediation\n")
	// Fetch remediation here so it can be deleted
	rem := &compv1alpha1.ComplianceRemediation{}
	err = f.Client.Get(context.TODO(), types.NamespacedName{Name: remName, Namespace: f.OperatorNamespace}, rem)
	if err != nil {
		t.Fatal(err)
	}
	mcfgToBeDeleted := rem.Spec.Current.Object.DeepCopy()
	mcfgToBeDeleted.SetName(rem.GetMcName())
	err = f.Client.Delete(context.TODO(), mcfgToBeDeleted)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("successfully deleted MachineConfig deleted, will wait for the machines to come back up")

	dummyAction := func() error {
		return nil
	}
	poolHasNoMc := func(pool *mcfgv1.MachineConfigPool) (bool, error) {
		for _, mc := range pool.Status.Configuration.Source {
			if mc.Name == rem.GetMcName() {
				return false, nil
			}
		}

		return true, nil
	}

	// We need to wait for both the pool to update..
	err = f.WaitForMachinePoolUpdate(framework.TestPoolName, dummyAction, poolHasNoMc, nil)
	if err != nil {
		t.Fatalf("failed waiting for workers to come back up after deleting MachineConfig: %s", err)
	}

	// ..as well as the nodes
	f.WaitForNodesToBeReady()
}

package e2e

import (
	goctx "context"
	"fmt"
	"testing"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
)

func TestE2E(t *testing.T) {
	executeTests(t,
		//testExecution{
		//	Name:       "TestNodeSchedulingErrorFailsTheScan",
		//	IsParallel: false,
		//	TestFn: func(t *testing.T, f *framework.Framework, ctx *framework.Context, namespace string) error {
		//		workerNodesLabel := map[string]string{
		//			"node-role.kubernetes.io/worker": "",
		//		}
		//		workerNodes := getNodesWithSelectorOrFail(t, f, workerNodesLabel)
		//		//		taintedNode := &workerNodes[0]
		//		taintKey := "co-e2e"
		//		taintVal := "val"
		//		taint := corev1.Taint{
		//			Key:    taintKey,
		//			Value:  taintVal,
		//			Effect: corev1.TaintEffectNoSchedule,
		//		}
		//		if err := taintNode(t, f, taintedNode, taint); err != nil {
		//			E2ELog(t, "Tainting node failed")
		//			return err
		//		}
		//		suiteName := getObjNameFromTest(t)
		//		scanName := suiteName
		//		suite := &compv1alpha1.ComplianceSuite{
		//			ObjectMeta: metav1.ObjectMeta{
		//				Name:      suiteName,
		//				Namespace: namespace,
		//			},
		//			Spec: compv1alpha1.ComplianceSuiteSpec{
		//				Scans: []compv1alpha1.ComplianceScanSpecWrapper{
		//					{
		//						ComplianceScanSpec: compv1alpha1.ComplianceScanSpec{
		//							ContentImage: contentImagePath,
		//							Profile:      "xccdf_org.ssgproject.content_profile_moderate",
		//							Rule:         "xccdf_org.ssgproject.content_rule_no_netrc_files",
		//							Content:      rhcosContentFile,
		//							NodeSelector: workerNodesLabel,
		//							ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
		//								Debug: true,
		//							},
		//						},
		//						Name: scanName,
		//					},
		//				},
		//			},
		//		}
		//		if err := f.Client.Create(goctx.TODO(), suite, getCleanupOpts(ctx)); err != nil {
		//			return err
		//		}
		//		//		err := waitForSuiteScansStatus(t, f, namespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultError)
		//		if err != nil {
		//			return err
		//		}
		//		return removeNodeTaint(t, f, taintedNode.Name, taintKey)
		//	},
		//},
		testExecution{
			Name:       "TestKubeletConfigRemediation",
			IsParallel: false,
			TestFn: func(t *testing.T, f *framework.Framework, ctx *framework.Context, namespace string) error {
				suiteName := "kubelet-remediation-test-suite"

				tp := &compv1alpha1.TailoredProfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:      suiteName,
						Namespace: namespace,
					},
					Spec: compv1alpha1.TailoredProfileSpec{
						Title:       "kubelet-remediation-test",
						Description: "A test tailored profile to test kubelet remediation",
						EnableRules: []compv1alpha1.RuleReferenceSpec{
							{
								Name:      "ocp4-kubelet-enable-streaming-connections",
								Rationale: "To be tested",
							},
							{
								Name:      "ocp4-version-detect-in-ocp",
								Rationale: "To be tested",
							},
						},
						SetValues: []compv1alpha1.VariableValueSpec{
							{
								Name:      "ocp4-var-streaming-connection-timeouts",
								Rationale: "Value to be set",
								Value:     "8h0m0s",
							},
							{
								Name:      "ocp4-var-role-master",
								Rationale: "Value to be set",
								Value:     testPoolName,
							},
							{
								Name:      "ocp4-var-role-worker",
								Rationale: "Value to be set",
								Value:     testPoolName,
							},
						},
					},
				}
				createTPErr := f.Client.Create(goctx.TODO(), tp, getCleanupOpts(ctx))
				if createTPErr != nil {
					return createTPErr
				}

				ssb := &compv1alpha1.ScanSettingBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      suiteName,
						Namespace: namespace,
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

				err := f.Client.Create(goctx.TODO(), ssb, getCleanupOpts(ctx))
				if err != nil {
					return err
				}

				// Ensure that all the scans in the suite have finished and are marked as Done
				err = waitForSuiteScansStatus(t, f, namespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
				if err != nil {
					return err
				}

				scanName := suiteName

				// We need to check that the remediation is auto-applied and save
				// the object so we can delete it later
				remName := scanName + "-kubelet-enable-streaming-connections"
				waitForGenericRemediationToBeAutoApplied(t, f, remName, namespace)

				err = reRunScan(t, f, scanName, namespace)
				if err != nil {
					return err
				}

				// Scan has been re-started
				E2ELogf(t, "Scan phase should be reset")
				err = waitForSuiteScansStatus(t, f, namespace, suiteName, compv1alpha1.PhaseRunning, compv1alpha1.ResultNotAvailable)
				if err != nil {
					return err
				}

				// Ensure that all the scans in the suite have finished and are marked as Done
				E2ELogf(t, "Let's wait for it to be done now")
				err = waitForSuiteScansStatus(t, f, namespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultCompliant)
				if err != nil {
					return err
				}
				E2ELogf(t, "scan re-run has finished")

				// Now the check should be passing
				checkResult := compv1alpha1.ComplianceCheckResult{
					ObjectMeta: metav1.ObjectMeta{
						Name:      fmt.Sprintf("%s-kubelet-enable-streaming-connections", suiteName),
						Namespace: namespace,
					},
					ID:       "xccdf_org.ssgproject.content_rule_kubelet_enable_streaming_connections",
					Status:   compv1alpha1.CheckResultPass,
					Severity: compv1alpha1.CheckResultSeverityMedium,
				}
				err = assertHasCheck(f, suiteName, scanName, checkResult)
				if err != nil {
					return err
				}

				err = assertHasCheck(f, suiteName, scanName, checkResult)
				if err != nil {
					return err
				}

				// The remediation must not be Outdated
				remediation := &compv1alpha1.ComplianceRemediation{}
				remNsName := types.NamespacedName{
					Name:      remName,
					Namespace: namespace,
				}
				err = f.Client.Get(goctx.TODO(), remNsName, remediation)
				if err != nil {
					return fmt.Errorf("couldn't get remediation %s: %w", remName, err)
				}
				if remediation.Status.ApplicationState != compv1alpha1.RemediationApplied {
					return fmt.Errorf("remediation %s is not applied, but %s", remName, remediation.Status.ApplicationState)
				}

				E2ELogf(t, "The test succeeded!")
				return nil
			},
		},
	)
}

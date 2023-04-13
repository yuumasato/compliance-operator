package e2e

import (
	goctx "context"
	"fmt"
	"testing"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/e2eutil"
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
			Name:       "TestProfileBundleDefaultIsKept",
			IsParallel: false,
			TestFn: func(t *testing.T, f *framework.Framework, ctx *framework.Context, namespace string) error {
				var (
					otherImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "proff_diff_baseline")
					bctx       = goctx.Background()
				)

				ocpPb, err := getReadyProfileBundle(t, f, "ocp4", namespace)
				if err != nil {
					E2EFatalf(t, "error getting ocp4 profile: %s", err)
				}

				origImage := ocpPb.Spec.ContentImage

				ocpPbCopy := ocpPb.DeepCopy()
				ocpPbCopy.Spec.ContentImage = otherImage
				ocpPbCopy.Spec.ContentFile = rhcosContentFile
				if updateErr := f.Client.Update(bctx, ocpPbCopy); updateErr != nil {
					E2EFatalf(t, "error updating default ocp4 profile: %s", err)
				}

				if err := waitForProfileBundleStatus(t, f, namespace, "ocp4", compv1alpha1.DataStreamPending); err != nil {
					E2EFatalf(t, "ocp4 update didn't trigger a PENDING state: %s", err)
				}

				// Now wait for the processing to finish
				if err := waitForProfileBundleStatus(t, f, namespace, "ocp4", compv1alpha1.DataStreamValid); err != nil {
					E2EFatalf(t, "ocp4 update didn't trigger a PENDING state: %s", err)
				}

				// Delete compliance operator pods
				// This will trigger a reconciliation of the profile bundle
				// This is what would happen on an operator update.

				inNs := client.InNamespace(namespace)
				withLabel := client.MatchingLabels{
					"name": "compliance-operator",
				}
				if err := f.Client.DeleteAllOf(bctx, &corev1.Pod{}, inNs, withLabel); err != nil {
					return err
				}

				// Wait for the operator deletion to happen
				time.Sleep(retryInterval)

				err = e2eutil.WaitForOperatorDeployment(t, f.KubeClient, namespace,
					"compliance-operator", 1, retryInterval, timeout)
				if err != nil {
					E2EFatalf(t, "failed waiting for compliance-operator to come back up: %s", err)
				}

				var lastErr error
				pbkey := types.NamespacedName{Name: "ocp4", Namespace: namespace}
				timeouterr := wait.Poll(retryInterval, timeout, func() (bool, error) {
					pb := &compv1alpha1.ProfileBundle{}
					if lastErr := f.Client.Get(bctx, pbkey, pb); lastErr != nil {
						E2ELogf(t, "error getting ocp4 PB. Retrying: %s", err)
						return false, nil
					}
					if pb.Spec.ContentImage != origImage {
						E2ELogf(t, "PB ContentImage not updated yet: Got %s - Expected %s", pb.Spec.ContentImage, origImage)
						return false, nil
					}
					E2ELogf(t, "PB ContentImage up-to-date")
					return true, nil
				})
				if err := processErrorOrTimeout(lastErr, timeouterr, "waiting for ProfileBundle to update"); err != nil {
					return err
				}

				_, err = getReadyProfileBundle(t, f, "ocp4", namespace)
				if err != nil {
					E2EFatalf(t, "error getting valid and up-to-date PB: %s", err)
				}
				return nil
			},
		},
		testExecution{
			Name:       "TestVariableTemplate",
			IsParallel: false,
			TestFn: func(t *testing.T, f *framework.Framework, ctx *framework.Context, namespace string) error {

				var baselineImage = fmt.Sprintf("%s:%s", brokenContentImagePath, "variabletemplate")
				const requiredRule = "audit-profile-set"
				pbName := getObjNameFromTest(t)
				prefixName := func(profName, ruleBaseName string) string { return profName + "-" + ruleBaseName }

				ocpPb := &compv1alpha1.ProfileBundle{
					ObjectMeta: metav1.ObjectMeta{
						Name:      pbName,
						Namespace: namespace,
					},
					Spec: compv1alpha1.ProfileBundleSpec{
						ContentImage: baselineImage,
						ContentFile:  ocpContentFile,
					},
				}
				if err := f.Client.Create(goctx.TODO(), ocpPb, getCleanupOpts(ctx)); err != nil {
					return err
				}
				if err := waitForProfileBundleStatus(t, f, namespace, pbName, compv1alpha1.DataStreamValid); err != nil {
					return err
				}

				// Check that if the rule we are going to test is there
				err, found := doesRuleExist(f, ocpPb.Namespace, prefixName(pbName, requiredRule))
				if err != nil {
					return err
				} else if found != true {
					E2EErrorf(t, "Expected rule %s not found", prefixName(pbName, requiredRule))
					return err
				}

				suiteName := "audit-profile-set-test"
				scanName := "audit-profile-set-test"

				tp := &compv1alpha1.TailoredProfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:      suiteName,
						Namespace: namespace,
					},
					Spec: compv1alpha1.TailoredProfileSpec{
						Title:       "Audit-Profile-Set-Test",
						Description: "A test tailored profile to auto remediate audit profile set",
						EnableRules: []compv1alpha1.RuleReferenceSpec{
							{
								Name:      prefixName(pbName, requiredRule),
								Rationale: "To be tested",
							},
						},
						SetValues: []compv1alpha1.VariableValueSpec{
							{
								Name:      prefixName(pbName, "var-openshift-audit-profile"),
								Rationale: "Value to be set",
								Value:     "WriteRequestBodies",
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
						Name:     "default-auto-apply",
					},
				}
				err = f.Client.Create(goctx.TODO(), ssb, getCleanupOpts(ctx))
				if err != nil {
					return err
				}

				apiServerBeforeRemediation := &configv1.APIServer{}
				err = f.Client.Get(goctx.TODO(), types.NamespacedName{Name: "cluster"}, apiServerBeforeRemediation)
				if err != nil {
					return err
				}

				// Ensure that all the scans in the suite have finished and are marked as Done
				err = waitForSuiteScansStatus(t, f, namespace, suiteName, compv1alpha1.PhaseDone, compv1alpha1.ResultNonCompliant)
				if err != nil {
					return err
				}

				// We need to check that the remediation is auto-applied
				remName := "audit-profile-set-test-audit-profile-set"
				waitForGenericRemediationToBeAutoApplied(t, f, remName, namespace)

				// We can re-run the scan at this moment and check that it's now compliant
				// and it's reflected in a CheckResult
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
				auditProfileSet := compv1alpha1.ComplianceCheckResult{
					ObjectMeta: metav1.ObjectMeta{
						Name:      fmt.Sprintf("%s-audit-profile-set", scanName),
						Namespace: namespace,
					},
					ID:       "xccdf_org.ssgproject.content_rule_audit_profile_set",
					Status:   compv1alpha1.CheckResultPass,
					Severity: compv1alpha1.CheckResultSeverityMedium,
				}
				err = assertHasCheck(f, suiteName, scanName, auditProfileSet)
				if err != nil {
					return err
				}

				E2ELogf(t, "The test succeeded!")
				return nil

			},
		},
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

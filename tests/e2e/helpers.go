package e2e

import (
	"bytes"
	goctx "context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	"github.com/ComplianceAsCode/compliance-operator/tests/e2e/framework"
	mcfgv1 "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io/v1"
)

var contentImagePath string
var shouldLogContainerOutput bool
var brokenContentImagePath string

var defaultBackoff = backoff.WithMaxRetries(backoff.NewExponentialBackOff(), maxRetries)

type ObjectResouceVersioner interface {
	client.Object
	metav1.Common
}

func init() {
	contentImagePath = os.Getenv("CONTENT_IMAGE")

	if contentImagePath == "" {
		fmt.Println("Please set the 'CONTENT_IMAGE' environment variable")
		os.Exit(1)
	}

	logContainerOutputEnv := os.Getenv("LOG_CONTAINER_OUTPUT")
	if logContainerOutputEnv != "" {
		shouldLogContainerOutput = true
	}

	brokenContentImagePath = os.Getenv("BROKEN_CONTENT_IMAGE")

	if brokenContentImagePath == "" {
		fmt.Println("Please set the 'BROKEN_CONTENT_IMAGE' environment variable")
		os.Exit(1)
	}
}

type testExecution struct {
	Name       string
	IsParallel bool
	TestFn     func(*testing.T, *framework.Framework, *framework.Context, string) error
}

func E2ELogf(t *testing.T, format string, args ...interface{}) {
	t.Helper()
	t.Logf(fmt.Sprintf("%s: %s", time.Now().Format(time.RFC3339), format), args...)
}

func E2ELog(t *testing.T, args ...interface{}) {
	t.Helper()
	t.Log(fmt.Sprintf("%s: %s", time.Now().Format(time.RFC3339), fmt.Sprint(args...)))
}

func E2EErrorf(t *testing.T, format string, args ...interface{}) {
	t.Helper()
	t.Errorf(fmt.Sprintf("E2E-FAILURE: %s: %s", time.Now().Format(time.RFC3339), format), args...)
}

func E2EFatalf(t *testing.T, format string, args ...interface{}) {
	t.Helper()
	t.Fatalf(fmt.Sprintf("E2E-FAILURE: %s: %s", time.Now().Format(time.RFC3339), format), args...)
}

func getObjNameFromTest(t *testing.T) string {
	fullTestName := t.Name()
	regexForCapitals := regexp.MustCompile(`[A-Z]`)

	testNameInitIndex := strings.LastIndex(fullTestName, "/") + 1

	// Remove test prefix
	testName := fullTestName[testNameInitIndex:]

	// convert capitals to lower case letters with hyphens prepended
	hyphenedTestName := regexForCapitals.ReplaceAllStringFunc(
		testName,
		func(currentMatch string) string {
			return "-" + strings.ToLower(currentMatch)
		})
	// remove double hyphens
	testNameNoDoubleHyphens := strings.ReplaceAll(hyphenedTestName, "--", "-")
	// Remove leading and trailing hyphens
	return strings.Trim(testNameNoDoubleHyphens, "-")
}

// executeTest sets up everything that a e2e test needs to run, and executes the test.
func executeTests(t *testing.T, tests ...testExecution) {
	// get global framework variables
	f := framework.Global
	ctx := framework.NewContext(t)
	defer ctx.Cleanup()

	ns := f.OperatorNamespace

	// This context doesn't really do anything since we've already created
	// the machine config pools in the framework setUp(). We can remove
	// this when we flatten the tests.
	testtype := ctx.GetTestType()
	if testtype == framework.TestTypeAll || testtype == framework.TestTypeParallel {
		t.Run("Parallel tests", func(t *testing.T) {
			for _, test := range tests {
				// Don't lose test reference
				test := test
				if test.IsParallel {
					t.Run(test.Name, func(tt *testing.T) {
						tt.Parallel()
						if err := test.TestFn(tt, f, ctx, ns); err != nil {
							tt.Error(err)
						}
					})
				}
			}
		})
	} else {
		t.Log("Skipping parallel tests")
	}

	if testtype == framework.TestTypeAll || testtype == framework.TestTypeSerial {
		t.Run("Serial tests", func(t *testing.T) {
			for _, test := range tests {
				// Don't lose test reference
				test := test
				if !test.IsParallel {
					t.Run(test.Name, func(t *testing.T) {
						if err := test.TestFn(t, f, ctx, ns); err != nil {
							t.Error(err)
						}
					})
				}
			}
		})
	} else {
		t.Log("Skipping serial tests")
	}
}

func getCleanupOpts(ctx *framework.Context) *framework.CleanupOptions {
	return &framework.CleanupOptions{
		TestContext:   ctx,
		Timeout:       cleanupTimeout,
		RetryInterval: cleanupRetryInterval,
	}
}

// waitForProfileBundleStatus will poll until the compliancescan that we're lookingfor reaches a certain status, or until
// a timeout is reached.
func waitForProfileBundleStatus(t *testing.T, f *framework.Framework, namespace, name string, targetStatus compv1alpha1.DataStreamStatusType) error {
	pb := &compv1alpha1.ProfileBundle{}
	var lastErr error
	// retry and ignore errors until timeout
	timeouterr := wait.Poll(retryInterval, timeout, func() (bool, error) {
		lastErr = f.Client.Get(goctx.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, pb)
		if lastErr != nil {
			if apierrors.IsNotFound(lastErr) {
				E2ELogf(t, "Waiting for availability of %s ProfileBundle\n", name)
				return false, nil
			}
			E2ELogf(t, "Retrying. Got error: %v\n", lastErr)
			return false, nil
		}

		if pb.Status.DataStreamStatus == targetStatus {
			return true, nil
		}
		E2ELogf(t, "Waiting for run of %s ProfileBundle (%s)\n", name, pb.Status.DataStreamStatus)
		return false, nil
	})
	if err := processErrorOrTimeout(lastErr, timeouterr, "waiting for ProfileBundle status"); err != nil {
		return err
	}
	E2ELogf(t, "ProfileBundle ready (%s)\n", pb.Status.DataStreamStatus)
	return nil
}

// waitForScanStatus will poll until the compliancescan that we're lookingfor reaches a certain status, or until
// a timeout is reached.
func waitForScanStatus(t *testing.T, f *framework.Framework, namespace, name string, targetStatus compv1alpha1.ComplianceScanStatusPhase) {
	exampleComplianceScan := &compv1alpha1.ComplianceScan{}
	var lastErr error
	defer logContainerOutput(t, f, namespace, name)
	// retry and ignore errors until timeout
	timeoutErr := wait.Poll(retryInterval, timeout, func() (bool, error) {
		lastErr = f.Client.Get(goctx.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, exampleComplianceScan)
		if lastErr != nil {
			if apierrors.IsNotFound(lastErr) {
				E2ELogf(t, "Waiting for availability of %s compliancescan\n", name)
				return false, nil
			}
			E2ELogf(t, "Retrying. Got error: %v\n", lastErr)
			return false, nil
		}

		if exampleComplianceScan.Status.Phase == targetStatus {
			return true, nil
		}
		E2ELogf(t, "Waiting for run of %s compliancescan (%s)\n", name, exampleComplianceScan.Status.Phase)
		return false, nil
	})

	assertNoErrorNorTimeout(t, lastErr, timeoutErr, "waiting for compliance status")

	E2ELogf(t, "ComplianceScan ready (%s)\n", exampleComplianceScan.Status.Phase)
}

// waitForScanStatus will poll until the compliancescan that we're lookingfor reaches a certain status, or until
// a timeout is reached.
func waitForSuiteScansStatus(t *testing.T, f *framework.Framework, namespace, name string, targetStatus compv1alpha1.ComplianceScanStatusPhase, targetComplianceStatus compv1alpha1.ComplianceScanStatusResult) error {
	suite := &compv1alpha1.ComplianceSuite{}
	var lastErr error
	// retry and ignore errors until timeout
	defer logContainerOutput(t, f, namespace, name)
	timeouterr := wait.Poll(retryInterval, timeout, func() (bool, error) {
		lastErr = f.Client.Get(goctx.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, suite)
		if lastErr != nil {
			if apierrors.IsNotFound(lastErr) {
				E2ELogf(t, "Waiting for availability of %s compliancesuite\n", name)
				return false, nil
			}
			E2ELogf(t, "Retrying. Got error: %v\n", lastErr)
			return false, nil
		}

		if suite.Status.Phase != targetStatus {
			E2ELogf(t, "Waiting until suite %s reaches target status '%s'. Current status: %s", suite.Name, targetStatus, suite.Status.Phase)
			return false, nil
		}

		// The suite is now done, make sure the compliance status is expected
		if suite.Status.Result != targetComplianceStatus {
			return false, fmt.Errorf("expecting %s got %s", targetComplianceStatus, suite.Status.Result)
		}

		// If we were expecting an error, there's no use checking the scans
		if targetComplianceStatus == compv1alpha1.ResultError {
			return true, nil
		}

		// Now as a sanity check make sure that the scan statuses match the aggregated
		// suite status

		// Got the suite. There should be at least one scan or else we're still initialising
		if len(suite.Status.ScanStatuses) < 1 {
			return false, errors.New("not enough scan statuses")
		}

		//Examine the scan status both in the suite status and the scan
		for _, scanStatus := range suite.Status.ScanStatuses {
			if scanStatus.Phase != targetStatus {
				return false, fmt.Errorf("suite in status %s but scan wrapper %s in status %s", targetStatus, scanStatus.Name, scanStatus.Phase)
			}

			// If the status was present in the suite, then /any/ error
			// should fail the test as the scans should be read /from/
			// the scan itself
			waitForScanStatus(t, f, namespace, scanStatus.Name, targetStatus)
		}

		return true, nil
	})

	// Error in function call
	if lastErr != nil {
		return lastErr
	}

	// Timeout
	if timeouterr != nil {
		return timeouterr
	}

	E2ELogf(t, "All scans in ComplianceSuite have finished (%s)\n", suite.Name)
	return nil
}

func getPodsForScan(f *framework.Framework, scanName string) ([]corev1.Pod, error) {
	selectPods := map[string]string{
		compv1alpha1.ComplianceScanLabel: scanName,
	}
	var pods corev1.PodList
	lo := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(selectPods),
	}
	err := f.Client.List(goctx.TODO(), &pods, lo)
	if err != nil {
		return nil, err
	}
	return pods.Items, nil
}

func assertHasCheck(f *framework.Framework, suiteName, scanName string, check compv1alpha1.ComplianceCheckResult) error {
	var getCheck compv1alpha1.ComplianceCheckResult

	err := f.Client.Get(goctx.TODO(), types.NamespacedName{Name: check.Name, Namespace: check.Namespace}, &getCheck)
	if err != nil {
		return err
	}

	if getCheck.Status != check.Status {
		return fmt.Errorf("expected result %s got result %s", check.Status, getCheck.Status)
	}

	if getCheck.ID != check.ID {
		return fmt.Errorf("expected ID %s got ID %s", check.ID, getCheck.ID)
	}

	if getCheck.Labels == nil {
		return fmt.Errorf("complianceCheckResult has no labels")
	}

	if getCheck.Labels[compv1alpha1.SuiteLabel] != suiteName {
		return fmt.Errorf("Did not find expected suite name label %s, found %s", suiteName, getCheck.Labels[compv1alpha1.SuiteLabel])
	}

	if getCheck.Labels[compv1alpha1.ComplianceScanLabel] != scanName {
		return fmt.Errorf("Did not find expected scan name label %s, found %s", scanName, getCheck.Labels[compv1alpha1.ComplianceScanLabel])
	}

	if getCheck.Labels[compv1alpha1.ComplianceCheckResultSeverityLabel] != string(getCheck.Severity) {
		return fmt.Errorf("did not find expected severity name label %s, found %s", suiteName, getCheck.Labels[compv1alpha1.ComplianceCheckResultSeverityLabel])
	}

	if getCheck.Labels[compv1alpha1.ComplianceCheckResultStatusLabel] != string(getCheck.Status) {
		return fmt.Errorf("did not find expected status name label %s, found %s", suiteName, getCheck.Labels[compv1alpha1.ComplianceCheckResultStatusLabel])
	}

	return nil
}

type machineConfigActionFunc func() error
type poolPredicate func(t *testing.T, pool *mcfgv1.MachineConfigPool) (bool, error)

// waitForMachinePoolUpdate retrieves the original version of a MCP, then performs an
// action passed in as a parameter and then waits until a MCP passes a predicate
// If a pool is already given (poolPre), that will be used to check the previous state of the pool.
func waitForMachinePoolUpdate(t *testing.T, f *framework.Framework, name string, action machineConfigActionFunc, predicate poolPredicate, poolPre *mcfgv1.MachineConfigPool) error {
	if poolPre == nil {
		// initialize empty pool if it wasn't already given
		poolPre = &mcfgv1.MachineConfigPool{}
		err := f.Client.Get(goctx.TODO(), types.NamespacedName{Name: name}, poolPre)
		if err != nil {
			E2EErrorf(t, "Could not find the pool pre update")
			return err
		}
	}
	E2ELogf(t, "Pre-update, MC Pool %s has generation %d", poolPre.Name, poolPre.Status.ObservedGeneration)

	err := action()
	if err != nil {
		E2EErrorf(t, "Action failed %v", err)
		return err
	}

	err = wait.PollImmediate(machineOperationRetryInterval, machineOperationTimeout, func() (bool, error) {
		pool := &mcfgv1.MachineConfigPool{}
		err := f.Client.Get(goctx.TODO(), types.NamespacedName{Name: name}, pool)
		if err != nil {
			// even not found is a hard error here
			E2EErrorf(t, "Could not find the pool post update")
			return false, err
		}

		ok, err := predicate(t, pool)
		if err != nil {
			E2EErrorf(t, "Predicate failed %v", err)
			return false, err
		}

		if !ok {
			E2ELogf(t, "Predicate not true yet, waiting")
			return false, nil
		}

		E2ELogf(t, "Will check for update, Gen: %d, previous %d updated %d/%d unavailable %d",
			pool.Status.ObservedGeneration, poolPre.Status.ObservedGeneration,
			pool.Status.UpdatedMachineCount, pool.Status.MachineCount,
			pool.Status.UnavailableMachineCount)

		// Check if the pool has finished updating yet. If the pool was paused, we just check that
		// the generation was increased and wait for machines to reboot separately
		if (pool.Status.ObservedGeneration != poolPre.Status.ObservedGeneration) &&
			pool.Spec.Paused == true || ((pool.Status.UpdatedMachineCount == pool.Status.MachineCount) &&
			(pool.Status.UnavailableMachineCount == 0)) {
			E2ELogf(t, "The pool has updated")
			return true, nil
		}

		E2ELogf(t, "The pool has not updated yet. Gen: %d, expected %d updated %d/%d unavailable %d",
			pool.Status.ObservedGeneration, poolPre.Status.ObservedGeneration,
			pool.Status.UpdatedMachineCount, pool.Status.MachineCount,
			pool.Status.UnavailableMachineCount)
		return false, nil
	})

	if err != nil {
		return err
	}

	return nil
}

// waitForNodesToBeReady waits until all the nodes in the cluster have
// reached the expected machineConfig.
func waitForNodesToBeReady(t *testing.T, f *framework.Framework, errorMessage string) {
	err := wait.PollImmediate(machineOperationRetryInterval, machineOperationTimeout, func() (bool, error) {
		var nodes corev1.NodeList

		f.Client.List(goctx.TODO(), &nodes, &client.ListOptions{})
		for _, node := range nodes.Items {
			E2ELogf(t, "Node %s has config %s, desired config %s state %s",
				node.Name,
				node.Annotations["machineconfiguration.openshift.io/currentConfig"],
				node.Annotations["machineconfiguration.openshift.io/desiredConfig"],
				node.Annotations["machineconfiguration.openshift.io/state"])

			if (node.Annotations["machineconfiguration.openshift.io/currentConfig"] != node.Annotations["machineconfiguration.openshift.io/desiredConfig"]) ||
				(node.Annotations["machineconfiguration.openshift.io/state"] != "Done") {
				E2ELogf(t, "Node %s still updating", node.Name)
				return false, nil
			}
			E2ELogf(t, "Node %s was updated", node.Name)
		}

		E2ELogf(t, "All machines updated")
		return true, nil
	})

	if err != nil {
		E2EFatalf(t, "%s: %s", errorMessage, err)
	}
}

func applyRemediationAndCheck(t *testing.T, f *framework.Framework, namespace, name, pool string) error {
	rem := &compv1alpha1.ComplianceRemediation{}
	err := f.Client.Get(goctx.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, rem)
	if err != nil {
		return err
	}
	E2ELogf(t, "Remediation %s found", name)

	applyRemediation := func() error {
		rem.Spec.Apply = true
		err = f.Client.Update(goctx.TODO(), rem)
		if err != nil {
			E2EErrorf(t, "Cannot apply remediation")
			return err
		}
		E2ELogf(t, "Remediation applied")
		return nil
	}

	predicate := func(t *testing.T, pool *mcfgv1.MachineConfigPool) (bool, error) {
		// When checking if a MC is applied to a pool, we can't check the pool status
		// when the pool is paused..
		source := pool.Status.Configuration.Source
		if pool.Spec.Paused == true {
			source = pool.Spec.Configuration.Source
		}

		for _, mc := range source {
			if mc.Name == rem.GetMcName() {
				// When applying a remediation, check that the MC *is* in the pool
				E2ELogf(t, "Remediation %s present in pool %s, returning true", mc.Name, pool.Name)
				return true, nil
			}
		}

		E2ELogf(t, "Remediation %s not present in pool %s, returning false", rem.GetMcName(), pool.Name)
		return false, nil
	}

	err = waitForMachinePoolUpdate(t, f, pool, applyRemediation, predicate, nil)
	if err != nil {
		E2EErrorf(t, "Failed to wait for pool to update after applying MC: %v", err)
		return err
	}

	E2ELogf(t, "Machines updated with remediation")
	return nil
}

func removeObsoleteRemediationAndCheck(t *testing.T, f *framework.Framework, namespace, name, renderedMcName, pool string) error {
	rem := &compv1alpha1.ComplianceRemediation{}
	err := f.Client.Get(goctx.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, rem)
	if err != nil {
		return err
	}
	E2ELogf(t, "Remediation %s found", name)

	removeObsoleteContents := func() error {
		E2ELogf(t, "pre-update %v", rem.Status)
		remCopy := rem.DeepCopy()
		remCopy.Spec.Apply = true
		remCopy.Spec.Outdated.Object = nil
		err = f.Client.Update(goctx.TODO(), remCopy)
		if err != nil {
			E2EErrorf(t, "Cannot update remediation")
			return err
		}
		E2ELogf(t, "Obsolete data removed")

		rem2 := &compv1alpha1.ComplianceRemediation{}
		f.Client.Get(goctx.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, rem2)
		E2ELogf(t, "post-update %v", rem2.Status)

		return nil
	}

	// Get the MachineConfigPool before the remediation has been made current
	// This way, we can check that it changed without race-conditions
	poolBeforeRemediation := &mcfgv1.MachineConfigPool{}
	err = f.Client.Get(goctx.TODO(), types.NamespacedName{Name: testPoolName}, poolBeforeRemediation)
	if err != nil {
		return err
	}

	obsoleteMc := &mcfgv1.MachineConfig{}
	err = f.Client.Get(goctx.TODO(), types.NamespacedName{Name: renderedMcName}, obsoleteMc)
	if err != nil {
		return err
	}

	predicate := func(t *testing.T, pool *mcfgv1.MachineConfigPool) (bool, error) {
		// make sure the composite remediation has been re-rendered
		currentMc := &mcfgv1.MachineConfig{}
		err = f.Client.Get(goctx.TODO(), types.NamespacedName{Name: renderedMcName}, currentMc)
		if err != nil {
			return false, err
		}

		if currentMc.Generation == obsoleteMc.Generation {
			E2ELogf(t, "MC %s still has generation %d, looping", renderedMcName, currentMc.Generation)
			return false, nil
		}
		E2ELogf(t, "MC has been re-rendered from %d to %d", obsoleteMc.Generation, currentMc.Generation)
		return true, nil
	}

	err = waitForMachinePoolUpdate(t, f, pool, removeObsoleteContents, predicate, poolBeforeRemediation)
	if err != nil {
		E2EErrorf(t, "Failed to wait for pool to update after applying MC: %v", err)
		return err
	}

	E2ELogf(t, "Machines updated with remediation that is no longer obsolete")
	return nil
}

func assertRemediationIsObsolete(t *testing.T, f *framework.Framework, namespace, name string) {
	err, isObsolete := remediationIsObsolete(t, f, namespace, name)
	if err != nil {
		E2EFatalf(t, "%s", err)
	}
	if !isObsolete {
		E2EFatalf(t, "expected that the remediation is obsolete")
	}
}

func assertRemediationIsCurrent(t *testing.T, f *framework.Framework, namespace, name string) {
	err, isObsolete := remediationIsObsolete(t, f, namespace, name)
	if err != nil {
		E2EFatalf(t, "%s", err)
	}
	if isObsolete {
		E2EFatalf(t, "expected that the remediation is not obsolete")
	}
}

func remediationIsObsolete(t *testing.T, f *framework.Framework, namespace, name string) (error, bool) {
	rem := &compv1alpha1.ComplianceRemediation{}
	var lastErr error
	timeouterr := wait.Poll(retryInterval, timeout, func() (bool, error) {
		lastErr := f.Client.Get(goctx.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, rem)
		if lastErr != nil {
			return false, nil
		}
		return true, nil
	})
	if lastErr != nil {
		return fmt.Errorf("Got error trying to get remediation's obsolescence: %w", lastErr), false
	}
	if timeouterr != nil {
		return fmt.Errorf("Timed out trying to get remediation's obsolescence: %w", lastErr), false
	}
	E2ELogf(t, "Remediation %s found", name)

	if rem.Status.ApplicationState == compv1alpha1.RemediationOutdated &&
		rem.Spec.Outdated.Object != nil {
		return nil, true
	}

	return nil, false
}

func unApplyRemediationAndCheck(t *testing.T, f *framework.Framework, namespace, name, pool string) error {
	rem := &compv1alpha1.ComplianceRemediation{}
	err := f.Client.Get(goctx.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, rem)
	if err != nil {
		return err
	}
	E2ELogf(t, "Remediation found")

	applyRemediation := func() error {
		rem.Spec.Apply = false
		err = f.Client.Update(goctx.TODO(), rem)
		if err != nil {
			E2EErrorf(t, "Cannot apply remediation")
			return err
		}
		E2ELogf(t, "Remediation applied")
		return nil
	}

	predicate := func(t *testing.T, pool *mcfgv1.MachineConfigPool) (bool, error) {
		// We want to check that the MC created by the operator went away. Let's
		// poll the pool until we no longer see the remediation in the status
		for _, mc := range pool.Status.Configuration.Source {
			if mc.Name == rem.GetMcName() {
				E2ELogf(t, "Remediation %s present in pool %s, returning false", mc.Name, pool.Name)
				return false, nil
			}
		}

		E2ELogf(t, "Remediation %s not present in pool %s, returning true", rem.GetMcName(), pool.Name)
		return true, nil
	}

	err = waitForMachinePoolUpdate(t, f, pool, applyRemediation, predicate, nil)
	if err != nil {
		E2EErrorf(t, "Failed to wait for pool to update after applying MC: %v", err)
		return err
	}

	E2ELogf(t, "Machines updated with remediation")
	return nil
}

func waitForGenericRemediationToBeAutoApplied(t *testing.T, f *framework.Framework, remName, remNamespace string) {
	rem := &compv1alpha1.ComplianceRemediation{}
	var lastErr error
	timeouterr := wait.Poll(retryInterval, timeout, func() (bool, error) {
		lastErr = f.Client.Get(goctx.TODO(), types.NamespacedName{Name: remName, Namespace: remNamespace}, rem)
		if apierrors.IsNotFound(lastErr) {
			E2ELogf(t, "Waiting for availability of %s remediation\n", remName)
			return false, nil
		}
		if lastErr != nil {
			E2ELogf(t, "Retrying. Got error: %v\n", lastErr)
			return false, nil
		}
		E2ELogf(t, "Found remediation: %s\n", remName)
		if rem.Status.ApplicationState == compv1alpha1.RemediationNotApplied || rem.Status.ApplicationState == compv1alpha1.RemediationPending {
			E2ELogf(t, "Retrying. remediation not yet applied. Remediation Name: %s, ApplicationState: %s\n", remName, rem.Status.ApplicationState)
		}
		// wait for the remediation to get applied
		time.Sleep(5 * time.Second)
		return true, nil
	})
	assertNoErrorNorTimeout(t, lastErr, timeouterr, "getting remediation before auto-applying it")
	E2ELogf(t, "Machines updated with remediation")
	waitForNodesToBeReady(t, f, "Failed to wait for nodes to come back up after auto-applying remediation")
}

// IsMachineConfigPoolConditionPresentAndEqual returns true when conditionType is present and equal to status.
func IsMachineConfigPoolConditionPresentAndEqual(conditions []mcfgv1.MachineConfigPoolCondition, conditionType mcfgv1.MachineConfigPoolConditionType, status corev1.ConditionStatus) bool {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status == status
		}
	}
	return false
}

func getPoolNodeRoleSelector() map[string]string {
	return utils.GetNodeRoleSelector(testPoolName)
}

func doesRuleExist(f *framework.Framework, namespace, ruleName string) (error, bool) {
	return doesObjectExist(f, "Rule", namespace, ruleName)
}

func doesObjectExist(f *framework.Framework, kind, namespace, name string) (error, bool) {
	obj := unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   compv1alpha1.SchemeGroupVersion.Group,
		Version: compv1alpha1.SchemeGroupVersion.Version,
		Kind:    kind,
	})

	key := types.NamespacedName{Namespace: namespace, Name: name}
	err := f.Client.Get(goctx.TODO(), key, &obj)
	if apierrors.IsNotFound(err) {
		return nil, false
	} else if err == nil {
		return nil, true
	}

	return err, false
}

func getReadyProfileBundle(t *testing.T, f *framework.Framework, name, namespace string) (*compv1alpha1.ProfileBundle, error) {
	if err := waitForProfileBundleStatus(t, f, namespace, name, compv1alpha1.DataStreamValid); err != nil {
		return nil, err
	}

	pb := &compv1alpha1.ProfileBundle{}
	if err := f.Client.Get(goctx.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, pb); err != nil {
		return nil, err
	}

	return pb, nil
}

func writeToArtifactsDir(dir, scan, pod, container, log string) error {
	logPath := path.Join(dir, fmt.Sprintf("%s_%s_%s.log", scan, pod, container))
	logFile, err := os.Create(logPath)
	if err != nil {
		return err
	}
	// #nosec G307
	defer logFile.Close()
	_, err = io.WriteString(logFile, log)
	if err != nil {
		return err
	}
	logFile.Sync()
	return nil
}

func logContainerOutput(t *testing.T, f *framework.Framework, namespace, name string) {
	if shouldLogContainerOutput == false {
		return
	}

	// Try all container/init variants for each pod and the pod itself (self), log nothing if the container is not applicable.
	containers := []string{"self", "api-resource-collector", "log-collector", "scanner", "content-container"}
	artifacts := os.Getenv("ARTIFACT_DIR")
	if artifacts == "" {
		return
	}
	pods, err := getPodsForScan(f, name)
	if err != nil {
		E2ELogf(t, "Warning: Error getting pods for container logging: %s", err)
	} else {
		for _, pod := range pods {
			for _, con := range containers {
				logOpts := &corev1.PodLogOptions{}
				if con != "self" {
					logOpts.Container = con
				}
				req := f.KubeClient.CoreV1().Pods(namespace).GetLogs(pod.Name, logOpts)
				podLogs, err := req.Stream(goctx.TODO())
				if err != nil {
					// Silence this error if the container is not valid for the pod
					if !apierrors.IsBadRequest(err) {
						E2ELogf(t, "error getting logs for %s/%s: reason: %v, err: %v", pod.Name, con, apierrors.ReasonForError(err), err)
					}
					continue
				}
				buf := new(bytes.Buffer)
				_, err = io.Copy(buf, podLogs)
				if err != nil {
					E2ELogf(t, "error copying logs for %s/%s: %v", pod.Name, con, err)
					continue
				}
				logs := buf.String()
				if len(logs) == 0 {
					E2ELogf(t, "no logs for %s/%s", pod.Name, con)
				} else {
					err := writeToArtifactsDir(artifacts, name, pod.Name, con, logs)
					if err != nil {
						E2ELogf(t, "error writing logs for %s/%s: %v", pod.Name, con, err)
					} else {
						E2ELogf(t, "wrote logs for %s/%s", pod.Name, con)
					}
				}
			}
		}
	}
}

func reRunScan(t *testing.T, f *framework.Framework, scanName, namespace string) error {
	scanKey := types.NamespacedName{Name: scanName, Namespace: namespace}
	err := backoff.Retry(func() error {
		foundScan := &compv1alpha1.ComplianceScan{}
		geterr := f.Client.Get(goctx.TODO(), scanKey, foundScan)
		if geterr != nil {
			return geterr
		}

		scapCopy := foundScan.DeepCopy()
		if scapCopy.Annotations == nil {
			scapCopy.Annotations = make(map[string]string)
		}
		scapCopy.Annotations[compv1alpha1.ComplianceScanRescanAnnotation] = ""
		return f.Client.Update(goctx.TODO(), scapCopy)
	}, defaultBackoff)

	if err != nil {
		return fmt.Errorf("couldn't update scan to re-launch it: %w", err)
	}

	E2ELogf(t, "Scan re-launched")
	return nil
}

func updateSuiteContentImage(t *testing.T, f *framework.Framework, newImg, suiteName, suiteNs string) error {
	var lastErr error
	timeoutErr := wait.Poll(retryInterval, timeout, func() (bool, error) {
		suite := &compv1alpha1.ComplianceSuite{}
		// Now update the suite with a different image that contains different remediations
		lastErr = f.Client.Get(goctx.TODO(), types.NamespacedName{Name: suiteName, Namespace: suiteNs}, suite)
		if lastErr != nil {
			E2ELogf(t, "Got error while trying to get suite %s. Retrying... - %s", suiteName, lastErr)
			return false, nil
		}
		modSuite := suite.DeepCopy()
		modSuite.Spec.Scans[0].ContentImage = newImg
		lastErr = f.Client.Update(goctx.TODO(), modSuite)
		if lastErr != nil {
			E2ELogf(t, "Got error while trying to update suite %s. Retrying... - %s", suiteName, lastErr)
			return false, nil
		}
		return true, nil
	})

	if timeoutErr != nil {
		return fmt.Errorf("couldn't update suite's content image. Timed out: %w", timeoutErr)
	}
	if lastErr != nil {
		return fmt.Errorf("couldn't update suite's content image. Errored out: %w", lastErr)
	}
	return nil
}

func assertNoErrorNorTimeout(t *testing.T, err, timeoutErr error, message string) {
	if finalErr := processErrorOrTimeout(err, timeoutErr, message); finalErr != nil {
		E2EFatalf(t, "%s", finalErr)
	}
}

func processErrorOrTimeout(err, timeoutErr error, message string) error {
	// Error in function call
	if err != nil {
		return fmt.Errorf("Got error when %s: %w", message, err)
	}
	// Timeout
	if timeoutErr != nil {
		return fmt.Errorf("Timed out when %s: %w", message, timeoutErr)
	}
	return nil
}

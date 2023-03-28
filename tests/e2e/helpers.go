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
	"strconv"
	"strings"
	"testing"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	compscanctrl "github.com/ComplianceAsCode/compliance-operator/pkg/controller/compliancescan"
	compsuitectrl "github.com/ComplianceAsCode/compliance-operator/pkg/controller/compliancesuite"
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

func scanResultIsExpected(t *testing.T, f *framework.Framework, namespace, name string, expectedResult compv1alpha1.ComplianceScanStatusResult) error {
	cs := &compv1alpha1.ComplianceScan{}
	defer logContainerOutput(t, f, namespace, name)
	err := f.Client.Get(goctx.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, cs)
	if err != nil {
		return err
	}
	if cs.Status.Result != expectedResult {
		return fmt.Errorf("The ComplianceScan Result wasn't what we expected. Got '%s', expected '%s'", cs.Status.Result, expectedResult)
	}
	if expectedResult == compv1alpha1.ResultError {
		if cs.Status.ErrorMessage == "" {
			return fmt.Errorf("The ComplianceScan 'errormsg' wasn't set (it was empty). Even if we expected an error")
		}
	}
	return nil
}

func suiteErrorMessageMatchesRegex(t *testing.T, f *framework.Framework, namespace, name, regexToMatch string) error {
	E2ELogf(t, "Fetching suite: '%s'", name)
	cs := &compv1alpha1.ComplianceSuite{}
	key := types.NamespacedName{Name: name, Namespace: namespace}
	err := f.Client.Get(goctx.TODO(), key, cs)
	if err != nil {
		return err
	}
	re := regexp.MustCompile(regexToMatch)
	if !re.MatchString(cs.Status.ErrorMessage) {
		return fmt.Errorf("The error message found in the compliance suite '%s' "+
			"didn't match the expected regex. Found: '%s', Expected regex: '%s'",
			name, cs.Status.ErrorMessage, regexToMatch)
	}
	return nil
}

// getNodesWithSelector lists nodes according to a specific selector
func getNodesWithSelector(f *framework.Framework, labelselector map[string]string) ([]corev1.Node, error) {
	var nodes corev1.NodeList
	lo := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labelselector),
	}
	listErr := backoff.Retry(
		func() error {
			return f.Client.List(goctx.TODO(), &nodes, lo)
		},
		defaultBackoff)
	if listErr != nil {
		return nodes.Items, fmt.Errorf("couldn't list nodes with selector %s: %w", labelselector, listErr)
	}
	return nodes.Items, nil
}

func getNodesWithSelectorOrFail(t *testing.T, f *framework.Framework, labelselector map[string]string) []corev1.Node {
	nodes, err := getNodesWithSelector(f, labelselector)
	if err != nil {
		E2EFatalf(t, "couldn't get nodes with selector %s: %w", labelselector, err)
	}
	return nodes
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

func assertCheckRemediation(f *framework.Framework, name, namespace string, shouldHaveRem bool) error {
	var getCheck compv1alpha1.ComplianceCheckResult

	err := f.Client.Get(goctx.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, &getCheck)
	if err != nil {
		return err
	}

	_, hasRemLabel := getCheck.Labels[compv1alpha1.ComplianceCheckResultHasRemediation]
	if hasRemLabel != shouldHaveRem {
		return fmt.Errorf("unexpected label found: %v (expected: %s)", getCheck.Labels, strconv.FormatBool(shouldHaveRem))
	}

	// Also make sure a remediation with the same name exists (or not)
	var getRem compv1alpha1.ComplianceRemediation
	var hasRem bool

	err = f.Client.Get(goctx.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, &getRem)
	if apierrors.IsNotFound(err) {
		hasRem = false
	} else if err != nil {
		return err
	} else {
		hasRem = true
	}

	if hasRemLabel != shouldHaveRem {
		return fmt.Errorf("unexpected remediation object: expected: %s, found: %s", strconv.FormatBool(shouldHaveRem), strconv.FormatBool(hasRem))
	}

	return nil
}

func getRemediationsFromScan(f *framework.Framework, suiteName, scanName string) ([]compv1alpha1.ComplianceRemediation, error) {
	var scanSuiteRemediations compv1alpha1.ComplianceRemediationList

	scanSuiteSelector := make(map[string]string)
	scanSuiteSelector[compv1alpha1.SuiteLabel] = suiteName
	scanSuiteSelector[compv1alpha1.ComplianceScanLabel] = scanName

	listOpts := client.ListOptions{
		LabelSelector: labels.SelectorFromSet(scanSuiteSelector),
	}

	if err := f.Client.List(goctx.TODO(), &scanSuiteRemediations, &listOpts); err != nil {
		return nil, err
	}
	return scanSuiteRemediations.Items, nil
}

func assertHasRemediations(t *testing.T, f *framework.Framework, suiteName, scanName, roleLabel string, remNameList []string) error {
	var scanSuiteMapNames = make(map[string]bool)
	var scanSuiteRemediations []compv1alpha1.ComplianceRemediation

	// FIXME: This is a temporary hack. At the moment, the ARF parser is too slow
	// and it might take a bit for the remediations to appear. It would be cleaner
	// to signify somehow that the remediations were already processed, but in the
	// meantime, poll for 5 minutes while the remediations are being created
	err := wait.PollImmediate(retryInterval, timeout, func() (bool, error) {
		var listErr error
		scanSuiteRemediations, listErr = getRemediationsFromScan(f, suiteName, scanName)
		if listErr != nil {
			E2ELogf(t, "Error listing remediations. Retrying: %s", listErr)
		}
		for idx := range scanSuiteRemediations {
			rem := &scanSuiteRemediations[idx]
			scanSuiteMapNames[rem.Name] = true
		}

		for _, expRem := range remNameList {
			_, ok := scanSuiteMapNames[expRem]
			if !ok {
				E2ELogf(t, "expected remediation %s not yet found", expRem)
				return false, nil
			}
		}
		E2ELogf(t, "expected remediations found!")
		return true, nil
	})

	if err != nil {
		E2EErrorf(t, "Error waiting for remediations to appear")
		return err
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

func waitForRemediationToBeAutoApplied(t *testing.T, f *framework.Framework, remName, remNamespace string, pool *mcfgv1.MachineConfigPool) {
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
		return true, nil
	})
	assertNoErrorNorTimeout(t, lastErr, timeouterr, "getting remediation before auto-applying it")

	preNoop := func() error {
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

	err := waitForMachinePoolUpdate(t, f, pool.Name, preNoop, predicate, pool)
	if err != nil {
		E2EFatalf(t, "Failed to wait for pool to update after applying MC: %v", err)
	}

	E2ELogf(t, "Machines updated with remediation")
	waitForNodesToBeReady(t, f, "Failed to wait for nodes to come back up after auto-applying remediation")

	E2ELogf(t, "Remediation applied to machines and machines rebooted")
}

func unPauseMachinePoolAndWait(t *testing.T, f *framework.Framework, poolName string) {
	if err := unPauseMachinePool(t, f, poolName); err != nil {
		E2EFatalf(t, "Could not unpause the MC pool")
	}

	// When the pool updates, we need to wait for the machines to pick up the new rendered
	// config
	var lastErr error
	timeoutErr := wait.PollImmediate(machineOperationRetryInterval, machineOperationTimeout, func() (bool, error) {
		pool := &mcfgv1.MachineConfigPool{}
		lastErr = f.Client.Get(goctx.TODO(), types.NamespacedName{Name: poolName}, pool)
		if apierrors.IsNotFound(lastErr) {
			E2EFatalf(t, "Could not find the pool post update")
		} else if lastErr != nil {
			// even not found is a hard error here
			E2ELogf(t, "Got error while getting MachineConfigPool. Retrying: %s", lastErr)
			return false, nil
		}

		E2ELogf(t, "Will check for update, updated %d/%d unavailable %d",
			pool.Status.UpdatedMachineCount, pool.Status.MachineCount,
			pool.Status.UnavailableMachineCount)

		if pool.Status.UpdatedMachineCount == pool.Status.MachineCount &&
			pool.Status.UnavailableMachineCount == 0 {
			E2ELogf(t, "The pool has updated")
			return true, nil
		}

		E2ELogf(t, "The pool has not updated yet. updated %d/%d unavailable %d",
			pool.Status.UpdatedMachineCount, pool.Status.MachineCount,
			pool.Status.UnavailableMachineCount)
		return false, nil
	})
	if lastErr != nil {
		E2EFatalf(t, "Got error waiting for MCP unpausing: %s", timeoutErr)
	}
	if timeoutErr != nil {
		E2EFatalf(t, "Timed out waiting for MCP unpausing: %s", timeoutErr)
	}
}

func pauseMachinePool(t *testing.T, f *framework.Framework, poolName string) error {
	return modMachinePoolPause(t, f, poolName, true)
}

func unPauseMachinePool(t *testing.T, f *framework.Framework, poolName string) error {
	return modMachinePoolPause(t, f, poolName, false)
}

func modMachinePoolPause(t *testing.T, f *framework.Framework, poolName string, pause bool) error {
	pool := &mcfgv1.MachineConfigPool{}
	err := f.Client.Get(goctx.TODO(), types.NamespacedName{Name: poolName}, pool)
	if err != nil {
		E2EErrorf(t, "Could not find the pool to modify")
		return err
	}

	poolCopy := pool.DeepCopy()
	poolCopy.Spec.Paused = pause
	err = f.Client.Update(goctx.TODO(), poolCopy)
	if err != nil {
		E2EErrorf(t, "Could not update the pool")
		return err
	}

	return nil
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

func waitForCronJobWithSchedule(t *testing.T, f *framework.Framework, namespace, suiteName, schedule string) error {
	job := &batchv1.CronJob{}
	jobName := compsuitectrl.GetRerunnerName(suiteName)
	var lastErr error
	// retry and ignore errors until timeout
	timeouterr := wait.Poll(retryInterval, timeout, func() (bool, error) {
		lastErr = f.Client.Get(goctx.TODO(), types.NamespacedName{Name: jobName, Namespace: namespace}, job)
		if lastErr != nil {
			if apierrors.IsNotFound(lastErr) {
				E2ELogf(t, "Waiting for availability of %s CronJob\n", jobName)
				return false, nil
			}
			E2ELogf(t, "Retrying. Got error: %v\n", lastErr)
			return false, nil
		}

		if job.Spec.Schedule != schedule {
			E2ELogf(t, "Retrying. Schedule in found job (%s) doesn't match excpeted schedule: %s\n",
				job.Spec.Schedule, schedule)
			return false, nil
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
	E2ELogf(t, "Found %s CronJob\n", jobName)
	return nil
}

// privCommandTuplePodOnHost returns a pod that calls commandPre in an init container, then sleeps for an hour
// and registers commandPost to be run in a PreStop handler.
func privCommandTuplePodOnHost(namespace, name, nodeName, commandPre string, commandPost []string) *corev1.Pod {
	runAs := int64(0)
	priv := true

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{
				{
					Name:    name + "-init",
					Image:   "busybox",
					Command: []string{"/bin/sh"},
					Args:    []string{"-c", commandPre},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "hostroot",
							MountPath: "/hostroot",
						},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged: &priv,
						RunAsUser:  &runAs,
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:    name,
					Image:   "busybox",
					Command: []string{"/bin/sh"},
					Args:    []string{"-c", "sleep 3600"},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "hostroot",
							MountPath: "/hostroot",
						},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged: &priv,
						RunAsUser:  &runAs,
					},
					Lifecycle: &corev1.Lifecycle{
						PreStop: &corev1.LifecycleHandler{
							Exec: &corev1.ExecAction{Command: commandPost},
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "hostroot",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/",
						},
					},
				},
			},
			RestartPolicy: "Never",
			NodeSelector: map[string]string{
				corev1.LabelHostname: nodeName,
			},
			ServiceAccountName: "resultscollector",
		},
	}
}

// Creates a file /etc/securetty on the pod in an init container, then sleeps. The function returns the pod which
// the caller can later delete, at that point, the file would be removed
func createAndRemoveEtcSecurettyPod(namespace, name, nodeName string) *corev1.Pod {
	return privCommandTuplePodOnHost(namespace, name, nodeName, "touch /hostroot/etc/securetty", []string{"rm", "-f", "/hostroot/etc/securetty"})
}

func waitForPod(podCallback wait.ConditionFunc) error {
	return wait.PollImmediate(retryInterval, timeout, podCallback)
}

// check if pod name has priority class set to the given value.
func checkPodLimit(t *testing.T, c kubernetes.Interface, podName, namespace, cpuLimit, memLimit string) wait.ConditionFunc {
	return func() (bool, error) {
		pod, err := c.CoreV1().Pods(namespace).Get(goctx.TODO(), podName, metav1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return false, err
		}

		if apierrors.IsNotFound(err) {
			E2ELogf(t, "Pod %s not found yet", podName)
			return false, nil
		}

		for i := range pod.Spec.Containers {
			cnt := &pod.Spec.Containers[i]
			if cnt.Name != compscanctrl.PlatformScanResourceCollectorName && cnt.Name != compscanctrl.OpenSCAPScanContainerName {
				continue
			}

			if cnt.Resources.Limits.Cpu().String() != cpuLimit {
				return false, fmt.Errorf("container %s in pod %s has cpu limit %s, expected %s", cnt.Name, podName, cnt.Resources.Limits.Cpu().String(), cpuLimit)
			}

			if cnt.Resources.Limits.Memory().String() != memLimit {
				return false, fmt.Errorf("container %s in pod %s has memory limit %s, expected %s", cnt.Name, podName, cnt.Resources.Limits.Cpu().String(), cpuLimit)
			}
		}

		return true, nil
	}
}

// initContainerComplated returns a ConditionFunc that passes if all init containers have succeeded
func initContainerCompleted(t *testing.T, c kubernetes.Interface, name, namespace string) wait.ConditionFunc {
	return func() (bool, error) {
		pod, err := c.CoreV1().Pods(namespace).Get(goctx.TODO(), name, metav1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return false, err
		}
		if apierrors.IsNotFound(err) {
			E2ELogf(t, "Pod %s not found yet", name)
			return false, nil
		}

		for _, initStatus := range pod.Status.InitContainerStatuses {
			E2ELog(t, initStatus)
			// the init container must have passed the readiness probe
			if initStatus.Ready == false {
				E2ELog(t, "Init container not ready yet")
				return false, nil
			}

			// the init container must have terminated
			if initStatus.State.Terminated == nil {
				E2ELog(t, "Init container did not terminate yet")
				return false, nil
			}

			if initStatus.State.Terminated.ExitCode != 0 {
				return true, errors.New("the init container failed")
			} else {
				E2ELogf(t, "init container in pod %s has finished", name)
				return true, nil
			}
		}

		E2ELogf(t, "init container in pod %s not finished yet", name)
		return false, nil
	}
}

func runPod(t *testing.T, f *framework.Framework, namespace string, podToRun *corev1.Pod) (*corev1.Pod, error) {
	pod, err := f.KubeClient.CoreV1().Pods(namespace).Create(goctx.TODO(), podToRun, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	if err := waitForPod(initContainerCompleted(t, f.KubeClient, pod.Name, namespace)); err != nil {
		return nil, err
	}

	return pod, nil
}

// createAndRemoveEtcSecurettyOnNode creates a pod that creates the file /etc/securetty on node, returns the pod
// object for the caller to delete at which point the pod, before exiting, removes the file
func createAndRemoveEtcSecurettyOnNode(t *testing.T, f *framework.Framework, namespace, name, nodeName string) (*corev1.Pod, error) {
	return runPod(t, f, namespace, createAndRemoveEtcSecurettyPod(namespace, name, nodeName))
}

func taintNode(t *testing.T, f *framework.Framework, node *corev1.Node, taint corev1.Taint) error {
	taintedNode := node.DeepCopy()
	if taintedNode.Spec.Taints == nil {
		taintedNode.Spec.Taints = []corev1.Taint{}
	}
	taintedNode.Spec.Taints = append(taintedNode.Spec.Taints, taint)
	E2ELogf(t, "Tainting node: %s", taintedNode.Name)
	return f.Client.Update(goctx.TODO(), taintedNode)
}

func removeNodeTaint(t *testing.T, f *framework.Framework, nodeName, taintKey string) error {
	var lastErr error

	timeoutErr := wait.Poll(retryInterval, timeout, func() (bool, error) {
		taintedNode := &corev1.Node{}
		nodeKey := types.NamespacedName{Name: nodeName}
		if err := f.Client.Get(goctx.TODO(), nodeKey, taintedNode); err != nil {
			E2ELogf(t, "Couldn't get node: %s", nodeName)
			return false, nil
		}
		untaintedNode := taintedNode.DeepCopy()
		untaintedNode.Spec.Taints = []corev1.Taint{}
		for _, taint := range taintedNode.Spec.Taints {
			if taint.Key != taintKey {
				untaintedNode.Spec.Taints = append(untaintedNode.Spec.Taints, taint)
			}
		}

		E2ELogf(t, "Removing taint from node: %s", nodeName)
		lastErr = f.Client.Update(goctx.TODO(), untaintedNode)
		if lastErr != nil {
			E2ELogf(t, "Got error while trying to remove taint from %s, retrying", nodeName)
			return false, nil
		}
		return true, nil
	})

	if timeoutErr != nil {
		return fmt.Errorf("couldn't remove node taint. Timed out: %w", timeoutErr)
	}
	if lastErr != nil {
		return fmt.Errorf("couldn't remove node taint. Errored out: %w", lastErr)
	}
	return nil
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

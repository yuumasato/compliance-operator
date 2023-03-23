package framework

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func MainEntry(m *testing.M) {
	fopts := &frameworkOpts{}
	fopts.addToFlagSet(flag.CommandLine)
	// controller-runtime registers the --kubeconfig flag in client config
	// package:
	// https://github.com/kubernetes-sigs/controller-runtime/blob/v0.5.2/pkg/client/config/config.go#L39
	//
	// If this flag is not registered, do so. Otherwise retrieve its value.
	kcFlag := flag.Lookup(KubeConfigFlag)
	if kcFlag == nil {
		flag.StringVar(&fopts.kubeconfigPath, KubeConfigFlag, "", "path to kubeconfig")
	}

	flag.Parse()

	if kcFlag != nil {
		fopts.kubeconfigPath = kcFlag.Value.String()
	}

	f, err := newFramework(fopts)
	if err != nil {
		log.Fatalf("Failed to create framework: %v", err)
	}

	Global = f

	// Do suite setup
	if err := f.setUp(); err != nil {
		log.Fatal(err)
	}

	// Run the tests
	exitCode, err := f.runM(m)
	if err != nil {
		log.Fatal(err)
	}

	// Do suite teardown only if we have a successful test run or if we don't care
	// about removing the test resources if the test failed.
	if exitCode == 0 || (exitCode > 0 && !f.cleanupOnError) {
		if err = f.tearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

func (f *Framework) setUp() error {
	return nil
}

// tearDown performs any tasks necessary to cleanup resources leftover from testing
// and assumes a specific order. All namespaced resources must be cleaned up before
// deleting the cluster-wide resources, like roles, service accounts, or the deployment.
// If we don't properly cleanup resources before deleting CRDs, it leaves resources in a
// terminating state, making them harder to cleanup.
func (f *Framework) tearDown() error {
	// Make sure all scans are cleaned up before we delete the CRDs. Scans should be cleaned up
	// because they're owned by ScanSettingBindings or ScanSuites, which should be cleaned up
	// by each individual test either directly or through deferred cleanup. If the test fails
	// because there are scans that haven't been cleaned up, we could have a bug in the
	// tests.
	err := f.waitForScanCleanup()
	if err != nil {
		return err
	}

	// Clean up these resources explicitly in this method because it's guaranteed to run
	// after all the tests execute. It's also safer to clean up resources that require
	// a specific cleanup order explicitly than to rely on Go's defer function. Defer
	// is implemented as a stack, and doesn't guarantee safety across go routines
	// (which may be the case with parallel tests), making it possible for some
	// resources to get cleaned up before others. We don't want that to happen with
	// cluster resources like CRDs, because it will orphan custom resource instances
	// that haven't been cleaned up, yet.
	log.Printf("cleaning up namespaced resources in %s\n", f.OperatorNamespace)
	err = f.cleanUpFromYAMLFile(f.NamespacedManPath)
	if err != nil {
		return err
	}

	log.Println("cleaning up cluster resources")
	err = f.cleanUpFromYAMLFile(&f.globalManPath)
	if err != nil {
		return err
	}

	log.Printf("cleaning up namespace %s\n", f.OperatorNamespace)
	err = f.KubeClient.CoreV1().Namespaces().Delete(context.TODO(), f.OperatorNamespace, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to cleanup namespace %s: %w", f.OperatorNamespace, err)
	}
	return nil
}

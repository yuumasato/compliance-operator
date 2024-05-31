package rosa_e2e

import (
	"context"
	"log"
	"os"
	"testing"

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

	exitCode := m.Run()
	if exitCode == 0 || (exitCode > 0 && f.CleanUpOnError()) {
		if err = f.TearDown(); err != nil {
			log.Fatal(err)
		}
	}
	os.Exit(exitCode)
}

func TestInstallOnlyParsesNodeProfiles(t *testing.T) {
	t.Parallel()
	f := framework.Global

	// list all profiles
	l := compv1alpha1.ProfileList{}
	err := f.Client.List(context.TODO(), &l)
	if err != nil {
		f.PrintROSADebugInfo(t)
		t.Fatalf("failed to get ProfileList: %s", err)
	}

	// assert profiles are loaded from both bundles
	// for each profile, assert it's is a node profile
	for _, p := range l.Items {
		pt := p.Annotations[compv1alpha1.ProductTypeAnnotation]
		if pt != "Node" {
			f.PrintROSADebugInfo(t)
			t.Fatalf("found an unexpected profile type: %s of type %s", p.GetName(), pt)
		}
	}

}

func TestScanSetting(t *testing.T) {
	f := framework.Global
	// prinout all scan settings
	scanSettingList := compv1alpha1.ScanSettingList{}
	err := f.Client.List(context.TODO(), &scanSettingList)
	if err != nil {
		t.Fatalf("Failed to list scan settings: %v", err)
	}
	for _, scanSetting := range scanSettingList.Items {
		if scanSetting.Name == "default-auto-apply" {
			f.PrintROSADebugInfo(t)
			t.Fatalf("ScanSetting: %s is not expected", scanSetting.Name)
		}
		t.Logf("ScanSetting: %s", scanSetting.Name)
		for _, role := range scanSetting.Roles {
			if role == "master" {
				f.PrintROSADebugInfo(t)
				t.Fatalf("Role: %s is not expected", role)
			}
			t.Logf("Role: %s", role)

		}
	}
}

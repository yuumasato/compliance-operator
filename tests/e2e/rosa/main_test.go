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
		t.Fatalf("failed to get ProfileList: %s", err)
	}

	// assert profiles are loaded from both bundles
	// for each profile, assert it's is a node profile
	for _, p := range l.Items {
		pt := p.Annotations[compv1alpha1.ProductTypeAnnotation]
		if pt != "Node" {
			t.Fatalf("found an unexpected profile type: %s of type %s", p.GetName(), pt)
		}
	}

}

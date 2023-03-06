package framework

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

// readFile accepts a file path and returns the file contents.
func (f *Framework) readFile(p *string) ([]byte, error) {
	y, err := os.ReadFile(*p)
	if err != nil {
		log.Printf("unable to read contents of %s: %s", *p, err)
		return nil, err
	}
	return y, nil
}

// readYAML accepts a byte string that is YAML-like and attempts to read
// it into a slice of byte strings where each element in the slice is a
// separate YAML document delimited by "---". This is useful for working
// with files that contain multiple YAML documents.
func (f *Framework) readYAML(y []byte) ([][]byte, error) {
	o := make([][]byte, 0)

	s := NewYAMLScanner(bytes.NewBuffer(y))
	for s.Scan() {
		// Grab the current YAML document
		d := s.Bytes()

		// Convert to JSON and attempt to decode it
		obj := &unstructured.Unstructured{}
		j, err := yaml.YAMLToJSON(d)
		if err != nil {
			return nil, fmt.Errorf("could not convert yaml document to json: %w", err)
		}
		if err := obj.UnmarshalJSON(j); err != nil {
			return nil, fmt.Errorf("failed to decode object spec: %w", err)
		}
		o = append(o, j)
	}
	return o, nil
}

func (f *Framework) cleanUpFromYAMLFile(p *string) error {
	c, err := f.readFile(p)
	if err != nil {
		return err
	}
	documents, err := f.readYAML(c)
	if err != nil {
		return err
	}

	for _, d := range documents {
		obj := &unstructured.Unstructured{}
		if err := obj.UnmarshalJSON(d); err != nil {
			return fmt.Errorf("failed to unmarshal object spec: %w", err)
		}
		obj.SetNamespace(f.OperatorNamespace)
		log.Printf("deleting %s %s", obj.GetKind(), obj.GetName())
		if err := f.Client.Delete(context.TODO(), obj); err != nil {
			return fmt.Errorf("failed to delete %s: %w", obj, err)
		}
	}
	return nil
}

func (f *Framework) waitForScanCleanup() error {
	timeouterr := wait.Poll(time.Second*5, time.Minute*2, func() (bool, error) {
		var scans compv1alpha1.ComplianceScanList
		f.Client.List(context.TODO(), &scans, &client.ListOptions{})
		if len(scans.Items) == 0 {
			return true, nil
		}
		log.Printf("%d scans not cleaned up\n", len(scans.Items))
		for _, i := range scans.Items {
			log.Printf("scan %s still exists in namespace %s", i.Name, i.Namespace)
		}
		return false, nil
	})

	if timeouterr != nil {
		return fmt.Errorf("timed out waiting for scans to cleanup: %w", timeouterr)

	}
	return nil
}

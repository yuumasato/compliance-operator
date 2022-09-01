package compliancescan

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
)

var _ = Describe("Test forwarding factory", func() {

	Context("Without debug enabled in scan", func() {
		It("should return a noop forwarding implementation", func() {
			s := &compv1alpha1.ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: compv1alpha1.ComplianceScanSpec{
					ScanType: compv1alpha1.ScanTypeNode,
					ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
						RawResultStorage: compv1alpha1.RawResultStorageSettings{
							PVAccessModes: defaultAccessMode,
							Size:          compv1alpha1.DefaultRawStorageSize,
						},
					},
				},
			}
			f := NewForwarder(s)
			Expect(f).To(Equal(noopForwarder{}))
		})
	})

	Context("With debug enabled in scan", func() {
		It("should return a log forwarding implementation", func() {
			s := &compv1alpha1.ComplianceScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: compv1alpha1.ComplianceScanSpec{
					ScanType: compv1alpha1.ScanTypeNode,
					ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
						Debug: true,
						RawResultStorage: compv1alpha1.RawResultStorageSettings{
							PVAccessModes: defaultAccessMode,
							Size:          compv1alpha1.DefaultRawStorageSize,
						},
					},
				},
			}
			f := NewForwarder(s)
			Expect(f).To(Equal(logForwarder{}))
		})
	})

})

package compliancescan

import (
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
)

func NewForwarder(s *compv1alpha1.ComplianceScan) Forwarder {
	// Figure out what type of forwarding implementation we need based on
	// scan configuration. By default, use the noopForwarder which doesn't
	// do anything and maintains backwards compatibility.
	if s.Spec.Debug {
		logf.Log.Info("Forwarding compliance results and remediations to logs")
		return logForwarder{}
	}
	logf.Log.Info("Result and remediation forwarding is disabled")
	return noopForwarder{}
}

type Forwarder interface {
	SendComplianceCheckResult(c *compv1alpha1.ComplianceCheckResult) error
	SendComplianceRemediation(r *compv1alpha1.ComplianceRemediation) error
}

type logForwarder struct{}

func (f logForwarder) SendComplianceCheckResult(c *compv1alpha1.ComplianceCheckResult) error {
	logf.Log.Info("ComplianceCheckResult", c.ID, c.Status)
	return nil
}

func (f logForwarder) SendComplianceRemediation(r *compv1alpha1.ComplianceRemediation) error {
	logf.Log.Info("ComplianceRemediation", "ComplianceRemediation.Name", r.Name)
	return nil
}

type noopForwarder struct{}

func (f noopForwarder) SendComplianceCheckResult(c *compv1alpha1.ComplianceCheckResult) error {
	return nil
}

func (f noopForwarder) SendComplianceRemediation(r *compv1alpha1.ComplianceRemediation) error {
	return nil
}

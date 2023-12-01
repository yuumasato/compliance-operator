package tailoredprofile

import (
	"context"

	"github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type variableMapper struct {
	client.Client
}

func (t *variableMapper) Map(ctx context.Context, obj client.Object) []reconcile.Request {
	var requests []reconcile.Request

	tpList := v1alpha1.TailoredProfileList{}
	err := t.List(ctx, &tpList, &client.ListOptions{})
	if err != nil {
		return requests
	}

	for _, tp := range tpList.Items {
		add := false

		for _, variable := range tp.Spec.SetValues {
			if variable.Name != obj.GetName() {
				continue
			}
			add = true
			break
		}

		if add == false {
			continue
		}

		objKey := types.NamespacedName{
			Name:      tp.GetName(),
			Namespace: tp.GetNamespace(),
		}
		requests = append(requests, reconcile.Request{NamespacedName: objKey})
	}

	return requests
}

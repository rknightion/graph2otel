package license

import (
	"context"
	"fmt"

	"github.com/microsoftgraph/msgraph-sdk-go/models"

	"github.com/rknightion/graph2otel/internal/graphclient"
)

// graphSkuLister is the real SkuLister: it reads a tenant's subscribedSkus
// through the Graph client built by internal/graphclient and flattens every
// SKU's service plans into the ServicePlan shape Detect consumes.
type graphSkuLister struct {
	client *graphclient.Client
}

// NewGraphSkuLister returns a SkuLister backed by client's Graph API
// connection. client must be non-nil.
func NewGraphSkuLister(client *graphclient.Client) SkuLister {
	return &graphSkuLister{client: client}
}

// ListServicePlans calls GET /subscribedSkus and flattens every returned
// SKU's servicePlans into ServicePlan entries. A read-only, least-privilege
// Graph permission (Organization.Read.All) is sufficient for this call.
func (l *graphSkuLister) ListServicePlans(ctx context.Context) ([]ServicePlan, error) {
	resp, err := l.client.Graph.SubscribedSkus().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("license: get subscribedSkus: %s", graphclient.FormatODataError(err))
	}
	return flattenServicePlans(resp.GetValue()), nil
}

// flattenServicePlans extracts every service plan across every SKU in skus
// into the package's SDK-independent ServicePlan shape. A nil-valued field on
// a given service plan (Graph docs the whole triple as always present, but
// the SDK types every field as an optional pointer) yields its zero value
// rather than panicking.
func flattenServicePlans(skus []models.SubscribedSkuable) []ServicePlan {
	var out []ServicePlan
	for _, sku := range skus {
		if sku == nil {
			continue
		}
		for _, sp := range sku.GetServicePlans() {
			if sp == nil {
				continue
			}
			var id string
			if v := sp.GetServicePlanId(); v != nil {
				id = v.String()
			}
			var name string
			if v := sp.GetServicePlanName(); v != nil {
				name = *v
			}
			var status string
			if v := sp.GetProvisioningStatus(); v != nil {
				status = *v
			}
			out = append(out, ServicePlan{
				ServicePlanId:      id,
				ServicePlanName:    name,
				ProvisioningStatus: status,
			})
		}
	}
	return out
}

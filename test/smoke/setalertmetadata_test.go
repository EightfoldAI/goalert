package smoke

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

// TestSetAlertMetadata verifies setAlertMetadata merges into an alert's
// existing metadata rather than replacing it, and is rejected once the alert
// is closed.
func TestSetAlertMetadata(t *testing.T) {
	const sql = `
	insert into escalation_policies (id, name)
	values
		({{uuid "eid"}}, 'esc policy');
	insert into services (id, escalation_policy_id, name)
	values
		({{uuid "sid"}}, {{uuid "eid"}}, 'service');
	`

	h := harness.NewHarness(t, sql, "")
	defer h.Close()

	type metaKV struct {
		Key   string
		Value string
	}
	getMeta := func(alertID int) map[string]string {
		res := h.GraphQLQuery2(fmt.Sprintf(`query{alert(id:%d){status meta{key value}}}`, alertID))
		require.Empty(t, res.Errors)

		var result struct {
			Alert struct {
				Status string
				Meta   []metaKV
			}
		}
		require.NoError(t, json.Unmarshal(res.Data, &result))

		out := make(map[string]string, len(result.Alert.Meta))
		for _, kv := range result.Alert.Meta {
			out[kv.Key] = kv.Value
		}
		return out
	}

	// Create with initial metadata, as an ingress integration would at
	// alert-creation time.
	res := h.GraphQLQuery2(`mutation{createAlert(input:{serviceID:"` + h.UUID("sid") + `",summary:"test",meta:[{key:"source", value:"cloudwatch"}]}){alertID}}`)
	require.Empty(t, res.Errors)

	var created struct {
		CreateAlert struct{ AlertID int }
	}
	require.NoError(t, json.Unmarshal(res.Data, &created))
	alertID := created.CreateAlert.AlertID

	require.Equal(t, map[string]string{"source": "cloudwatch"}, getMeta(alertID))

	t.Run("adds a new key without touching existing ones", func(t *testing.T) {
		res := h.GraphQLQuery2(fmt.Sprintf(`mutation{setAlertMetadata(input:{alertID:%d, meta:[{key:"jira_ticket", value:"CLOP-123"}]})}`, alertID))
		require.Empty(t, res.Errors)

		require.Equal(t, map[string]string{
			"source":      "cloudwatch",
			"jira_ticket": "CLOP-123",
		}, getMeta(alertID))
	})

	t.Run("overwrites an existing key, leaves others alone", func(t *testing.T) {
		res := h.GraphQLQuery2(fmt.Sprintf(`mutation{setAlertMetadata(input:{alertID:%d, meta:[{key:"source", value:"cloudwatch-updated"}]})}`, alertID))
		require.Empty(t, res.Errors)

		require.Equal(t, map[string]string{
			"source":      "cloudwatch-updated",
			"jira_ticket": "CLOP-123",
		}, getMeta(alertID))
	})

	t.Run("rejected once the alert is closed", func(t *testing.T) {
		res := h.GraphQLQuery2(fmt.Sprintf(`mutation{updateAlerts(input:{alertIDs:[%d], newStatus: StatusClosed}){id}}`, alertID))
		require.Empty(t, res.Errors)

		before := getMeta(alertID)

		res = h.GraphQLQuery2(fmt.Sprintf(`mutation{setAlertMetadata(input:{alertID:%d, meta:[{key:"jira_ticket", value:"CLOP-999"}]})}`, alertID))
		require.NotEmpty(t, res.Errors, "expected an error setting metadata on a closed alert")

		require.Equal(t, before, getMeta(alertID), "metadata must be unchanged after a rejected update")
	})

	t.Run("rejected for a nonexistent alert", func(t *testing.T) {
		res := h.GraphQLQuery2(`mutation{setAlertMetadata(input:{alertID: 999999999, meta:[{key:"x", value:"y"}]})}`)
		require.NotEmpty(t, res.Errors)
	})
}

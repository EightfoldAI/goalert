package smoke

import (
	"encoding/json"
	"fmt"
	"sync"
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

	t.Run("an empty value is stored, not treated as a delete", func(t *testing.T) {
		// Pins what the schema documents. There is no delete operation, so an empty
		// value must round-trip as an empty string with the key still present --
		// otherwise callers storing a legitimately empty value would lose the key.
		res := h.GraphQLQuery2(fmt.Sprintf(`mutation{setAlertMetadata(input:{alertID:%d, meta:[{key:"jira_ticket", value:""}]})}`, alertID))
		require.Empty(t, res.Errors)

		meta := getMeta(alertID)
		require.Contains(t, meta, "jira_ticket", "key must survive an empty value")
		require.Equal(t, "", meta["jira_ticket"])
		require.Equal(t, "cloudwatch-updated", meta["source"], "other keys must be untouched")

		// Restore, so the closed-alert subtest below still asserts against a
		// meaningful value.
		res = h.GraphQLQuery2(fmt.Sprintf(`mutation{setAlertMetadata(input:{alertID:%d, meta:[{key:"jira_ticket", value:"CLOP-123"}]})}`, alertID))
		require.Empty(t, res.Errors)
	})

	t.Run("concurrent sets of different keys both survive", func(t *testing.T) {
		// Reproduces the realistic conflict: two automations, each writing a
		// different key on the same alert at the same time (e.g. a Jira automation
		// setting jira_ticket while a PagerDuty bridge sets pd_incident). Without
		// LockMetadataTx serializing the read-modify-write, both read the same
		// starting document and the later writer's INSERT ... ON CONFLICT DO UPDATE
		// silently discards whatever the other added -- while still returning true.
		const n = 8
		var wg sync.WaitGroup
		errs := make([]bool, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				res := h.GraphQLQuery2(fmt.Sprintf(`mutation{setAlertMetadata(input:{alertID:%d, meta:[{key:"concurrent_%d", value:"v%d"}]})}`, alertID, i, i))
				errs[i] = len(res.Errors) > 0
			}(i)
		}
		wg.Wait()

		for i, hadErr := range errs {
			require.False(t, hadErr, "concurrent setAlertMetadata call %d returned an error", i)
		}

		meta := getMeta(alertID)
		for i := 0; i < n; i++ {
			require.Equal(t, fmt.Sprintf("v%d", i), meta[fmt.Sprintf("concurrent_%d", i)],
				"key from concurrent call %d must not have been lost", i)
		}
		// Pre-existing keys from earlier subtests must also have survived.
		require.Equal(t, "cloudwatch-updated", meta["source"])
		require.Equal(t, "CLOP-123", meta["jira_ticket"])
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

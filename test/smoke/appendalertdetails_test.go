package smoke

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

// TestAppendAlertDetails verifies appendAlertDetails appends to an alert's
// existing Details rather than replacing it, truncates rather than errors
// when the combined text is too long, and is rejected once the alert is
// closed.
func TestAppendAlertDetails(t *testing.T) {
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

	getDetails := func(alertID int) string {
		res := h.GraphQLQuery2(fmt.Sprintf(`query{alert(id:%d){status details}}`, alertID))
		require.Empty(t, res.Errors)

		var result struct {
			Alert struct {
				Status  string
				Details string
			}
		}
		require.NoError(t, json.Unmarshal(res.Data, &result))
		return result.Alert.Details
	}

	res := h.GraphQLQuery2(`mutation{createAlert(input:{serviceID:"` + h.UUID("sid") + `",summary:"test",details:"State: OK -> ALARM"}){alertID}}`)
	require.Empty(t, res.Errors)

	var created struct {
		CreateAlert struct{ AlertID int }
	}
	require.NoError(t, json.Unmarshal(res.Data, &created))
	alertID := created.CreateAlert.AlertID

	require.Equal(t, "State: OK -> ALARM", getDetails(alertID))

	t.Run("appends without touching existing content", func(t *testing.T) {
		res := h.GraphQLQuery2(fmt.Sprintf(`mutation{appendAlertDetails(input:{alertID:%d, text:"Ticket: CLOP-123"})}`, alertID))
		require.Empty(t, res.Errors)

		require.Equal(t, "State: OK -> ALARM\n\nTicket: CLOP-123", getDetails(alertID))
	})

	t.Run("a second append stacks rather than overwrites", func(t *testing.T) {
		res := h.GraphQLQuery2(fmt.Sprintf(`mutation{appendAlertDetails(input:{alertID:%d, text:"Also see CLOP-124"})}`, alertID))
		require.Empty(t, res.Errors)

		require.Equal(t, "State: OK -> ALARM\n\nTicket: CLOP-123\n\nAlso see CLOP-124", getDetails(alertID))
	})

	t.Run("combined text over the length limit is truncated, not rejected", func(t *testing.T) {
		// A resolver that errored here would be a worse outcome than truncating --
		// the alert already exists and is actionable; losing the append entirely
		// over a length overflow would just discard useful information.
		long := strings.Repeat("x", 10000)
		res := h.GraphQLQuery2(fmt.Sprintf(`mutation{appendAlertDetails(input:{alertID:%d, text:%q})}`, alertID, long))
		require.Empty(t, res.Errors)

		details := getDetails(alertID)
		require.LessOrEqual(t, len([]rune(details)), 6144)
		require.True(t, strings.HasSuffix(details, "…"), "expected truncation marker, got: %s", details[len(details)-20:])
	})

	t.Run("rejected once the alert is closed", func(t *testing.T) {
		res := h.GraphQLQuery2(`mutation{createAlert(input:{serviceID:"` + h.UUID("sid") + `",summary:"closeme",details:"original"}){alertID}}`)
		require.Empty(t, res.Errors)
		var created struct {
			CreateAlert struct{ AlertID int }
		}
		require.NoError(t, json.Unmarshal(res.Data, &created))
		closedID := created.CreateAlert.AlertID

		res = h.GraphQLQuery2(fmt.Sprintf(`mutation{updateAlerts(input:{alertIDs:[%d], newStatus: StatusClosed}){id}}`, closedID))
		require.Empty(t, res.Errors)

		res = h.GraphQLQuery2(fmt.Sprintf(`mutation{appendAlertDetails(input:{alertID:%d, text:"too late"})}`, closedID))
		require.NotEmpty(t, res.Errors, "expected an error appending details on a closed alert")

		require.Equal(t, "original", getDetails(closedID), "details must be unchanged after a rejected update")
	})

	t.Run("rejected for a nonexistent alert", func(t *testing.T) {
		res := h.GraphQLQuery2(`mutation{appendAlertDetails(input:{alertID: 999999999, text:"x"})}`)
		require.NotEmpty(t, res.Errors)
	})
}

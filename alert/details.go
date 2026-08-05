package alert

import (
	"context"

	"github.com/target/goalert/gadb"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation/validate"
)

// LockDetailsTx returns an alert's current Details, locking its row for the rest
// of the transaction.
//
// This exists so an append can be done as a read-modify-write without losing a
// concurrent one: the lock makes a second appender wait for the first to commit
// and then read the value it wrote, instead of both reading the same original and
// one overwriting the other.
func (s Store) LockDetailsTx(ctx context.Context, db gadb.DBTX, alertID int) (string, error) {
	err := permission.LimitCheckAny(ctx, permission.User, permission.Service)
	if err != nil {
		return "", err
	}

	return gadb.New(db).Alert_LockOneAlertDetails(ctx, gadb.Alert_LockOneAlertDetailsParams{
		ID:        int64(alertID),
		ServiceID: permission.ServiceNullUUID(ctx), // only provide service_id restriction if request is from a service
	})
}

// SetDetailsTx sets the Details for an existing alert, replacing it wholesale.
//
// Unlike SetMetadataTx this does not merge: Details is free text with no
// key/value structure to merge on, so a caller wanting to preserve existing
// content must read it first and pass the full text it wants stored.
func (s Store) SetDetailsTx(ctx context.Context, db gadb.DBTX, alertID int, details string) error {
	err := permission.LimitCheckAny(ctx, permission.User, permission.Service)
	if err != nil {
		return err
	}

	err = validate.Text("Details", details, 0, MaxDetailsLength)
	if err != nil {
		return err
	}

	rowCount, err := gadb.New(db).Alert_SetDetails(ctx, gadb.Alert_SetDetailsParams{
		ID:        int64(alertID),
		Details:   details,
		ServiceID: permission.ServiceNullUUID(ctx), // only provide service_id restriction if request is from a service
	})
	if err != nil {
		return err
	}

	if rowCount == 0 {
		// shouldn't happen, but just in case
		return permission.NewAccessDenied("alert closed, invalid, or wrong service")
	}

	return nil
}

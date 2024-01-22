package privatejwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClaims_Validate(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()

	type fields struct {
		Issuer    string
		Subject   string
		Audience  string
		JTI       string
		ExpiresAt time.Time
		IssuedAt  time.Time
	}
	type args struct {
		clientID string
		audience string
		now      time.Time
	}
	tests := []struct {
		name          string
		fields        fields
		args          args
		wantErr       bool
		wantErrString string
	}{
		{
			name:          "nil",
			wantErr:       true,
			wantErrString: `jti must not be blank`,
		},
		{
			name: "invalid issuer",
			fields: fields{
				Issuer:    "invalid",
				Subject:   "urn:client:123456789",
				Audience:  "https://sts.server.com",
				JTI:       "azertyui",
				ExpiresAt: now.Add(2 * time.Minute),
				IssuedAt:  now,
			},
			args: args{
				clientID: "urn:client:123456789",
				audience: "https://sts.server.com",
				now:      now,
			},
			wantErr:       true,
			wantErrString: `issuer must not be "invalid"`,
		},
		{
			name: "invalid subject",
			fields: fields{
				Issuer:    "urn:client:123456789",
				Subject:   "invalid",
				Audience:  "https://sts.server.com",
				JTI:       "azertyui",
				ExpiresAt: now.Add(2 * time.Minute),
				IssuedAt:  now,
			},
			args: args{
				clientID: "urn:client:123456789",
				audience: "https://sts.server.com",
				now:      now,
			},
			wantErr:       true,
			wantErrString: `subject must not be "invalid"`,
		},
		{
			name: "audience mismatch",
			fields: fields{
				Issuer:    "urn:client:123456789",
				Subject:   "urn:client:123456789",
				Audience:  "https://other.server.com",
				JTI:       "azertyui",
				ExpiresAt: now.Add(2 * time.Minute),
				IssuedAt:  now,
			},
			args: args{
				clientID: "urn:client:123456789",
				audience: "https://sts.server.com",
				now:      now,
			},
			wantErr:       true,
			wantErrString: `audience must not be "https://other.server.com"`,
		},
		{
			name: "jti too long",
			fields: fields{
				Issuer:    "urn:client:123456789",
				Subject:   "urn:client:123456789",
				Audience:  "https://sts.server.com",
				JTI:       "  azertyuiop    ",
				ExpiresAt: now.Add(2 * time.Minute),
				IssuedAt:  now,
			},
			args: args{
				clientID: "urn:client:123456789",
				audience: "https://sts.server.com",
				now:      now,
			},
			wantErr:       true,
			wantErrString: `the assertion has an invalid JTI length`,
		},
		{
			name: "issuedAt after expiration",
			fields: fields{
				Issuer:    "urn:client:123456789",
				Subject:   "urn:client:123456789",
				Audience:  "https://sts.server.com",
				JTI:       "azertyui",
				ExpiresAt: now,
				IssuedAt:  now.Add(2 * time.Minute),
			},
			args: args{
				clientID: "urn:client:123456789",
				audience: "https://sts.server.com",
				now:      now,
			},
			wantErr:       true,
			wantErrString: `the issuance date is after the expiration`,
		},
		{
			name: "expired",
			fields: fields{
				Issuer:    "urn:client:123456789",
				Subject:   "urn:client:123456789",
				Audience:  "https://sts.server.com",
				JTI:       "azertyui",
				ExpiresAt: now.Add(-2 * time.Minute),
				IssuedAt:  now.Add(-4 * time.Minute),
			},
			args: args{
				clientID: "urn:client:123456789",
				audience: "https://sts.server.com",
				now:      now,
			},
			wantErr:       true,
			wantErrString: `the assertion is expired`,
		},
		{
			name: "not useable yet",
			fields: fields{
				Issuer:    "urn:client:123456789",
				Subject:   "urn:client:123456789",
				Audience:  "https://sts.server.com",
				JTI:       "azertyui",
				ExpiresAt: now.Add(6 * time.Minute),
				IssuedAt:  now.Add(4 * time.Minute),
			},
			args: args{
				clientID: "urn:client:123456789",
				audience: "https://sts.server.com",
				now:      now,
			},
			wantErr:       true,
			wantErrString: `the assertion is not yet valid`,
		},
		{
			name: "expiration too far into the future",
			fields: fields{
				Issuer:    "urn:client:123456789",
				Subject:   "urn:client:123456789",
				Audience:  "https://sts.server.com",
				JTI:       "azertyui",
				ExpiresAt: now.Add(maxExpiration + 1*time.Minute),
				IssuedAt:  now.Add(-2 * time.Minute),
			},
			args: args{
				clientID: "urn:client:123456789",
				audience: "https://sts.server.com",
				now:      now,
			},
			wantErr:       true,
			wantErrString: `the assertion has an expiration too far into the future`,
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			fields: fields{
				Issuer:    "urn:client:123456789",
				Subject:   "urn:client:123456789",
				Audience:  "https://sts.server.com",
				JTI:       "azertyui",
				ExpiresAt: now.Add(2 * time.Minute),
				IssuedAt:  now,
			},
			args: args{
				clientID: "urn:client:123456789",
				audience: "https://sts.server.com",
				now:      now,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := &Claims{
				Issuer:    tt.fields.Issuer,
				Subject:   tt.fields.Subject,
				Audience:  tt.fields.Audience,
				JTI:       tt.fields.JTI,
				ExpiresAt: tt.fields.ExpiresAt,
				IssuedAt:  tt.fields.IssuedAt,
			}
			err := c.Validate(tt.args.clientID, tt.args.audience, tt.args.now)
			if (err != nil) != tt.wantErr {
				t.Errorf("Claims.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				require.ErrorContains(t, err, tt.wantErrString)
			}
		})
	}
}

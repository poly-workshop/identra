package gorm

import (
	"testing"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "postgres with username",
			config: Config{
				Driver:   "postgres",
				Host:     "localhost",
				Port:     5432,
				Username: "testuser",
				Password: "testpass",
				DbName:   "testdb",
				SSLMode:  "disable",
			},
			wantErr: false,
		},
		{
			name: "postgres without username",
			config: Config{
				Driver:   "postgres",
				Host:     "localhost",
				Port:     5432,
				Username: "",
				Password: "testpass",
				DbName:   "testdb",
				SSLMode:  "disable",
			},
			wantErr: true,
		},
		{
			name: "mysql with username",
			config: Config{
				Driver:   "mysql",
				Host:     "localhost",
				Port:     3306,
				Username: "testuser",
				Password: "testpass",
				DbName:   "testdb",
			},
			wantErr: false,
		},
		{
			name: "mysql without username",
			config: Config{
				Driver:   "mysql",
				Host:     "localhost",
				Port:     3306,
				Username: "",
				Password: "testpass",
				DbName:   "testdb",
			},
			wantErr: true,
		},
		{
			name: "sqlite without username (allowed)",
			config: Config{
				Driver: "sqlite",
				DbName: "test.db",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestQuotePostgresIdentifier(t *testing.T) {
	tests := []struct {
		name string
		input string
		want string
	}{
		{
			name:  "simple name",
			input: "identra",
			want:  `"identra"`,
		},
		{
			name:  "name with double quote",
			input: `my"db`,
			want:  `"my""db"`,
		},
		{
			name:  "name with spaces",
			input: "my database",
			want:  `"my database"`,
		},
		{
			name:  "name with special chars",
			input: "my-db_123",
			want:  `"my-db_123"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := quotePostgresIdentifier(tt.input)
			if got != tt.want {
				t.Errorf("quotePostgresIdentifier(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestQuoteMysqlIdentifier(t *testing.T) {
	tests := []struct {
		name string
		input string
		want string
	}{
		{
			name:  "simple name",
			input: "identra",
			want:  "`identra`",
		},
		{
			name:  "name with backtick",
			input: "my`db",
			want:  "`my``db`",
		},
		{
			name:  "name with spaces",
			input: "my database",
			want:  "`my database`",
		},
		{
			name:  "name with special chars",
			input: "my-db_123",
			want:  "`my-db_123`",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := quoteMysqlIdentifier(tt.input)
			if got != tt.want {
				t.Errorf("quoteMysqlIdentifier(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

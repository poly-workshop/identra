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

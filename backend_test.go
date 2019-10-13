package athenzauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetConfigPath(t *testing.T) {
	path := "/tmp/config.hcl"
	SetConfigPath(path)
	assert.Equal(t, path, confPath)

	path = "/etc/test/path"
	SetConfigPath(path)
	assert.Equal(t, path, confPath)
}

// func TestBackend_CRUD(t *testing.T) {
//   // var resp *logical.Response
//   var err error

//   storage := &logical.InmemStorage{}

//   config := logical.TestBackendConfig()
//   config.StorageView = storage

//   ctx := context.Background()

//   b, err := Factory(ctx, config)
//   if err != nil {
//     t.Fatal(err)
//   }
//   if b == nil {
//     t.Fatal("Failed to create backend")
//   }
// }

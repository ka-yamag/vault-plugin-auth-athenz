package main

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestClientPath_Listing(t *testing.T) {
	b, storage, removeFunc := getBackend(t)
	defer removeFunc()

	// Create user "testuser"
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Path:      "clients/testuser",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"role":     "test_access1",
			"policies": []string{"default"},
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v", resp, err)
	}

	// Create user "testuser2" with role
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Path:      "clients/testuser2",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"role":     "test_access2",
			"policies": []string{"default"},
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v", resp, err)
	}

	// Create user "testuser3" with ttl
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Path:      "clients/testuser3",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"role":     "test_access3",
			"policies": []string{"default"},
			"ttl":      "10s",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v", resp, err)
	}

	// List users
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Path:      "clients/",
		Operation: logical.ListOperation,
		Storage:   storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v", resp, err)
	}

	expected := []string{"testuser", "testuser2", "testuser3"}

	if !reflect.DeepEqual(expected, resp.Data["keys"].([]string)) {
		t.Fatalf("bad: listed users: expected %#v actual: %#v", expected, resp.Data["keys"].([]string))
	}
}

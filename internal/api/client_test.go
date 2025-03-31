package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	baseURL := "https://api.example.com"

	client := NewClient(baseURL)

	if client.BaseURL != baseURL {
		t.Errorf("Expected BaseURL to be %s, got %s", baseURL, client.BaseURL)
	}

	if client.token != "" {
		t.Errorf("Expected token to be empty, got %s", client.token)
	}

	if client.HTTPClient == nil {
		t.Error("Expected HTTPClient to be initialized")
	}

	// Check default timeout
	if client.HTTPClient.Timeout != 30*time.Second {
		t.Errorf("Expected timeout to be 30s, got %v", client.HTTPClient.Timeout)
	}
}

func TestLogin(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request method
		if r.Method != "POST" {
			t.Errorf("Expected request method to be POST, got %s", r.Method)
		}

		// Check request path
		if r.URL.Path != "/console/api/login" {
			t.Errorf("Expected request path to be /console/api/login, got %s", r.URL.Path)
		}

		// Return a mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": "success",
			"data": {
				"access_token": "test-access-token"
			}
		}`))
	}))
	defer server.Close()

	// Create client with test server URL
	client := NewClient(server.URL)

	// Call the method
	err := client.Login("test@example.com", "password")

	// Check for errors
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check token was set
	if client.token != "test-access-token" {
		t.Errorf("Expected token to be 'test-access-token', got '%s'", client.token)
	}
}

func TestLoginErrors(t *testing.T) {
	// Test HTTP client error
	client := NewClient("invalid-url")
	err := client.Login("test@example.com", "password")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}

	// Test non-200 response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "Invalid credentials"}`))
	}))
	defer server.Close()

	client = NewClient(server.URL)
	err = client.Login("test@example.com", "wrong-password")
	if err == nil {
		t.Error("Expected error for 401 response")
	}

	// Test invalid JSON response
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`invalid json`))
	}))
	defer server.Close()

	client = NewClient(server.URL)
	err = client.Login("test@example.com", "password")
	if err == nil {
		t.Error("Expected error for invalid JSON response")
	}
}

func TestGetAppInfo(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request method
		if r.Method != "GET" {
			t.Errorf("Expected request method to be GET, got %s", r.Method)
		}

		// Check request path
		if r.URL.Path != "/console/api/apps/test-app-id" {
			t.Errorf("Expected request path to be /console/api/apps/test-app-id, got %s", r.URL.Path)
		}

		// Check authorization header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("Expected Authorization header to be 'Bearer test-token', got '%s'", auth)
		}

		// Return a mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"data": {
				"id": "test-app-id",
				"name": "Test App",
				"updated_at": "2023-01-01T12:00:00Z"
			}
		}`))
	}))
	defer server.Close()

	// Create client with test server URL
	client := NewClient(server.URL)
	client.token = "test-token" // Set token directly for testing

	// Call the method
	appInfo, err := client.GetAppInfo("test-app-id")

	// Check for errors
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check response
	if appInfo.ID != "test-app-id" {
		t.Errorf("Expected ID to be 'test-app-id', got '%s'", appInfo.ID)
	}

	if appInfo.Name != "Test App" {
		t.Errorf("Expected Name to be 'Test App', got '%s'", appInfo.Name)
	}

	// Compare UpdatedAt as string since it's now an interface{} type
	expectedTimeStr := "2023-01-01T12:00:00Z"
	if updatedAtStr, ok := appInfo.UpdatedAt.(string); ok {
		if updatedAtStr != expectedTimeStr {
			t.Errorf("Expected UpdatedAt to be %v, got %v", expectedTimeStr, updatedAtStr)
		}
	} else {
		t.Errorf("Expected UpdatedAt to be string type with value %v, got %T: %v", expectedTimeStr, appInfo.UpdatedAt, appInfo.UpdatedAt)
	}
}

func TestGetAppInfoErrors(t *testing.T) {
	// Test not authenticated error
	client := NewClient("https://api.example.com")
	_, err := client.GetAppInfo("test-app-id")
	if err == nil || err.Error() != "not authenticated, call Login() first" {
		t.Errorf("Expected 'not authenticated' error, got %v", err)
	}

	// Test HTTP client error
	client = NewClient("invalid-url")
	client.token = "test-token" // Set token directly for testing
	_, err = client.GetAppInfo("test-app-id")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}

	// Test non-200 response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "App not found"}`))
	}))
	defer server.Close()

	client = NewClient(server.URL)
	client.token = "test-token" // Set token directly for testing
	_, err = client.GetAppInfo("test-app-id")
	if err == nil {
		t.Error("Expected error for 404 response")
	}

	// Test invalid JSON response
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`invalid json`))
	}))
	defer server.Close()

	client = NewClient(server.URL)
	client.token = "test-token" // Set token directly for testing
	_, err = client.GetAppInfo("test-app-id")
	if err == nil {
		t.Error("Expected error for invalid JSON response")
	}
}

func TestGetDSL(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request method
		if r.Method != "GET" {
			t.Errorf("Expected request method to be GET, got %s", r.Method)
		}

		// Check request path
		expectedPath := "/console/api/apps/test-app-id/export"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected request path to be %s, got %s", expectedPath, r.URL.Path)
		}

		// Check query parameter
		if r.URL.Query().Get("include_secret") != "false" {
			t.Errorf("Expected include_secret=false query parameter")
		}

		// Check authorization header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("Expected Authorization header to be 'Bearer test-token', got '%s'", auth)
		}

		// Return a mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"data": "name: Test App\nversion: 1.0.0"
		}`))
	}))
	defer server.Close()

	// Create client with test server URL
	client := NewClient(server.URL)
	client.token = "test-token" // Set token directly for testing

	// Call the method
	dsl, err := client.GetDSL("test-app-id")

	// Check for errors
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check response
	expected := "name: Test App\nversion: 1.0.0"
	if string(dsl) != expected {
		t.Errorf("Expected DSL to be '%s', got '%s'", expected, string(dsl))
	}
}

func TestGetDSLErrors(t *testing.T) {
	// Test not authenticated error
	client := NewClient("https://api.example.com")
	_, err := client.GetDSL("test-app-id")
	if err == nil || err.Error() != "not authenticated, call Login() first" {
		t.Errorf("Expected 'not authenticated' error, got %v", err)
	}

	// Test HTTP client error
	client = NewClient("invalid-url")
	client.token = "test-token" // Set token directly for testing
	_, err = client.GetDSL("test-app-id")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}

	// Test non-200 response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "DSL not found"}`))
	}))
	defer server.Close()

	client = NewClient(server.URL)
	client.token = "test-token" // Set token directly for testing
	_, err = client.GetDSL("test-app-id")
	if err == nil {
		t.Error("Expected error for 404 response")
	}
}

func TestUpdateDSL(t *testing.T) {
	// このテストケースは削除します
}

func TestUpdateDSLErrors(t *testing.T) {
	// このテストケースは削除します
}

func TestDoesDSLExist(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request method
		if r.Method != "GET" {
			t.Errorf("Expected request method to be GET, got %s", r.Method)
		}

		// Check paths and return appropriate responses
		if r.URL.Path == "/console/api/apps/existing-app" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": "existing-app", "name": "Existing App"}`))
		} else if r.URL.Path == "/console/api/apps/deleted-app" {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	// Create client with test server URL
	client := NewClient(server.URL)
	client.token = "test-token" // Set token directly for testing

	// Test with existing app
	exists, err := client.DoesDSLExist("existing-app")
	if err != nil {
		t.Fatalf("Expected no error for existing app, got %v", err)
	}
	if !exists {
		t.Error("Expected existing app to return true")
	}

	// Test with deleted app
	exists, err = client.DoesDSLExist("deleted-app")
	if err != nil {
		t.Fatalf("Expected no error for deleted app, got %v", err)
	}
	if exists {
		t.Error("Expected deleted app to return false")
	}

	// Test with error
	_, err = client.DoesDSLExist("error-app")
	if err == nil {
		t.Error("Expected error for server error")
	}
}

func TestDoesDSLExistErrors(t *testing.T) {
	// Test not authenticated error
	client := NewClient("https://api.example.com")
	_, err := client.DoesDSLExist("test-app-id")
	if err == nil || err.Error() != "not authenticated, call Login() first" {
		t.Errorf("Expected 'not authenticated' error, got %v", err)
	}

	// Test HTTP client error
	client = NewClient("invalid-url")
	client.token = "test-token" // Set token directly for testing
	_, err = client.DoesDSLExist("test-app-id")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

// TestGetAppList tests the GetAppList method
func TestGetAppList(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request method
		if r.Method != "GET" {
			t.Errorf("Expected request method to be GET, got %s", r.Method)
		}

		// Check request path
		if r.URL.Path != "/console/api/apps" {
			t.Errorf("Expected request path to be /console/api/apps, got %s", r.URL.Path)
		}

		// Check authorization header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("Expected Authorization header to be 'Bearer test-token', got '%s'", auth)
		}

		// Return a mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"data": [
				{
					"id": "app-id-1",
					"name": "App 1",
					"updated_at": "2023-01-01T12:00:00Z"
				},
				{
					"id": "app-id-2",
					"name": "App 2",
					"updated_at": "2023-01-02T12:00:00Z"
				}
			]
		}`))
	}))
	defer server.Close()

	// Create client with test server URL
	client := NewClient(server.URL)
	client.token = "test-token" // Set token directly for testing

	// Call the method
	apps, err := client.GetAppList()

	// Check for errors
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check response
	if len(apps) != 2 {
		t.Errorf("Expected 2 apps, got %d", len(apps))
	}

	if apps[0].ID != "app-id-1" || apps[0].Name != "App 1" {
		t.Errorf("Expected first app to be App 1, got %+v", apps[0])
	}

	// Also check UpdatedAt
	expectedTime1 := "2023-01-01T12:00:00Z"
	if updatedAtStr, ok := apps[0].UpdatedAt.(string); ok {
		if updatedAtStr != expectedTime1 {
			t.Errorf("Expected first app UpdatedAt to be %v, got %v", expectedTime1, updatedAtStr)
		}
	} else {
		t.Errorf("Expected first app UpdatedAt to be string type with value %v, got %T: %v",
			expectedTime1, apps[0].UpdatedAt, apps[0].UpdatedAt)
	}

	if apps[1].ID != "app-id-2" || apps[1].Name != "App 2" {
		t.Errorf("Expected second app to be App 2, got %+v", apps[1])
	}

	// Also check UpdatedAt
	expectedTime2 := "2023-01-02T12:00:00Z"
	if updatedAtStr, ok := apps[1].UpdatedAt.(string); ok {
		if updatedAtStr != expectedTime2 {
			t.Errorf("Expected second app UpdatedAt to be %v, got %v", expectedTime2, updatedAtStr)
		}
	} else {
		t.Errorf("Expected second app UpdatedAt to be string type with value %v, got %T: %v",
			expectedTime2, apps[1].UpdatedAt, apps[1].UpdatedAt)
	}
}

func TestMin(t *testing.T) {
	testCases := []struct {
		a, b     int
		expected int
	}{
		{5, 10, 5},
		{10, 5, 5},
		{0, 0, 0},
		{-5, 5, -5},
		{5, -5, -5},
		{-10, -5, -10},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("min(%d,%d)", tc.a, tc.b), func(t *testing.T) {
			result := min(tc.a, tc.b)
			if result != tc.expected {
				t.Errorf("Expected min(%d, %d) = %d, got %d", tc.a, tc.b, tc.expected, result)
			}
		})
	}
}

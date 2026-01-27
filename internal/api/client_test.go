package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	testEmail := "test@example.com"
	testPassword := "password123"
	expectedEncodedPassword := base64.StdEncoding.EncodeToString([]byte(testPassword))

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

		// Check Content-Type header
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected Content-Type to be application/json, got %s", contentType)
		}

		// Read and verify request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}

		var loginData map[string]string
		if err := json.Unmarshal(body, &loginData); err != nil {
			t.Fatalf("Failed to parse request body as JSON: %v", err)
		}

		// Verify email
		if loginData["email"] != testEmail {
			t.Errorf("Expected email to be %s, got %s", testEmail, loginData["email"])
		}

		// Verify password is Base64 encoded
		if loginData["password"] != expectedEncodedPassword {
			t.Errorf("Expected password to be Base64 encoded (%s), got %s", expectedEncodedPassword, loginData["password"])
		}

		// Verify the encoded password can be decoded back to original
		decodedPassword, err := base64.StdEncoding.DecodeString(loginData["password"])
		if err != nil {
			t.Errorf("Password is not valid Base64: %v", err)
		}
		if string(decodedPassword) != testPassword {
			t.Errorf("Decoded password does not match original: expected %s, got %s", testPassword, string(decodedPassword))
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
	err := client.Login(testEmail, testPassword)

	// Check for errors
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check token was set
	if client.token != "test-access-token" {
		t.Errorf("Expected token to be 'test-access-token', got '%s'", client.token)
	}
}

func TestLoginWithCookieAuth(t *testing.T) {
	testEmail := "test@example.com"
	testPassword := "password123"

	// Create a test server that returns cookies (new Dify API format)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set cookies for new Dify API format
		http.SetCookie(w, &http.Cookie{
			Name:  "__Host-access_token",
			Value: "cookie-access-token",
		})
		http.SetCookie(w, &http.Cookie{
			Name:  "__Host-csrf_token",
			Value: "cookie-csrf-token",
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "success"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	err := client.Login(testEmail, testPassword)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check token was set from cookie
	if client.token != "cookie-access-token" {
		t.Errorf("Expected token to be 'cookie-access-token', got '%s'", client.token)
	}

	// Check CSRF token was set from cookie
	if client.csrfToken != "cookie-csrf-token" {
		t.Errorf("Expected csrfToken to be 'cookie-csrf-token', got '%s'", client.csrfToken)
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

// TestGetAppListPagination tests the GetAppList method with pagination
func TestGetAppListPagination(t *testing.T) {
	requestCount := 0

	// Create a test server that returns paginated results
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

		requestCount++
		page := r.URL.Query().Get("page")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Return different responses based on page
		switch page {
		case "1", "":
			w.Write([]byte(`{
				"page": 1,
				"limit": 2,
				"total": 5,
				"has_more": true,
				"data": [
					{"id": "app-id-1", "name": "App 1", "updated_at": "2023-01-01T12:00:00Z"},
					{"id": "app-id-2", "name": "App 2", "updated_at": "2023-01-02T12:00:00Z"}
				]
			}`))
		case "2":
			w.Write([]byte(`{
				"page": 2,
				"limit": 2,
				"total": 5,
				"has_more": true,
				"data": [
					{"id": "app-id-3", "name": "App 3", "updated_at": "2023-01-03T12:00:00Z"},
					{"id": "app-id-4", "name": "App 4", "updated_at": "2023-01-04T12:00:00Z"}
				]
			}`))
		case "3":
			w.Write([]byte(`{
				"page": 3,
				"limit": 2,
				"total": 5,
				"has_more": false,
				"data": [
					{"id": "app-id-5", "name": "App 5", "updated_at": "2023-01-05T12:00:00Z"}
				]
			}`))
		default:
			t.Errorf("Unexpected page requested: %s", page)
		}
	}))
	defer server.Close()

	// Create client with test server URL
	client := NewClient(server.URL)
	client.token = "test-token"

	// Call the method
	apps, err := client.GetAppList()

	// Check for errors
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify all pages were requested
	if requestCount != 3 {
		t.Errorf("Expected 3 requests (for 3 pages), got %d", requestCount)
	}

	// Check total number of apps
	if len(apps) != 5 {
		t.Errorf("Expected 5 apps from pagination, got %d", len(apps))
	}

	// Verify all apps are present
	expectedIDs := []string{"app-id-1", "app-id-2", "app-id-3", "app-id-4", "app-id-5"}
	for i, expectedID := range expectedIDs {
		if i >= len(apps) {
			t.Errorf("Missing app at index %d", i)
			continue
		}
		if apps[i].ID != expectedID {
			t.Errorf("Expected app %d to have ID %s, got %s", i, expectedID, apps[i].ID)
		}
	}
}

// TestGetAppListNoPagination tests GetAppList when has_more is false
func TestGetAppListNoPagination(t *testing.T) {
	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"page": 1,
			"limit": 20,
			"total": 2,
			"has_more": false,
			"data": [
				{"id": "app-id-1", "name": "App 1", "updated_at": "2023-01-01T12:00:00Z"},
				{"id": "app-id-2", "name": "App 2", "updated_at": "2023-01-02T12:00:00Z"}
			]
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	client.token = "test-token"

	apps, err := client.GetAppList()

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should only make one request when has_more is false
	if requestCount != 1 {
		t.Errorf("Expected 1 request when has_more is false, got %d", requestCount)
	}

	if len(apps) != 2 {
		t.Errorf("Expected 2 apps, got %d", len(apps))
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

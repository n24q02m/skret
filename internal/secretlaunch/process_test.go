package secretlaunch

import "testing"

func TestFilteredEnvironmentDropsInheritedCredentials(t *testing.T) {
	values := SecretSet{items: map[string]SecretBuffer{
		"APP_TOKEN": {Key: "APP_TOKEN", Version: "1", Env: "APP_TOKEN", Bytes: []byte("synthetic-sentinel")},
	}}
	defer values.Zeroize()
	result := filteredEnvironment(
		[]string{
			"AWS_ACCESS_KEY_ID=access-id",
			"AWS_SECRET_ACCESS_KEY=secret-sentinel",
			"CUSTOM_INHERITED=value",
			"HOME=/home/skret",
			"PATH=/usr/bin",
		},
		map[string]string{"LOG_LEVEL": "info"},
		values,
	)
	observed := make(map[string]string, len(result))
	for _, entry := range result {
		name, value, ok := splitEnvironmentEntry(entry)
		if !ok {
			t.Fatalf("invalid environment entry %q", entry)
		}
		observed[name] = value
	}
	if _, ok := observed["AWS_ACCESS_KEY_ID"]; ok {
		t.Fatal("inherited AWS access key was retained")
	}
	if _, ok := observed["AWS_SECRET_ACCESS_KEY"]; ok {
		t.Fatal("inherited AWS secret was retained")
	}
	if _, ok := observed["CUSTOM_INHERITED"]; ok {
		t.Fatal("undeclared inherited variable was retained")
	}
	if observed["HOME"] != "/home/skret" || observed["PATH"] != "/usr/bin" ||
		observed["LOG_LEVEL"] != "info" || observed["APP_TOKEN"] != "synthetic-sentinel" {
		t.Fatalf("filtered environment = %#v", observed)
	}
}

func splitEnvironmentEntry(entry string) (string, string, bool) {
	for index := 0; index < len(entry); index++ {
		if entry[index] == '=' {
			return entry[:index], entry[index+1:], entry[:index] != ""
		}
	}
	return "", "", false
}

package collect

import "testing"

func TestParseXML_ArrConfig(t *testing.T) {
	input := []byte(`<Config>
  <AuthenticationMethod>Forms</AuthenticationMethod>
  <ApiKey>abc123</ApiKey>
  <Port>8989</Port>
</Config>`)
	m, ok := parseXML(input)
	if !ok {
		t.Fatal("parseXML: ok=false, want true")
	}
	if m["Config.AuthenticationMethod"] != "Forms" {
		t.Errorf("Config.AuthenticationMethod=%q, want Forms", m["Config.AuthenticationMethod"])
	}
	if m["Config.ApiKey"] != "abc123" {
		t.Errorf("Config.ApiKey=%q, want abc123", m["Config.ApiKey"])
	}
}

func TestParseXML_EmptyReturnsOK(t *testing.T) {
	_, ok := parseXML([]byte("not xml"))
	if ok {
		t.Error("malformed XML: want ok=false")
	}
}

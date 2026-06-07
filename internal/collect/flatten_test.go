package collect

import (
	"reflect"
	"testing"
)

func TestFlattenJSON(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   map[string]string
		wantOK bool
	}{
		{
			name:   "simple-flat",
			input:  `{"a":"hello","b":"world"}`,
			want:   map[string]string{"a": "hello", "b": "world"},
			wantOK: true,
		},
		{
			name:   "nested",
			input:  `{"tools":{"exec":{"ask":"on-miss"}}}`,
			want:   map[string]string{"tools.exec.ask": "on-miss"},
			wantOK: true,
		},
		{
			name:   "array-numeric-segments",
			input:  `{"args":["npx","--yes","server"]}`,
			want:   map[string]string{"args.0": "npx", "args.1": "--yes", "args.2": "server"},
			wantOK: true,
		},
		{
			name:   "bool-true",
			input:  `{"enabled":true}`,
			want:   map[string]string{"enabled": "true"},
			wantOK: true,
		},
		{
			name:   "bool-false",
			input:  `{"skipDangerousModePermissionPrompt":false}`,
			want:   map[string]string{"skipDangerousModePermissionPrompt": "false"},
			wantOK: true,
		},
		{
			name:   "number",
			input:  `{"count":42}`,
			want:   map[string]string{"count": "42"},
			wantOK: true,
		},
		{
			name:   "not-json-object",
			input:  `["a","b"]`,
			wantOK: false,
		},
		{
			name:   "invalid-json",
			input:  `{broken`,
			wantOK: false,
		},
		{
			name:   "null-value-skipped",
			input:  `{"a":null,"b":"ok"}`,
			want:   map[string]string{"b": "ok"},
			wantOK: true,
		},
		{
			name:  "mixed-depth",
			input: `{"mcpServers":{"slack":{"command":"npx","args":["slack-mcp"]}}}`,
			want: map[string]string{
				"mcpServers.slack.command": "npx",
				"mcpServers.slack.args.0":  "slack-mcp",
			},
			wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := flattenJSON([]byte(tt.input))
			if ok != tt.wantOK {
				t.Fatalf("flattenJSON ok=%v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("flattenJSON =\n  %v\nwant\n  %v", got, tt.want)
			}
		})
	}
}

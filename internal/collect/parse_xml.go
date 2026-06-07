package collect

import (
	"encoding/xml"
	"strings"
)

// parseXML parses a simple XML document into a flat dotted-key map using the
// element-path as key and the text content as value. Only leaf text nodes are
// emitted; structural (parent) elements are not. Used for *arr config.xml.
// Returns ok=false if the XML is not parseable.
func parseXML(b []byte) (map[string]string, bool) {
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	out := make(map[string]string)
	var pathStack []string
	var currentText strings.Builder
	ok := false

	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			pathStack = append(pathStack, t.Name.Local)
			currentText.Reset()
			ok = true
		case xml.EndElement:
			if len(pathStack) > 0 {
				path := strings.Join(pathStack, ".")
				text := trimSpace(currentText.String())
				if text != "" {
					out[path] = text
				}
				pathStack = pathStack[:len(pathStack)-1]
			}
			currentText.Reset()
		case xml.CharData:
			currentText.Write(t)
		}
	}
	if !ok {
		return nil, false
	}
	return out, true
}

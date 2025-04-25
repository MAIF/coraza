package main

import (
	"embed"
	_ "embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"
)

const BUFFER_SIZE int = 1 << 20

type BufferWriter struct {
	buffer [BUFFER_SIZE]uint8
	offset int
}

var stdin BufferWriter = BufferWriter{}
var stdout BufferWriter = BufferWriter{}
var errors BufferWriter = BufferWriter{}

var waf coraza.WAF
var configuration CorazaConfig = CorazaConfig{}

var (
	//go:embed rules
	crs  embed.FS
	root fs.FS
)

type rulesFS struct {
	fs           fs.FS
	filesMapping map[string]string
	dirsMapping  map[string]string
}

func (r rulesFS) Open(name string) (fs.File, error) {
	return r.fs.Open(r.mapPath(name))
}

func (r rulesFS) ReadDir(name string) ([]fs.DirEntry, error) {
	for a, dst := range r.dirsMapping {
		if a == name {
			return fs.ReadDir(r.fs, dst)
		}

		prefix := a + "/"
		if strings.HasPrefix(name, prefix) {
			return fs.ReadDir(r.fs, fmt.Sprintf("%s/%s", dst, name[len(prefix):]))
		}
	}
	return fs.ReadDir(r.fs, name)
}

func (r rulesFS) ReadFile(name string) ([]byte, error) {
	return fs.ReadFile(r.fs, r.mapPath(name))
}

func (r rulesFS) mapPath(p string) string {
	if strings.IndexByte(p, '/') != -1 {
		// is not in root, hence we can do dir mapping
		for a, dst := range r.dirsMapping {
			prefix := a + "/"
			if strings.HasPrefix(p, prefix) {
				return fmt.Sprintf("%s/%s", dst, p[len(prefix):])
			}
		}
	}

	for a, dst := range r.filesMapping {
		if a == p {
			return dst
		}
	}

	return p
}

type RequestData struct {
	Headers map[string]string `json:"headers"`
	Url     string            `json:"url"`
	Method  string            `json:"method"`
	Body    *[]byte           `json:"body,omitempty"`
	Proto   string            `json:"proto"`
}

type ResponseData struct {
	Headers map[string]string `json:"headers"`
	Body    *[]byte           `json:"body,omitempty"`
	Status  int               `json:"status,omitempty"`
	Proto   string            `json:"proto"`
}

type ResponseContext struct {
	Request  RequestData  `json:"request"`
	Response ResponseData `json:"response"`
}

type RuleError struct {
	Message string `json:"message"`
	URI     string `json:"uri"`
	Rule    struct {
		Id       int    `json:"id"`
		File     string `json:"file"`
		Severity int    `json:"severity"`
	} `json:"rule"`
}

type Rule struct {
	Id       int    `json:"id"`
	File     string `json:"file"`
	Severity int    `json:"severity"`
}

type CorazaConfig struct {
	Directives    string `json:"directives"`
	InspectInputBodies bool   `json:"inspect_input_bodies"`
	InspectOutputBodies bool   `json:"inspect_output_bodies"`
}

func customErrorCallback(matchedRule types.MatchedRule) {
	rule := RuleError{
		Message: matchedRule.Message(),
		URI:     matchedRule.URI(),
		Rule: Rule{
			Id:       matchedRule.Rule().ID(),
			File:     matchedRule.Rule().File(),
			Severity: matchedRule.Rule().Severity().Int(),
		},
	}

	jsonData, err := json.Marshal(rule)
	if err != nil {

	} else {
		newline := append(jsonData, []byte("\n")...)
		copy(errors.buffer[errors.offset:], newline)
		errors.offset += len(newline)
	}
}

type testLogOutput struct {
}

func (l testLogOutput) Write(p []byte) (int, error) {
	write(string(p))
	return len(p), nil
}

func Init() {
	rules, _ := fs.Sub(crs, "rules")
	root = &rulesFS{
		rules,
		map[string]string{
			"@coraza":           "coraza.conf",
			"@crs-setup":        "crs-setup.conf",
			"@recommended-conf": "coraza.conf",
			"@crs-setup-conf":   "crs-setup.conf",
		},
		map[string]string{
			"@owasp_crs": "crs",
		},
	}
}

//go:wasmexport initialize_coraza
func InitializeCoraza() {
	Init()

	configuration = StdinToCorazaConfig(stdin.buffer[0:stdin.offset])

	logger := debuglog.Default().
		WithLevel(debuglog.LevelNoLog).
		WithOutput(testLogOutput{})

	new_waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithErrorCallback(customErrorCallback).
			WithDebugLogger(logger).
			WithRootFS(root).
			WithDirectives(configuration.Directives))

	if err != nil || new_waf == nil {
		write_error("{ \"error\": " + err.Error() + "}")
	} else {
		waf = new_waf
	}
}

//go:wasmexport process_transaction
func ProcessTransaction() {
	tx := waf.NewTransaction()

	defer func() {
		tx.Close()
		tx.ProcessLogging()
	}()

	var input = stdin.buffer[0:stdin.offset]

	var context = StdinToRequestData(input)

	tx.ProcessURI(context.Url, context.Method, context.Proto)

	var headers = context.Headers
	for key, value := range headers {
		tx.AddRequestHeader(key, value)
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		reject()
		return
	}

	if configuration.InspectInputBodies && context.Body != nil {
		var body []byte = *context.Body
		tx.WriteRequestBody(body)
	}

	if _, err := tx.ProcessRequestBody(); err != nil {
		reject()
		return
	}

	if tx.IsInterrupted() {
		reject()
		return
	}

	pass()
}

//go:wasmexport process_response_transaction
func ProcessResponseTransaction() {
	tx := waf.NewTransaction()

	defer func() {
		tx.Close()
		tx.ProcessLogging()
	}()

	var input = stdin.buffer[0:stdin.offset]

	var context = StdinToResponseContext(input)

	tx.ProcessURI(context.Request.Url, context.Request.Method, context.Request.Proto)

	var headers = context.Request.Headers
	for key, value := range headers {
		tx.AddRequestHeader(key, value)
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		reject()
		return
	}

	if configuration.InspectInputBodies && context.Request.Body != nil {
		var body []byte = *context.Request.Body
		tx.WriteRequestBody(body)
	}

	if _, err := tx.ProcessRequestBody(); err != nil {
		reject()
		return
	}

	headers = context.Response.Headers
	for key, value := range headers {
		tx.AddResponseHeader(key, value)
	}

	if it := tx.ProcessResponseHeaders(context.Response.Status, context.Response.Proto); it != nil {
		reject()
		return
	}

	if configuration.InspectOutputBodies && context.Response.Body != nil {
		var body []byte = *context.Response.Body
		tx.WriteResponseBody(body)
	}

	if _, err := tx.ProcessResponseBody(); err != nil {
		reject()
		return
	}

	if tx.IsInterrupted() {
		reject()
		return
	}

	pass()
}

func pass() {
	write("true")
}

func reject() {
	write("false")
}

func StdinToCorazaConfig(input []byte) CorazaConfig {
	var result = CorazaConfig{}
	err := json.Unmarshal(input, &result)
	if err != nil {
		write_error("{ \"error\": Error unmarshaling CorazaConfig JSON: " + err.Error() + "}")
	}

	return result
}

func StdinToRequestData(input []byte) RequestData {
	var result RequestData

	err := json.Unmarshal(input, &result)
	if err != nil {
		write_error("{ \"error\": Error unmarshaling RequestData JSON: " + err.Error() + "}")
	}

	return result
}

func StdinToResponseContext(input []byte) ResponseContext {
	var result ResponseContext

	err := json.Unmarshal(input, &result)
	if err != nil {
		write_error("{ \"error\": Error unmarshaling ResponseContext JSON: " + err.Error() + "}")
	}

	return result
}

//go:wasmexport write
func write(text string) {
	stdout = BufferWriter{}
	copy(stdout.buffer[stdout.offset:], text)
	stdout.offset += len(text)
}

//go:wasmexport write_stdin
func write_stdin(length int32) {
	stdin.offset = int(length)
}

//go:wasmexport get_stdout
func get_stdout() *[BUFFER_SIZE]uint8 {
	return &stdout.buffer
}

//go:wasmexport get_stdin
func get_stdin() *[BUFFER_SIZE]uint8 {
	return &stdin.buffer
}

//go:wasmexport stdin_length
func stdin_length() int32 {
	return int32(stdin.offset)
}

//go:wasmexport stdout_length
func stdout_length() int32 {
	return int32(stdout.offset)
}

func write_error(text string) {
	text += "\n"
	copy(errors.buffer[errors.offset:], text)
	errors.offset += len(text)
}

//go:wasmexport get_errors
func GetErrorsBuffer() *[BUFFER_SIZE]uint8 {
	return &errors.buffer
}

//go:wasmexport errors_length
func errors_length() int32 {
	return int32(errors.offset)
}

//go:wasmexport reset
func reset() {
	stdout = BufferWriter{}
	stdin = BufferWriter{}
	errors = BufferWriter{}
}

func main() {}

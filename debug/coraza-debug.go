package main

import (
	"embed"
	_ "embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strconv"
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
var flows BufferWriter = BufferWriter{}

var waf coraza.WAF

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

type Context struct {
	Request struct {
		Headers map[string]string `json:"headers"`
		Url     string            `json:"url"`
		Method  string            `json:"method"`
		Body    *[]byte           `json:"body,omitempty"`
	} `json:"request"`
}

func customErrorCallback(matchedRule types.MatchedRule) {
	write_error("Error triggered by rule ID: " + strconv.Itoa(matchedRule.Rule().ID()) + ", Message: " + matchedRule.Message())
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
			"@coraza":    "coraza.conf",
			"@crs-setup": "crs-setup.conf",
		},
		map[string]string{
			"@owasp_crs": "crs",
		},
	}
}

//go:wasmexport initialize_coraza
func InitializeCoraza() {
	Init()
	flow("read root FS")

	logger := debuglog.Default().
		WithLevel(debuglog.LevelNoLog).
		WithOutput(testLogOutput{})

	flow("initialize logger")

	new_waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithErrorCallback(customErrorCallback).
			WithDebugLogger(logger).
			WithRootFS(root).
			WithDirectives(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecResponseBodyAccess On
			Include @coraza
			Include @crs-setup
			Include @owasp_crs/*.conf
			SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,t:lowercase,deny,msg:'ADMIN PATH forbidden'"
			SecRule REQUEST_HEADERS:foo "@streq bar" "id:1001,phase:1,deny,status:403,msg:'Header foo cannot be bar'"
			SecRule REQUEST_METHOD "@pm HEAD" "id:1002,phase:1,deny,status:403,msg:'HTTP METHOD NOT AUTHORIZED'"
		`))

	// Include @recommended-conf
	// Include @crs-setup-conf
	// Include @owasp_crs/*.conf
	// SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,t:lowercase,deny,msg:'ADMIN PATH forbidden'"
	// SecRuleEngine DetectionOnly
	// SecRequestBodyAccess On
	// SecResponseBodyAccess On

	if err != nil || new_waf == nil {
		flow("failed to initialize waf")
		write_error(err.Error())
	} else {
		flow("initialized waf")
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

	flow("process transaction")
	var input = stdin.buffer[0:stdin.offset]

	var context = ConfigurationToJson(input)

	jsonData, err := json.MarshalIndent(context, "", "  ")
	if err != nil {
		// log.Fatalf("Error marshaling struct: %v", err)
	}

	flow("context read: " + string(jsonData))

	tx.ProcessURI(context.Request.Url, context.Request.Method, "HTTP/1.1")

	var headers = context.Request.Headers
	for key, value := range headers {
		tx.AddRequestHeader(key, value)
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		write("{ \"result\": false }")
		return
	}

	flow("manage body")

	if context.Request.Body != nil {
		var body []byte = *context.Request.Body
		tx.WriteRequestBody(body)
	}

	flow("try to process body")
	if it, err := tx.ProcessRequestBody(); it != nil || err != nil {
		write("{ \"result\": false }")
		return
	}

	flow("test interrupted")
	if tx.IsInterrupted() {
		write("{ \"result\": false }")
		return
	}

	write("{ \"result\": true }")
}

func ConfigurationToJson(input []byte) Context {
	var result = Context{}
	err := json.Unmarshal([]byte(input), &result)
	if err != nil {
		write_error("Error unmarshaling JSON: " + err.Error())
	}

	return result
}

//go:wasmexport write
func write(text string) {
	copy(stdout.buffer[stdout.offset:], text)
	stdout.offset += len(text)
}

//go:wasmexport get_stdin
func get_stdin() *[BUFFER_SIZE]uint8 {
	return &stdin.buffer
}

//go:wasmexport write_stdin
func write_stdin(length int32) {
	stdin.offset += int(length)
}

//go:wasmexport get_stdout
func get_stdout() *[BUFFER_SIZE]uint8 {
	return &stdout.buffer
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

func flow(text string) {
	text += "\n"
	copy(flows.buffer[flows.offset:], text)
	flows.offset += len(text)
}

//go:wasmexport get_flow
func GetFlow() *[BUFFER_SIZE]uint8 {
	return &flows.buffer
}

//go:wasmexport flow_length
func flow_length() int32 {
	return int32(flows.offset)
}

//go:wasmexport reset
func reset() {
	stdout = BufferWriter{}
	stdin = BufferWriter{}
}

func main() {}

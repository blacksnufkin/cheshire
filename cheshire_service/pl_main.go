package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	adaptix "github.com/Adaptix-Framework/axc2"
)

type Teamserver interface {
	TsServiceSendDataAll(service string, data string)
	TsServiceSendDataClient(operator string, service string, data string)
	TsExtenderDataSave(extenderName string, key string, value []byte) error
	TsExtenderDataLoad(extenderName string, key string) ([]byte, error)
}

type PluginService struct{}

var (
	Ts           Teamserver
	ModuleDir    string
	LitterboxURL string
	httpClient   = &http.Client{Timeout: 600 * time.Second}
)

func InitPlugin(ts any, moduleDir string, serviceConfig string) adaptix.PluginService {
	Ts = ts.(Teamserver)
	ModuleDir = moduleDir
	LitterboxURL = "http://192.168.88.128:1337"

	for _, line := range strings.Split(serviceConfig, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "litterbox_url:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "litterbox_url:"))
			val = strings.Trim(val, `"'`)
			if val != "" {
				LitterboxURL = val
			}
		}
	}

	fmt.Printf("[cheshire] Initialized — LitterBox at %s\n", LitterboxURL)
	return &PluginService{}
}

func (p *PluginService) Call(operator string, function string, args string) {
	switch function {
	case "get_profiles":
		go p.handleGetProfiles(operator)
	case "submit":
		go p.handleSubmit(operator, args)
	case "run_all":
		go p.handleRunAll(operator, args)
	case "run_static":
		go p.handleRunStatic(operator, args)
	case "run_dynamic":
		go p.handleRunDynamic(operator, args)
	case "run_edr":
		go p.handleRunEdr(operator, args)
	case "get_risk":
		go p.handleGetRisk(operator, args)
	case "cleanup":
		go p.handleCleanup(operator, args)
	default:
		sendError(operator, "Unknown function: "+function)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func send(operator string, payload any) {
	j, _ := json.Marshal(payload)
	Ts.TsServiceSendDataClient(operator, "cheshire", string(j))
}

func sendError(operator string, msg string) {
	send(operator, map[string]string{"action": "error", "message": msg})
}

func sendStatus(operator, kind, msg string) {
	send(operator, map[string]string{"action": "status", "kind": kind, "message": msg})
}

func lbGet(path string) ([]byte, int, error) {
	resp, err := httpClient.Get(LitterboxURL + path)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode, nil
}

func lbPostJSON(path string, payload any) ([]byte, int, error) {
	var body io.Reader
	if payload != nil {
		j, _ := json.Marshal(payload)
		body = bytes.NewReader(j)
	} else {
		body = strings.NewReader("")
	}
	resp, err := httpClient.Post(LitterboxURL+path, "application/json", body)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data, resp.StatusCode, nil
}

func lbDelete(path string) ([]byte, int, error) {
	req, err := http.NewRequest("DELETE", LitterboxURL+path, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode, nil
}

// ── handlers ─────────────────────────────────────────────────────────────────

func (p *PluginService) handleGetProfiles(operator string) {
	profBody, _, err := lbGet("/api/edr/profiles")
	if err != nil {
		sendError(operator, "LitterBox unreachable: "+err.Error())
		return
	}
	agentBody, _, _ := lbGet("/api/edr/agents/status")

	var profiles, agents any
	json.Unmarshal(profBody, &profiles)
	json.Unmarshal(agentBody, &agents)

	send(operator, map[string]any{
		"action":   "profiles",
		"profiles": profiles,
		"agents":   agents,
	})
}

func (p *PluginService) handleSubmit(operator string, args string) {
	var req struct {
		FilePath string `json:"file_path"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil || req.FilePath == "" {
		sendError(operator, "submit requires file_path")
		return
	}

	f, err := os.Open(req.FilePath)
	if err != nil {
		sendError(operator, "Cannot open file: "+err.Error())
		return
	}
	defer f.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filepath.Base(req.FilePath))
	if err != nil {
		sendError(operator, "Multipart error: "+err.Error())
		return
	}
	if _, err = io.Copy(fw, f); err != nil {
		sendError(operator, "File read error: "+err.Error())
		return
	}
	mw.Close()

	resp, err := httpClient.Post(LitterboxURL+"/upload", mw.FormDataContentType(), &buf)
	if err != nil {
		sendError(operator, "Upload failed: "+err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		sendError(operator, fmt.Sprintf("Upload HTTP %d: %s", resp.StatusCode, string(body)))
		return
	}

	var result map[string]any
	json.Unmarshal(body, &result)
	fileInfo, _ := result["file_info"].(map[string]any)
	md5, _ := fileInfo["md5"].(string)
	origName, _ := fileInfo["original_name"].(string)

	send(operator, map[string]any{
		"action":    "submitted",
		"md5":       md5,
		"file_name": origName,
		"file_info": fileInfo,
	})
}

// run_all — fan out static + dynamic + each EDR profile in parallel
func (p *PluginService) handleRunAll(operator string, args string) {
	var req struct {
		MD5      string   `json:"md5"`
		Static   bool     `json:"static"`
		Dynamic  bool     `json:"dynamic"`
		DynArgs  []string `json:"dyn_args"`
		Profiles []string `json:"profiles"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil || req.MD5 == "" {
		sendError(operator, "run_all requires md5")
		return
	}

	var wg sync.WaitGroup

	if req.Static {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.doStatic(operator, req.MD5)
		}()
	}
	if req.Dynamic {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.doDynamic(operator, req.MD5, req.DynArgs)
		}()
	}
	for _, prof := range req.Profiles {
		wg.Add(1)
		go func(profile string) {
			defer wg.Done()
			p.doEdr(operator, req.MD5, profile)
		}(prof)
	}

	wg.Wait()

	// Risk recomputed from saved JSON now that everything is in
	p.fetchRisk(operator, req.MD5)
	send(operator, map[string]any{"action": "all_done", "md5": req.MD5})
}

func (p *PluginService) handleRunStatic(operator string, args string) {
	var req struct {
		MD5 string `json:"md5"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil || req.MD5 == "" {
		sendError(operator, "run_static requires md5")
		return
	}
	p.doStatic(operator, req.MD5)
	p.fetchRisk(operator, req.MD5)
}

func (p *PluginService) handleRunDynamic(operator string, args string) {
	var req struct {
		MD5  string   `json:"md5"`
		Args []string `json:"args"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil || req.MD5 == "" {
		sendError(operator, "run_dynamic requires md5")
		return
	}
	p.doDynamic(operator, req.MD5, req.Args)
	p.fetchRisk(operator, req.MD5)
}

func (p *PluginService) handleRunEdr(operator string, args string) {
	var req struct {
		MD5      string   `json:"md5"`
		Profiles []string `json:"profiles"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil || req.MD5 == "" || len(req.Profiles) == 0 {
		sendError(operator, "run_edr requires md5 and at least one profile")
		return
	}

	var wg sync.WaitGroup
	for _, prof := range req.Profiles {
		wg.Add(1)
		go func(profile string) {
			defer wg.Done()
			p.doEdr(operator, req.MD5, profile)
		}(prof)
	}
	wg.Wait()
	p.fetchRisk(operator, req.MD5)
}

// ── core analysis primitives ─────────────────────────────────────────────────

func (p *PluginService) doStatic(operator, md5 string) {
	sendStatus(operator, "static", "running")

	body, status, err := lbPostJSON("/analyze/static/"+md5, nil)
	if err != nil {
		sendError(operator, "Static failed: "+err.Error())
		sendStatus(operator, "static", "error")
		return
	}
	if status != 200 {
		sendError(operator, fmt.Sprintf("Static HTTP %d: %s", status, string(body)))
		sendStatus(operator, "static", "error")
		return
	}

	var result map[string]any
	json.Unmarshal(body, &result)

	send(operator, map[string]any{
		"action":  "static_results",
		"md5":     md5,
		"results": result["results"],
	})
	sendStatus(operator, "static", "done")
}

func (p *PluginService) doDynamic(operator, md5 string, dynArgs []string) {
	sendStatus(operator, "dynamic", "running")

	payload := map[string]any{}
	if len(dynArgs) > 0 {
		payload["args"] = dynArgs
	}

	body, status, err := lbPostJSON("/analyze/dynamic/"+md5, payload)
	if err != nil {
		sendError(operator, "Dynamic failed: "+err.Error())
		sendStatus(operator, "dynamic", "error")
		return
	}
	if status != 200 && status != 202 {
		sendError(operator, fmt.Sprintf("Dynamic HTTP %d: %s", status, string(body)))
		sendStatus(operator, "dynamic", "error")
		return
	}

	var result map[string]any
	json.Unmarshal(body, &result)

	send(operator, map[string]any{
		"action":     "dynamic_results",
		"md5":        md5,
		"results":    result["results"],
		"early_term": status == 202,
	})
	sendStatus(operator, "dynamic", "done")
}

func (p *PluginService) doEdr(operator, md5, profile string) {
	sendStatus(operator, "edr:"+profile, "phase1")

	body, status, err := lbPostJSON("/analyze/edr/"+profile+"/"+md5, nil)
	if err != nil {
		send(operator, map[string]any{
			"action":  "edr_error",
			"profile": profile,
			"message": err.Error(),
		})
		sendStatus(operator, "edr:"+profile, "error")
		return
	}
	if status == 409 {
		send(operator, map[string]any{
			"action":  "edr_error",
			"profile": profile,
			"message": "agent busy",
		})
		sendStatus(operator, "edr:"+profile, "busy")
		return
	}
	if status == 502 {
		send(operator, map[string]any{
			"action":  "edr_error",
			"profile": profile,
			"message": "agent unreachable",
		})
		sendStatus(operator, "edr:"+profile, "unreachable")
		return
	}
	if status != 200 {
		send(operator, map[string]any{
			"action":  "edr_error",
			"profile": profile,
			"message": fmt.Sprintf("HTTP %d", status),
		})
		sendStatus(operator, "edr:"+profile, "error")
		return
	}

	var phase1 map[string]any
	json.Unmarshal(body, &phase1)

	send(operator, map[string]any{
		"action":  "edr_phase1",
		"md5":     md5,
		"profile": profile,
		"data":    phase1,
	})
	sendStatus(operator, "edr:"+profile, "polling")

	// Phase 2: adaptive poll
	interval := 2 * time.Second
	deadline := time.Now().Add(300 * time.Second)
	var lastTotal float64 = -1

	for time.Now().Before(deadline) {
		time.Sleep(interval)

		pollBody, pollStatus, pollErr := lbGet("/api/results/edr/" + profile + "/" + md5)
		if pollErr != nil || pollStatus == 404 {
			continue
		}

		var result map[string]any
		json.Unmarshal(pollBody, &result)

		edrStatus, _ := result["status"].(string)

		var total float64 = 0
		if summary, ok := result["summary"].(map[string]any); ok {
			if t, ok := summary["total_alerts"].(float64); ok {
				total = t
			}
		}

		if edrStatus == "polling_alerts" {
			send(operator, map[string]any{
				"action":  "edr_polling",
				"md5":     md5,
				"profile": profile,
				"data":    result,
			})
			if total != lastTotal {
				interval = 2 * time.Second
				lastTotal = total
			} else if interval < 15*time.Second {
				interval = time.Duration(float64(interval) * 1.5)
				if interval > 15*time.Second {
					interval = 15 * time.Second
				}
			}
			continue
		}

		send(operator, map[string]any{
			"action":  "edr_results",
			"md5":     md5,
			"profile": profile,
			"data":    result,
		})
		sendStatus(operator, "edr:"+profile, "done")
		return
	}

	send(operator, map[string]any{
		"action":  "edr_error",
		"profile": profile,
		"message": "polling timed out",
	})
	sendStatus(operator, "edr:"+profile, "timeout")
}

func (p *PluginService) fetchRisk(operator, md5 string) {
	body, status, err := lbGet("/api/results/risk/" + md5)
	if err != nil || status != 200 {
		return
	}
	var result map[string]any
	json.Unmarshal(body, &result)
	send(operator, map[string]any{
		"action":       "risk_results",
		"md5":          md5,
		"risk_score":   result["risk_score"],
		"risk_level":   result["risk_level"],
		"risk_factors": result["risk_factors"],
	})
}

func (p *PluginService) handleGetRisk(operator string, args string) {
	var req struct {
		MD5 string `json:"md5"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil || req.MD5 == "" {
		sendError(operator, "get_risk requires md5")
		return
	}
	p.fetchRisk(operator, req.MD5)
}

func (p *PluginService) handleCleanup(operator string, args string) {
	var req struct {
		MD5 string `json:"md5"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil || req.MD5 == "" {
		sendError(operator, "cleanup requires md5")
		return
	}

	body, status, err := lbDelete("/file/" + req.MD5)
	if err != nil {
		sendError(operator, "Cleanup failed: "+err.Error())
		return
	}
	if status != 200 {
		sendError(operator, fmt.Sprintf("Cleanup HTTP %d: %s", status, string(body)))
		return
	}

	send(operator, map[string]any{"action": "cleaned", "md5": req.MD5})
}

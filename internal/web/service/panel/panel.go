package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/util/version"
	"github.com/mhsanaei/3x-ui/v3/internal/web/global"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

// PanelService provides business logic for panel management operations.
// It handles panel restart, updates, and system-level panel controls.
type PanelService struct{}

// PanelUpdateInfo contains the current and latest available GhandShekan versions.
type PanelUpdateInfo struct {
	Channel         string `json:"channel"`
	CurrentVersion  string `json:"currentVersion"`
	LatestVersion   string `json:"latestVersion"`
	CurrentCommit   string `json:"currentCommit,omitempty"`
	LatestCommit    string `json:"latestCommit,omitempty"`
	UpdateAvailable bool   `json:"updateAvailable"`
}

const (
	panelUpdaterURL      = "https://raw.githubusercontent.com/MaMMaD1999/ghandshekan-3x-ui/%s/pronet-update.sh"
	maxPanelUpdaterBytes = 2 << 20
	// devReleaseTag is the fixed-tag rolling pre-release the CI force-moves to the
	// newest main commit; the dev update channel installs from it.
	devReleaseTag = "dev-latest"

	updateStatePending = "pending"
	updateStateSuccess = "success"
	updateStateFailed  = "failed"
)

// PanelUpdateStatus reports the outcome of the most recently launched panel
// self-update. RunID lets the caller confirm this status belongs to the
// update it started rather than a stale result left over from an earlier
// run; State is one of "pending", "success", or "failed". RunID is a decimal
// string, not a JSON number: it's a formatted UnixNano timestamp, and
// JavaScript's number type can't represent that precisely (it exceeds
// Number.MAX_SAFE_INTEGER), which would let two different runs round to the
// same value on the wire and defeat the whole point of this field.
type PanelUpdateStatus struct {
	RunID      string `json:"runId" example:"1735689600123456789"`
	State      string `json:"state" example:"success"`
	ExitCode   int    `json:"exitCode" example:"0"`
	FinishedAt int64  `json:"finishedAt" example:"1735689612"`
}

var releaseCommitRegex = regexp.MustCompile(`(?i)commit=([0-9a-f]{7,40})`)

// updateMu guards updateRunning/updateStarted/updateRunID/updatePID, which
// stop a second self-update from launching while one is still in flight (two
// concurrent update.sh runs would race each other extracting the release
// tarball and swapping the service unit). A slot is released as soon as the
// in-flight run's own status file reports success or failure -- checked
// against updateRunID so a stale file from an even earlier run can't be
// mistaken for this one finishing -- so a fast failure doesn't lock out a
// retry.
//
// For a run that never reaches a terminal state at all, staleness is judged
// primarily by whether the process we actually launched is still alive
// (updatePID, via processAlive), not by wall-clock time alone: update.sh
// runs install_base() (a package-manager update+install) before anything
// else, plus several downloads, which can legitimately run past a short
// fixed timeout on a slow or throttled host without anything being wrong.
// updateStaleAfter/updatePID together are only a fallback for the systemd-run
// launch path, where the process we can observe (systemd-run itself) has
// already exited by the time startUpdate returns and the actual update.sh
// unit's PID is never recorded -- for that path this is still a pure
// wall-clock heuristic. updateHardCeiling is an absolute backstop so a
// genuinely wedged run (alive but hung forever) can never lock out retries
// permanently, even on the PID-tracked path.
var (
	updateMu         sync.Mutex
	updateRunning    bool
	updateStarted    time.Time
	updateRunID      int64
	updatePID        int
	releaseMu        sync.Mutex
	cachedReleaseTag string
	cachedReleaseAt  time.Time
)

const (
	updateStaleAfter  = 20 * time.Minute
	updateHardCeiling = 2 * time.Hour
)

func (s *PanelService) RestartPanel(delay time.Duration) error {
	go func() {
		time.Sleep(delay)
		if global.TriggerRestart() {
			return
		}
		if runtime.GOOS == "windows" {
			logger.Error("panel restart: no restart hook registered (SIGHUP unsupported on Windows)")
			return
		}
		p, err := os.FindProcess(syscall.Getpid())
		if err != nil {
			logger.Error("panel restart: FindProcess failed:", err)
			return
		}
		if err := p.Signal(syscall.SIGHUP); err != nil {
			logger.Error("failed to send SIGHUP signal:", err)
		}
	}()
	return nil
}

// GetUpdateInfo checks the latest complete GhandShekan release published in the
// custom fork. Upstream releases and the rolling development channel are not
// used by GhandShekan installations.
func (s *PanelService) GetUpdateInfo() (*PanelUpdateInfo, error) {
	latest, err := fetchLatestPanelVersion()
	if err != nil {
		return nil, err
	}
	current := config.GetBaseVersion()
	return &PanelUpdateInfo{
		Channel:         "stable",
		CurrentVersion:  current,
		LatestVersion:   latest,
		UpdateAvailable: isNewerVersion(latest, current),
	}, nil
}

// devChannelActive reports whether self-update should track the rolling dev
// release. It is driven solely by the opt-in setting so the panel can
// cross-grade a stable build onto the dev channel once the user enables it;
// nothing updates without an explicit user action, so an unattended stable
// binary with the toggle off stays on the stable channel.
func devChannelActive() bool {
	enabled, err := (&service.SettingService{}).GetDevChannelEnable()
	return err == nil && enabled
}

// getDevUpdateInfo compares the running commit against the commit recorded in the
// rolling dev release.
func getDevUpdateInfo() (*PanelUpdateInfo, error) {
	release, err := fetchPanelRelease(devReleaseTag)
	if err != nil {
		return nil, err
	}
	latestCommit := extractReleaseCommit(release)
	if latestCommit == "" {
		return nil, fmt.Errorf("dev release commit is unknown")
	}
	currentCommit := config.GetBuildCommit()
	return &PanelUpdateInfo{
		Channel:         "dev",
		CurrentVersion:  config.GetPanelVersion(),
		CurrentCommit:   shortCommit(currentCommit),
		LatestCommit:    shortCommit(latestCommit),
		LatestVersion:   "dev+" + shortCommit(latestCommit),
		UpdateAvailable: !commitsEqual(currentCommit, latestCommit),
	}, nil
}

// StartUpdate starts the updater for the latest complete GhandShekan release.
// Returns the run ID to pass to GetUpdateStatus so callers can distinguish
// this run from a stale result.
func (s *PanelService) StartUpdate() (int64, error) {
	return s.startUpdate(false)
}

// StartUpdateChannel preserves the node-update API contract. GhandShekan nodes only
// accept published custom releases; upstream dev-channel requests are rejected.
func (s *PanelService) StartUpdateChannel(dev bool) (int64, error) {
	if dev {
		return 0, fmt.Errorf("GhandShekan updates use published custom releases only")
	}
	return s.startUpdate(false)
}

// GetUpdateStatus reports the outcome of the most recently launched panel
// self-update, as recorded by update.sh's EXIT trap (see the script for why
// that covers every exit path, not just the happy one). This is a best-effort
// side channel: a missing or unreadable status file reads as "pending"
// rather than an error, since the update itself is what matters, not this
// status file.
func (s *PanelService) GetUpdateStatus() *PanelUpdateStatus {
	data, err := os.ReadFile(config.GetUpdateStatusFilePath())
	if err != nil {
		return &PanelUpdateStatus{State: updateStatePending}
	}
	var status PanelUpdateStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return &PanelUpdateStatus{State: updateStatePending}
	}
	if status.State != updateStateSuccess && status.State != updateStateFailed {
		status.State = updateStatePending
	}
	return &status
}

func (s *PanelService) startUpdate(useDev bool) (int64, error) {
	if useDev {
		return 0, fmt.Errorf("GhandShekan updates use published custom releases only; disable the development channel")
	}
	latest, err := fetchLatestPanelVersion()
	if err != nil {
		return 0, err
	}
	if !isNewerVersion(latest, config.GetBaseVersion()) {
		return 0, fmt.Errorf("GhandShekan is already up to date")
	}

	runID := time.Now().UnixNano()
	if !acquireUpdateSlot(runID) {
		return 0, fmt.Errorf("a panel update is already in progress")
	}
	launched := false
	defer func() {
		if !launched {
			releaseUpdateSlot()
		}
	}()

	if runtime.GOOS != "linux" {
		return 0, fmt.Errorf("panel web update is supported only on Linux installations")
	}

	bash, err := exec.LookPath("bash")
	if err != nil {
		return 0, fmt.Errorf("bash is required to run the panel updater: %w", err)
	}

	backup := filepath.Join(config.GetDBFolderPath(), "pronet-backups", strconv.FormatInt(runID, 10))
	if err := os.MkdirAll(backup, 0700); err != nil {
		return 0, err
	}
	if database.IsPostgres() {
		dsn, err := url.Parse(config.GetDBDSN())
		if err != nil || (dsn.Scheme != "postgres" && dsn.Scheme != "postgresql") || dsn.Path == "/" || dsn.Path == "" {
			return 0, fmt.Errorf("database backup failed: PostgreSQL DSN must be a postgres:// or postgresql:// URL")
		}
		host := dsn.Hostname()
		if host == "" {
			host = "127.0.0.1"
		}
		port := dsn.Port()
		if port == "" {
			port = "5432"
		}
		dbName, err := url.PathUnescape(strings.TrimPrefix(dsn.EscapedPath(), "/"))
		if err != nil {
			return 0, fmt.Errorf("database backup failed: invalid PostgreSQL database name")
		}
		cmd := exec.Command("pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--file="+filepath.Join(backup, "database.dump"), "--dbname", dbName)
		env := append(os.Environ(), "PGHOST="+host, "PGPORT="+port)
		if user := dsn.User.Username(); user != "" {
			env = append(env, "PGUSER="+user)
		}
		if password, ok := dsn.User.Password(); ok {
			env = append(env, "PGPASSWORD="+password)
		}
		for _, key := range []string{"sslmode", "sslcert", "sslkey", "sslrootcert", "sslcrl"} {
			if value := dsn.Query().Get(key); value != "" {
				env = append(env, "PG"+strings.ToUpper(key)+"="+value)
			}
		}
		cmd.Env = env
		if err := cmd.Run(); err != nil {
			return 0, fmt.Errorf("database backup failed; pg_dump must be installed: %w", err)
		}
	} else if err := database.BackupSQLite(filepath.Join(backup, "x-ui.db")); err != nil {
		return 0, fmt.Errorf("database backup failed: %w", err)
	}
	scriptPath, err := downloadPanelUpdater(latest)
	if err != nil {
		return 0, err
	}

	statusFile := config.GetUpdateStatusFilePath()

	mainFolder, serviceFolder := resolveUpdateFolders()
	updateTag := latest
	updateScript := fmt.Sprintf("set -e; trap 'rm -f %s' EXIT; %s %s >>%s 2>&1", shellQuote(scriptPath), shellQuote(bash), shellQuote(scriptPath), shellQuote(filepath.Join(backup, "update.log")))
	updateScript = "export XUI_UPDATE_PID=" + strconv.Itoa(os.Getpid()) + "; export XUI_BACKUP_FOLDER=" + shellQuote(backup) + "; " + updateScript
	runIDEnv := "XUI_UPDATE_RUN_ID=" + strconv.FormatInt(runID, 10)
	statusFileEnv := "XUI_UPDATE_STATUS_FILE=" + statusFile
	proxyEnv := updateProxyEnvVars()

	if systemdRun, err := exec.LookPath("systemd-run"); err == nil {
		unitName := fmt.Sprintf("x-ui-web-update-%d", time.Now().Unix())
		args := []string{
			"--unit", unitName,
			"--setenv", "XUI_MAIN_FOLDER=" + mainFolder,
			"--setenv", "XUI_SERVICE=" + serviceFolder,
			"--setenv", "XUI_UPDATE_TAG=" + updateTag,
			"--setenv", runIDEnv,
			"--setenv", statusFileEnv,
		}
		for _, kv := range proxyEnv {
			args = append(args, "--setenv", kv)
		}
		args = append(args, bash, "-lc", updateScript)
		cmd := exec.CommandContext(context.Background(), systemdRun, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			output := strings.TrimSpace(string(out))
			if !strings.Contains(output, "System has not been booted with systemd") &&
				!strings.Contains(output, "Failed to connect to bus") {
				_ = os.Remove(scriptPath)
				return 0, fmt.Errorf("failed to start panel update job: %w: %s", err, output)
			}
			logger.Warning("systemd-run is unavailable, falling back to detached update process:", output)
		} else {
			logger.Infof("started panel update job via systemd-run unit %s", unitName)
			launched = true
			return runID, nil
		}
	}

	cmd := exec.CommandContext(context.Background(), bash, "-lc", updateScript)
	cmd.Env = append(os.Environ(),
		"XUI_MAIN_FOLDER="+mainFolder,
		"XUI_SERVICE="+serviceFolder,
		"XUI_UPDATE_TAG="+updateTag,
		runIDEnv,
		statusFileEnv,
	)
	setDetachedProcess(cmd)
	if err := cmd.Start(); err != nil {
		_ = os.Remove(scriptPath)
		return 0, fmt.Errorf("failed to start panel update job: %w", err)
	}
	if err := cmd.Process.Release(); err != nil {
		logger.Warning("failed to release panel update process:", err)
	}
	logger.Infof("started panel update job with pid %d", cmd.Process.Pid)
	recordUpdatePID(cmd.Process.Pid)
	launched = true
	return runID, nil
}

// updateProxyEnvVars forwards ambient proxy env vars to systemd-run's child,
// which (unlike the bash fallback) inherits nothing but --setenv.
func updateProxyEnvVars() []string {
	var out []string
	for _, key := range []string{"https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY"} {
		if v := os.Getenv(key); v != "" {
			out = append(out, key+"="+v)
		}
	}
	return out
}

// acquireUpdateSlot claims the single in-flight-update slot for runID. It
// refuses while another run is genuinely still in flight, but grants the
// slot immediately once that run's own status file reports a terminal
// result (success or failure) -- a fast failure shouldn't force the next
// attempt to wait out updateStaleAfter for no reason. Past updateStaleAfter
// with no terminal status yet, it grants the slot anyway UNLESS the process
// we recorded (updatePID) is confirmed still alive, so a merely-slow run
// isn't mistaken for a crashed one; past updateHardCeiling it grants the
// slot unconditionally regardless of liveness, so a truly wedged run can
// never lock out retries forever.
func acquireUpdateSlot(runID int64) bool {
	updateMu.Lock()
	defer updateMu.Unlock()
	if updateRunning && !previousRunIsTerminal() {
		elapsed := time.Since(updateStarted)
		if elapsed < updateHardCeiling {
			stale := elapsed >= updateStaleAfter
			alive := updatePID > 0 && processAlive(updatePID)
			if !stale || alive {
				return false
			}
		}
	}
	updateRunning = true
	updateStarted = time.Now()
	updateRunID = runID
	updatePID = 0
	return true
}

// recordUpdatePID notes the PID of the detached update.sh process the
// current slot is tracking, so a later acquireUpdateSlot call can check
// whether it is actually still running instead of only how long ago it
// started. Only reachable for the detached-fallback launch path -- the
// systemd-run path never learns update.sh's own PID, since the process it
// directly observes (systemd-run) has already exited by the time it returns.
func recordUpdatePID(pid int) {
	updateMu.Lock()
	updatePID = pid
	updateMu.Unlock()
}

// previousRunIsTerminal reports whether the run currently recorded in
// updateRunID has reached success or failure per its status file. Must be
// called with updateMu held.
func previousRunIsTerminal() bool {
	status := (&PanelService{}).GetUpdateStatus()
	return status.RunID == strconv.FormatInt(updateRunID, 10) && status.State != updateStatePending
}

func releaseUpdateSlot() {
	updateMu.Lock()
	updateRunning = false
	updateMu.Unlock()
}

func downloadPanelUpdater(tag string) (string, error) {
	client := (&service.SettingService{}).NewProxiedHTTPClient(15 * time.Second)
	req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf(panelUpdaterURL, tag), nil)
	if reqErr != nil {
		return "", fmt.Errorf("download panel updater: %w", reqErr)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download panel updater: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download panel updater: unexpected HTTP %d", resp.StatusCode)
	}

	file, err := os.CreateTemp("", "3x-ui-update-*.sh")
	if err != nil {
		return "", err
	}
	path := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()

	n, err := io.Copy(file, io.LimitReader(resp.Body, maxPanelUpdaterBytes+1))
	if err != nil {
		return "", fmt.Errorf("write panel updater: %w", err)
	}
	if n == 0 {
		return "", fmt.Errorf("panel updater download is empty")
	}
	if n > maxPanelUpdaterBytes {
		return "", fmt.Errorf("panel updater exceeds %d bytes", maxPanelUpdaterBytes)
	}
	if err := file.Chmod(0o700); err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

func fetchLatestPanelVersion() (string, error) {
	releaseMu.Lock()
	defer releaseMu.Unlock()
	if cachedReleaseTag != "" && time.Since(cachedReleaseAt) < 5*time.Minute {
		return cachedReleaseTag, nil
	}
	release, err := fetchPanelRelease("")
	if err != nil {
		return "", err
	}
	if release.TagName == "" {
		return "", fmt.Errorf("latest panel release tag is empty")
	}
	cachedReleaseTag, cachedReleaseAt = release.TagName, time.Now()
	return cachedReleaseTag, nil
}

// fetchPanelRelease fetches a complete release from the GhandShekan fork. The empty
// tag selects the newest complete custom release; a non-empty tag resolves it.
func fetchPanelRelease(tag string) (*service.Release, error) {
	url := "https://api.github.com/repos/MaMMaD1999/ghandshekan-3x-ui/releases?per_page=100"
	if tag != "" {
		url = "https://api.github.com/repos/MaMMaD1999/ghandshekan-3x-ui/releases/tags/" + tag
	}
	client := (&service.SettingService{}).NewProxiedHTTPClient(10 * time.Second)
	req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if reqErr != nil {
		return nil, reqErr
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, resp.Status)
	}

	if tag == "" {
		var releases []struct {
			service.Release
			Draft  bool `json:"draft"`
			Assets []struct {
				Name string `json:"name"`
			} `json:"assets"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&releases); err != nil {
			return nil, err
		}
		var best *service.Release
		for _, r := range releases {
			if r.Draft || !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+-(?:pronet|ghandshekan)\.[0-9]+$`).MatchString(r.TagName) {
				continue
			}
			files := map[string]bool{}
			for _, asset := range r.Assets {
				files[asset.Name] = true
			}
			if !files["checksums.txt"] || !files["x-ui-linux-amd64.tar.gz"] || !files["x-ui-linux-arm64.tar.gz"] {
				continue
			}
			if best == nil || isNewerVersion(r.TagName, best.TagName) {
				copy := r.Release
				best = &copy
			}
		}
		if best == nil {
			return nil, fmt.Errorf("no complete GhandShekan release found")
		}
		return best, nil
	}
	var release service.Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}
	return &release, nil
}

// extractReleaseCommit reads the build commit recorded in the dev release: first
// the `commit=<sha>` marker the CI writes into the body, falling back to the
// tag's target commit.
func extractReleaseCommit(release *service.Release) string {
	if m := releaseCommitRegex.FindStringSubmatch(release.Body); m != nil {
		return strings.ToLower(m[1])
	}
	if isCommitSHA(release.TargetCommitish) {
		return strings.ToLower(release.TargetCommitish)
	}
	return ""
}

func isCommitSHA(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 7 || len(s) > 40 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

func shortCommit(sha string) string {
	sha = strings.TrimSpace(sha)
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

// commitsEqual compares a short (injected) commit against a full release commit
// by prefix, so an 8-char build stamp matches the 40-char release SHA.
func commitsEqual(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	return strings.HasPrefix(b, a)
}

func resolveUpdateFolders() (string, string) {
	mainFolder := os.Getenv("XUI_MAIN_FOLDER")
	if mainFolder == "" {
		if exePath, err := os.Executable(); err == nil {
			mainFolder = filepath.Dir(exePath)
		}
	}
	if mainFolder == "" {
		mainFolder = "/usr/local/x-ui"
	}

	serviceFolder := os.Getenv("XUI_SERVICE")
	if serviceFolder == "" {
		serviceFolder = "/etc/systemd/system"
	}
	return mainFolder, serviceFolder
}

func isNewerVersion(latest string, current string) bool {
	cmp, ok := version.Compare(latest, current)
	if !ok {
		return version.Normalize(latest) != version.Normalize(current)
	}
	return cmp > 0
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

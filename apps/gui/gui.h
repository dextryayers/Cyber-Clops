#pragma once
// Cyber-Clops GUI state. English only. No emdash in strings.
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

struct ToolMeta {
  const char* id;
  const char* name;
  const char* group;
  const char* desc;
  const char* verb;
  const char* extra_label;
};

inline const ToolMeta kTools[25] = {
  {"T01", "Subdomain Enumerator", "Recon", "Aggregate 22 cert and DNS sources, no key, wildcard filtered.", "", "Domain"},
  {"T02", "DNS Toolkit", "Recon", "A AAAA MX TXT NS SOA CAA query plus AXFR check plus DoH fallback.", "resolve", "Host"},
  {"T03", "Port Scanner", "Recon", "Fast TCP scan with banner grab and version refine, live rows.", "scan", "Ports (80,443,8000-8010)"},
  {"T04", "SSL/TLS Analyzer", "Recon", "Chain length, expiry, SAN, TLS 1.2 and 1.3 probe, HSTS, grade.", "tls", "Port (443)"},
  {"T05", "HTTP Fingerprint", "Recon", "Server, tech stack, WAF, cookie flags, header audit.", "fetch", "URL"},
  {"T06", "Cloud + Takeover", "Recon", "Bucket probes plus 30 takeover fingerprints, signal only.", "", "Host"},
  {"T07", "Directory Bruteforcer", "Web", "Fuzz paths with smart 404 filter, checkpoint resume.", "dirbrute", "Wordlist path"},
  {"T08", "Web Spider", "Web", "Crawl with depth limit, robots respect, sitemap, forms.", "", "Seed URL"},
  {"T09", "Endpoint + Secrets", "Web", "JS endpoints plus 10 high precision secret patterns.", "", "URL or HAR"},
  {"T10", "SQLi Detector", "Web", "Safe error plus boolean plus gated time checks, GET and POST.", "", "URL with param"},
  {"T11", "XSS Scanner", "Web", "Reflected double send with context and encoding flag.", "", "URL with param"},
  {"T12", "LFI + SSTI Tester", "Web", "Traversal markers plus template math probe, no RCE.", "", "URL with param"},
  {"T13", "Misconfig Checker", "Web", "CORS, clickjacking, HSTS, CSP, cookies, listing, git.", "fetch", "Base URL"},
  {"T14", "Repeater", "Web", "Raw resend with timing, diff, 200 entry history.", "", "URL"},
  {"T15", "Intercept Proxy", "Network", "HTTP forward plus CONNECT relay, scope gated, history.", "", "Listen addr"},
  {"T16", "Packet Sniffer", "Network", "Offline PCAP parse with TCP UDP DNS decode.", "", "PCAP path"},
  {"T17", "CVE Mapper", "Network", "Offline service version to CVE match.", "", "service/version"},
  {"T18", "Payload Generator", "Network", "Lab shells with listener helper, encoded variants.", "", "LHOST LPORT"},
  {"T19", "Codec Lab", "Crack", "Base64 hex url html jwt time uuid, bulk files.", "codec", "op (b64encode...)"},
  {"T20", "Hash Cracker", "Crack", "Dict plus mask plus hybrid, honest H/s backend badge.", "crack-dict", "ALGO HASH"},
  {"T21", "Wordlist Studio", "Crack", "Dedupe, mutate, combine, regex, lua transform, stream.", "", "Wordlist path"},
  {"T22", "OSINT Toolkit", "Intel", "Username check, MX, local breach match, wayback, dorks.", "", "Username/domain"},
  {"T23", "Chain Builder", "Intel", "No code DAG with dry run and real recon execute.", "", "Chain file"},
  {"T24", "AI Auto Hacker", "Intel", "Planner with approval gates, redact, replay, Ollama optional.", "", "Goal"},
  {"T25", "Report Center", "Report", "Severity ordered findings, redacted evidence, HTML JSON.", "", "Project"},
};

inline const char* kGroups[6] = {"Recon", "Web", "Network", "Crack", "Intel", "Report"};

struct PortRow {
  int port = 0;
  std::string state;
  std::string service;
  std::string version;
  std::string banner;
};

struct Job {
  int id = 0;
  std::string tool;
  std::string target;
  std::string status;
  long started_ms = 0;
};

struct AppState {
  int active = 2;
  char target[256] = "127.0.0.1";
  char extra[256] = "80,443";
  int profile = 3;
  bool safe_mode = true;
  bool palette_open = false;
  char palette_filter[128] = "";
  std::string accel_text = "CPU: unknown | Backend: CPU only";
  std::vector<PortRow> rows;
  std::vector<Job> jobs;
  std::vector<std::string> logs;
  int selected = -1;
  int next_job = 1;
  std::mutex mu;
  std::atomic<bool> cancel_flag{false};
};

bool scope_allowed(const std::string& target);
std::string shell_escape(const std::string& s);
void run_tool(AppState& st, int tool_idx);
void stop_jobs(AppState& st);

void panels_draw_topbar(AppState& st);
void panels_draw_left_tree(AppState& st);
void panels_draw_center(AppState& st);
void panels_draw_inspector(AppState& st);
void panels_draw_bottom(AppState& st);
void panels_draw_palette(AppState& st);
void table_draw_ports(AppState& st);

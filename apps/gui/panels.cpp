#include "gui.h"
#include "imgui.h"
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <thread>

namespace ClopsFonts {
extern void* ui;
extern void* ui_bold;
extern void* mono;
}

static void push_ui() {
  if (ClopsFonts::ui) ImGui::PushFont((ImFont*)ClopsFonts::ui);
}
static void push_bold() {
  if (ClopsFonts::ui_bold) ImGui::PushFont((ImFont*)ClopsFonts::ui_bold);
  else push_ui();
}
static void push_mono() {
  if (ClopsFonts::mono) ImGui::PushFont((ImFont*)ClopsFonts::mono);
  else push_ui();
}
static void pop_font(void* f) {
  if (f) ImGui::PopFont();
}

static long now_ms() {
  using namespace std::chrono;
  return (long)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

std::string fmt_clock() {
  std::time_t t = std::time(nullptr);
  struct tm tmv;
#ifdef _WIN32
  localtime_s(&tmv, &t);
#else
  localtime_r(&t, &tmv);
#endif
  char buf[16];
  std::strftime(buf, sizeof(buf), "%H:%M:%S", &tmv);
  return buf;
}

void push_toast(AppState& st, const std::string& text) {
  while (st.toasts.size() >= 4) st.toasts.erase(st.toasts.begin());
  st.toasts.push_back({text, now_ms() + 3000});
}

void push_audit(AppState& st, const std::string& event) {
  st.audit.push_back(fmt_clock() + "  " + event);
  if (st.audit.size() > 500) st.audit.erase(st.audit.begin());
}

// Scope mirror of Rust Scope::lab_only. UI rejects before any job starts.
bool scope_allowed(const std::string& target) {
  std::string t = target;
  for (const char* p : {"http://", "https://"}) {
    if (t.rfind(p, 0) == 0) t = t.substr(std::strlen(p));
  }
  auto slash = t.find('/');
  if (slash != std::string::npos) t = t.substr(0, slash);
  auto colon = t.rfind(':');
  std::string host = (colon == std::string::npos) ? t : t.substr(0, colon);
  if (!host.empty() && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);
  for (auto& c : host) c = (char)std::tolower(c);
  if (host.empty()) return false;
  if (host == "localhost" || host == "example.com") return true;
  if (host.size() > 12 && host.compare(host.size() - 12, 12, ".example.com") == 0) return true;
  if (host == "127.0.0.1") return true;
  if (host.rfind("127.", 0) == 0) return true;
  return false;
}

std::string shell_escape(const std::string& s) {
  std::string o = "'";
  for (char c : s) {
    if (c == '\'') o += "'\\''";
    else o += c;
  }
  o += "'";
  return o;
}

static int find_int(const std::string& line, const char* key, int dflt) {
  auto p = line.find(key);
  if (p == std::string::npos) return dflt;
  return std::atoi(line.c_str() + p + std::strlen(key));
}

static bool find_bool(const std::string& line, const char* key) {
  auto p = line.find(key);
  if (p == std::string::npos) return false;
  return line.compare(p + std::strlen(key), 4, "true") == 0;
}

static std::string find_str(const std::string& line, const char* key) {
  auto p = line.find(key);
  if (p == std::string::npos) return "";
  p += std::strlen(key);
  std::string o;
  for (size_t i = p; i < line.size(); i++) {
    char c = line[i];
    if (c == '\\' && i + 1 < line.size()) {
      char n = line[i + 1];
      if (n == 'n') o += '\n';
      else if (n == 'r') o += '\r';
      else if (n == 't') o += '\t';
      else o += n;
      i++;
    } else if (c == '"') {
      break;
    } else {
      o += c;
    }
  }
  return o;
}

static double find_num(const std::string& line, const char* key, double dflt) {
  auto p = line.find(key);
  if (p == std::string::npos) return dflt;
  return std::atof(line.c_str() + p + std::strlen(key));
}

int find_page(AppState& st, int tool_idx) {
  for (size_t i = 0; i < st.pages.size(); i++) {
    if (st.pages[i].tool_idx == tool_idx) return (int)i;
  }
  return -1;
}

int open_page(AppState& st, int tool_idx) {
  for (size_t i = 0; i < st.recent.size(); i++) {
    if (st.recent[i] == tool_idx) {
      st.recent.erase(st.recent.begin() + i);
      break;
    }
  }
  st.recent.insert(st.recent.begin(), tool_idx);
  while (st.recent.size() > 5) st.recent.pop_back();
  int i = find_page(st, tool_idx);
  if (i >= 0) {
    st.active_tab = i;
    return i;
  }
  ToolPage pg;
  pg.tool_idx = tool_idx;
  st.pages.push_back(pg);
  st.active_tab = (int)st.pages.size() - 1;
  return st.active_tab;
}

// Parse one JSONL line from clops-job into the active page.
static void ingest_line(AppState& st, int page_idx, const std::string& verb, const std::string& line, int& rows) {
  ToolPage& pg = st.pages[page_idx];
  if (!line.empty() && line[0] != '{') {
    if (line.size() > 4) pg.errors++;
    return;
  }
  if (line.empty()) return;
  pg.raw.push_back(line.size() > 2000 ? line.substr(0, 2000) : line);
  if (pg.raw.size() > 200) pg.raw.erase(pg.raw.begin());
  const ToolMeta& tm = kTools[pg.tool_idx];
  if (verb == "scan") {
    PortRow r;
    r.port = find_int(line, "\"port\":", 0);
    r.proto = "TCP";
    r.state = find_bool(line, "\"open\":") ? "open" : "closed";
    r.service = find_str(line, "\"service\":\"");
    r.version = find_str(line, "\"version\":\"");
    r.banner = find_str(line, "\"banner\":\"");
    r.latency_ms = (long)find_num(line, "\"latency_ms\":", 0);
    if (r.state == "open") {
      pg.ports.push_back(r);
      rows++;
    }
    return;
  }
  FindingRow f;
  f.tool = tm.id;
  f.severity = "Info";
  if (verb == "resolve") {
    f.title = std::string("Resolved: ") + find_str(line, "\"host\":\"");
    f.detail = line.size() > 240 ? line.substr(0, 240) : line;
  } else if (verb == "tls") {
    f.title = std::string("CN ") + find_str(line, "\"cert_cn\":\"");
    std::string grade = find_str(line, "\"grade\":\"");
    f.severity = (grade == "F") ? "High" : (grade == "C" ? "Medium" : "Low");
    f.title += " grade " + grade;
    f.detail = line.size() > 240 ? line.substr(0, 240) : line;
  } else if (verb == "fetch") {
    f.title = std::string("Server ") + find_str(line, "\"server\":\"");
    std::string waf = find_str(line, "\"waf\":\"");
    if (!waf.empty()) f.title += std::string(" WAF ") + waf;
    f.detail = line.size() > 240 ? line.substr(0, 240) : line;
  } else if (verb == "dirbrute") {
    f.title = find_str(line, "\"path\":\"") + " -> " + std::to_string(find_int(line, "\"status\":", 0));
    f.detail = line.size() > 240 ? line.substr(0, 240) : line;
  } else if (verb == "codec") {
    f.title = std::string("op ") + find_str(line, "\"op\":\"");
    f.detail = find_str(line, "\"output\":\"");
  } else if (verb == "crack-dict") {
    auto pp = line.find("\"password\":");
    if (pp != std::string::npos && line.compare(pp + 12, 4, "null") == 0) {
      f.title = std::string("not found, tested ") + std::to_string((long)find_num(line, "\"tested\":", 0));
    } else {
      f.title = std::string("CRACKED: ") + find_str(line, "\"password\":\"");
      f.severity = "High";
    }
    f.detail = line.size() > 240 ? line.substr(0, 240) : line;
  } else {
    f.title = line.size() > 120 ? line.substr(0, 120) : line;
    f.detail = line;
  }
  pg.findings.push_back(f);
  rows++;
}

void run_tool(AppState& st, int tool_idx) {
  const ToolMeta& tm = kTools[tool_idx];
  std::string target;
  std::string extra;
  int conc, timeout, rate;
  {
    std::lock_guard<std::mutex> lk(st.mu);
    target = st.target;
    extra = st.extra;
    conc = st.concurrency;
    timeout = st.timeout_ms;
    rate = st.rate_rps;
  }
  if (!scope_allowed(target) && std::string(tm.verb) != std::string("codec")) {
    std::lock_guard<std::mutex> lk(st.mu);
    st.logs.push_back(fmt_clock() + "  DENY target outside scope: " + target);
    push_audit(st, "Scope denied " + std::string(tm.id) + " " + target);
    push_toast(st, "Target outside scope");
    st.scope_dialog_target = target;
    st.show_scope_dialog = true;
    return;
  }
  int jid;
  int page_idx;
  {
    std::lock_guard<std::mutex> lk(st.mu);
    jid = st.next_job++;
    st.jobs.push_back({jid, tm.id, target, "Running", now_ms(), 0});
    st.logs.push_back(fmt_clock() + "  INFO Job #" + std::to_string(jid) + " started " + tm.id + " " + target);
    push_audit(st, "Scope accepted " + std::string(tm.id) + " " + target);
    push_toast(st, std::string("Job started ") + tm.id);
    page_idx = open_page(st, tool_idx);
    st.pages[page_idx].target = target;
    st.pages[page_idx].extra = extra;
    st.pages[page_idx].started_ms = now_ms();
    st.pages[page_idx].errors = 0;
  }
  if (std::string(tm.verb).empty()) {
    std::lock_guard<std::mutex> lk(st.mu);
    st.logs.push_back(fmt_clock() + "  INFO Job #" + std::to_string(jid) + " queued. Engine runs via core API.");
    push_audit(st, "Queued " + std::string(tm.id) + " " + target);
    for (auto& j : st.jobs) {
      if (j.id == jid) j.status = "Queued";
    }
    return;
  }
  std::string cmd;
  std::string verb = tm.verb;
  std::string tstr = std::to_string(timeout);
  std::string cstr = std::to_string(conc);
  if (verb == "resolve") {
    cmd = std::string("clops-job resolve --host ") + shell_escape(target);
  } else if (verb == "scan") {
    cmd = std::string("clops-job scan --host ") + shell_escape(target) + " --ports " + shell_escape(extra) +
      " --timeout " + tstr + " --concurrency " + cstr;
    if (rate > 0) cmd += " --rate " + std::to_string(rate);
  } else if (verb == "tls") {
    cmd = std::string("clops-job tls --host ") + shell_escape(target) + " --port " + shell_escape(extra) +
      " --timeout " + tstr;
  } else if (verb == "fetch") {
    cmd = std::string("clops-job fetch --url ") + shell_escape(target) + " --timeout " + tstr;
  } else if (verb == "dirbrute") {
    cmd = std::string("clops-job dirbrute --base ") + shell_escape(target) + " --wordlist " + shell_escape(extra) +
      " --concurrency " + cstr + " --timeout " + tstr;
    if (rate > 0) cmd += " --rate " + std::to_string(rate);
  } else if (verb == "codec") {
    cmd = std::string("clops-job codec --op ") + shell_escape(extra) + " --input " + shell_escape(target);
  } else if (verb == "crack-dict") {
    cmd = std::string("clops-job crack-dict ") + shell_escape(extra);
  } else {
    cmd = "";
  }
  std::thread([cmd, jid, verb, page_idx, &st]() {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
      std::lock_guard<std::mutex> lk(st.mu);
      st.logs.push_back(fmt_clock() + "  ERROR Job #" + std::to_string(jid) + " failed to spawn. Is clops-job on PATH?");
      push_audit(st, "Spawn failed job #" + std::to_string(jid));
      push_toast(st, "Spawn failed. Is clops-job on PATH?");
      for (auto& j : st.jobs) {
        if (j.id == jid) j.status = "Failed";
      }
      return;
    }
    char buf[4096];
    std::string pending;
    int rows = 0;
    while (fgets(buf, sizeof(buf), pipe)) {
      if (st.cancel_flag.load()) break;
      pending += buf;
      size_t pos;
      while ((pos = pending.find('\n')) != std::string::npos) {
        std::string line = pending.substr(0, pos);
        pending = pending.substr(pos + 1);
        std::lock_guard<std::mutex> lk(st.mu);
        if (page_idx < (int)st.pages.size()) ingest_line(st, page_idx, verb, line, rows);
      }
    }
    int rc = pclose(pipe);
    std::lock_guard<std::mutex> lk(st.mu);
    bool ok = (rc == 0 && !st.cancel_flag.load());
    for (auto& j : st.jobs) {
      if (j.id == jid) {
        j.status = ok ? "Done" : "Cancelled";
        j.rows = rows;
      }
    }
    st.logs.push_back(fmt_clock() + (ok ? "  INFO Job #" : "  WARN Job #") + std::to_string(jid) +
      " finished: " + std::to_string(rows) + " rows");
    push_audit(st, std::string(ok ? "Completed " : "Cancelled ") + "job #" + std::to_string(jid));
    push_toast(st, std::string("Job ") + (ok ? "completed " : "cancelled ") + std::to_string(rows) + " rows");
  }).detach();
}

void stop_jobs(AppState& st) {
  st.cancel_flag.store(true);
  std::lock_guard<std::mutex> lk(st.mu);
  for (auto& j : st.jobs) {
    if (j.status == "Running") {
      j.status = "Cancelled";
      push_audit(st, "Cancelled job #" + std::to_string(j.id));
    }
  }
  st.logs.push_back(fmt_clock() + "  WARN Stop pressed. Running jobs cancelled.");
  push_toast(st, "Stop pressed");
  st.cancel_flag.store(false);
}

static void badge(const char* label, const ImVec4& col) {
  ImGui::TextColored(col, "%s", label);
}

void panels_draw_topbar(AppState& st) {
  // Fixed top strip instead of viewport menu bar. Same content, deterministic
  // visibility on every backend. Height 40 per spec section 20.
  ImGuiViewport* vp = ImGui::GetMainViewport();
  float W = vp->WorkSize.x > 0 ? vp->WorkSize.x : 1400;
  ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, vp->WorkPos.y), ImGuiCond_Always);
  ImGui::SetNextWindowSize(ImVec2(W, 40), ImGuiCond_Always);
  ImGui::Begin("##topbar", nullptr,
    ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings);
  push_bold();
  ImGui::Text("CYBER-CLOPS");
  pop_font(ClopsFonts::ui_bold ? ClopsFonts::ui_bold : ClopsFonts::ui);
  ImGui::SameLine();
  ImGui::TextDisabled("|");
  ImGui::SameLine();
  ImGui::TextDisabled("Project: demo.clops");
  ImGui::SameLine();
  ImGui::TextDisabled("|");
  ImGui::SameLine();
  ImGui::Text("Scope: lab-only");
  ImGui::SameLine();
  ImGui::TextDisabled("|");
  ImGui::SameLine();
  if (st.safe_mode) badge("Safe Mode: ON", ImVec4(0.25f, 0.73f, 0.44f, 1.0f));
  else badge("Safe Mode: OFF", ImVec4(0.90f, 0.33f, 0.29f, 1.0f));
  ImGui::SameLine();
  ImGui::TextDisabled("|");
  ImGui::SameLine();
  ImGui::TextDisabled("%s", st.accel_text.c_str());
  ImGui::SameLine();
  ImGui::TextDisabled("|");
  ImGui::SameLine();
  int running = 0;
  for (auto& j : st.jobs) {
    if (j.status == "Running") running++;
  }
  if (ImGui::Button(running > 0 ? ("Jobs: " + std::to_string(running)).c_str() : "Jobs: 0")) {
    st.bottom_tab = 0;
  }
  ImGui::SameLine();
  ImGui::TextDisabled("|");
  ImGui::SameLine();
  if (ImGui::Button("Cmd+K")) st.palette_open = true;
  ImGui::SameLine();
  ImGui::TextDisabled("|");
  ImGui::SameLine();
  if (ImGui::Button("Settings")) st.show_settings = true;
  ImGui::End();
}

static std::string upper_of(const char* s) {
  std::string o = s;
  for (auto& c : o) c = (char)std::toupper(c);
  return o;
}

void panels_draw_left_tree(AppState& st) {
  // Proportional first-run placement. Docking owns final positions after that.
  ImGuiViewport* vp = ImGui::GetMainViewport();
  float W = vp->WorkSize.x > 0 ? vp->WorkSize.x : 1400;
  float H = vp->WorkSize.y > 0 ? vp->WorkSize.y : 900;
  float navw = W * 0.18f < 230 ? 230 : (W * 0.18f > 300 ? 300 : W * 0.18f);
  float drawh = H * 0.26f < 200 ? 200 : (H * 0.26f > 280 ? 280 : H * 0.26f);
  ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, vp->WorkPos.y + 40), ImGuiCond_FirstUseEver);
  ImGui::SetNextWindowSize(ImVec2(navw, H - drawh - 40), ImGuiCond_FirstUseEver);
  ImGui::Begin("Navigator");
  push_bold();
  ImGui::Text("PROJECT");
  pop_font(ClopsFonts::ui_bold ? ClopsFonts::ui_bold : ClopsFonts::ui);
  size_t n_ports = 0, n_find = 0;
  for (auto& pg : st.pages) {
    n_ports += pg.ports.size();
    n_find += pg.findings.size();
  }
  ImGui::TextDisabled("Targets (1)  Ports (%d)  Findings (%d)", (int)n_ports, (int)n_find);
  ImGui::Separator();
  ImGui::InputText("Search tools", st.nav_filter, sizeof(st.nav_filter));
  ImGui::Separator();
  std::string nf = st.nav_filter;
  for (auto& c : nf) c = (char)std::tolower(c);
  for (auto g : kGroups) {
    bool any = nf.empty();
    if (!any) {
      for (int i = 0; i < 25; i++) {
        if (std::string(kTools[i].group) != g) continue;
        std::string hay = std::string(kTools[i].id) + " " + kTools[i].name + " " + kTools[i].desc;
        for (auto& c : hay) c = (char)std::tolower(c);
        if (hay.find(nf) != std::string::npos) {
          any = true;
          break;
        }
      }
      if (!any) continue;
    }
    ImGui::SetNextItemOpen(true, ImGuiCond_FirstUseEver);
    push_mono();
    bool node = ImGui::TreeNode(upper_of(g).c_str());
    pop_font(ClopsFonts::mono);
    if (node) {
      for (int i = 0; i < 25; i++) {
        if (std::string(kTools[i].group) != g) continue;
        if (!nf.empty()) {
          std::string hay = std::string(kTools[i].id) + " " + kTools[i].name + " " + kTools[i].desc;
          for (auto& c : hay) c = (char)std::tolower(c);
          if (hay.find(nf) == std::string::npos) continue;
        }
        char label[128];
        std::snprintf(label, sizeof(label), "%s  %s", kTools[i].id, kTools[i].name);
        bool sel = st.active_tab >= 0 && st.active_tab < (int)st.pages.size() &&
          st.pages[st.active_tab].tool_idx == i;
        if (find_page(st, i) >= 0) {
          ImGui::Bullet();
          ImGui::SameLine();
        }
        if (ImGui::Selectable(label, sel)) {
          st.active = i;
          open_page(st, i);
        }
      }
      ImGui::TreePop();
    }
  }
  ImGui::End();
}

static std::string mmss(long ms) {
  if (ms <= 0) return "--:--";
  long s = ms / 1000;
  char b[16];
  std::snprintf(b, sizeof(b), "%02ld:%02ld", s / 60, s % 60);
  return b;
}

static void metrics_strip(AppState& st, ToolPage& pg) {
  long elapsed = pg.started_ms > 0 ? now_ms() - pg.started_ms : 0;
  size_t found = pg.ports.size() + pg.findings.size();
  ImGui::TextDisabled("Elapsed");
  ImGui::SameLine();
  push_mono();
  ImGui::Text("%s", mmss(elapsed).c_str());
  pop_font(ClopsFonts::mono);
  ImGui::SameLine();
  ImGui::TextDisabled("| Found");
  ImGui::SameLine();
  push_mono();
  ImGui::Text("%d", (int)found);
  pop_font(ClopsFonts::mono);
  ImGui::SameLine();
  ImGui::TextDisabled("| Errors");
  ImGui::SameLine();
  push_mono();
  ImGui::Text("%d", pg.errors);
  pop_font(ClopsFonts::mono);
  ImGui::SameLine();
  ImGui::TextDisabled("| Backend");
  ImGui::SameLine();
  push_mono();
  ImGui::Text("%s", st.backend.c_str());
  pop_font(ClopsFonts::mono);
}

static void tool_form(AppState& st, const ToolMeta& tm, int tool_idx) {
  push_bold();
  ImGui::Text("%s  %s", tm.id, tm.name);
  pop_font(ClopsFonts::ui_bold ? ClopsFonts::ui_bold : ClopsFonts::ui);
  ImGui::SameLine();
  ImGui::TextDisabled("%s", tm.desc);
  ImGui::SameLine();
  badge("SAFE", ImVec4(0.25f, 0.73f, 0.44f, 1.0f));
  ImGui::Separator();
  ImGui::InputText("Target", st.target, sizeof(st.target));
  ImGui::InputText(tm.extra_label, st.extra, sizeof(st.extra));
  const char* profiles[] = {"Fast", "Balanced", "Deep", "Lab"};
  ImGui::Combo("Profile", &st.profile, profiles, 4);
  ImGui::SliderInt("Concurrency", &st.concurrency, 1, 1000);
  ImGui::SliderInt("Timeout ms", &st.timeout_ms, 200, 15000);
  ImGui::SliderInt("Rate rps (0 off)", &st.rate_rps, 0, 2000);
  ImVec4 grn(0.231f, 0.647f, 0.365f, 1.0f);
  ImVec4 grn_h(0.282f, 0.729f, 0.427f, 1.0f);
  ImVec4 grn_a(0.180f, 0.541f, 0.306f, 1.0f);
  ImGui::PushStyleColor(ImGuiCol_Button, grn);
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, grn_h);
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, grn_a);
  if (ImGui::Button("Run")) run_tool(st, tool_idx);
  ImGui::PopStyleColor(3);
  ImGui::SameLine();
  ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.55f, 0.20f, 0.18f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.90f, 0.33f, 0.29f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.45f, 0.16f, 0.14f, 1.0f));
  if (ImGui::Button("Stop")) stop_jobs(st);
  ImGui::PopStyleColor(3);
  if (std::string(tm.verb).empty()) {
    ImGui::SameLine();
    ImGui::TextDisabled("CLI verb pending. Scope check and queue work now.");
  }
  ImGui::Separator();
  ImGui::InputText("Search results", st.table_filter, sizeof(st.table_filter));
  ImGui::Separator();
}

static void welcome_page(AppState& st) {
  push_bold();
  ImGui::Text("Workspace");
  pop_font(ClopsFonts::ui_bold ? ClopsFonts::ui_bold : ClopsFonts::ui);
  ImGui::Separator();
  ImGui::Text("No tool open yet.");
  ImGui::TextDisabled("Pick a tool on the left or press Cmd+K. Each tool opens its own tab here.");
  ImGui::Spacing();
  ImGui::Text("Try the local lab:");
  ImGui::BulletText("T03 Port Scanner on 127.0.0.1, ports 1-1000, profile Lab");
  ImGui::BulletText("T07 Directory Bruteforcer on http://127.0.0.1:18080");
  ImGui::BulletText("T19 Codec Lab, op b64encode, any text");
  (void)st;
}

void panels_draw_center(AppState& st) {
  ImGuiViewport* vp = ImGui::GetMainViewport();
  float W = vp->WorkSize.x > 0 ? vp->WorkSize.x : 1400;
  float H = vp->WorkSize.y > 0 ? vp->WorkSize.y : 900;
  float navw = W * 0.18f < 230 ? 230 : (W * 0.18f > 300 ? 300 : W * 0.18f);
  float inspw = W * 0.22f < 280 ? 280 : (W * 0.22f > 360 ? 360 : W * 0.22f);
  float drawh = H * 0.26f < 200 ? 200 : (H * 0.26f > 280 ? 280 : H * 0.26f);
  ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + navw, vp->WorkPos.y + 40), ImGuiCond_FirstUseEver);
  ImGui::SetNextWindowSize(ImVec2(W - navw - inspw, H - drawh - 40), ImGuiCond_FirstUseEver);
  ImGui::Begin("Workspace");
  if (st.pages.empty()) {
    welcome_page(st);
    ImGui::End();
    return;
  }
  if (st.active_tab < 0 || st.active_tab >= (int)st.pages.size()) st.active_tab = 0;
  if (ImGui::BeginTabBar("ToolTabs")) {
    for (size_t i = 0; i < st.pages.size();) {
      ToolPage& pg = st.pages[i];
      const ToolMeta& tm = kTools[pg.tool_idx];
      char label[128];
      std::snprintf(label, sizeof(label), "%s %s", tm.id, tm.name);
      bool open = true;
      ImGuiTabItemFlags flags = ((int)i == st.active_tab) ? ImGuiTabItemFlags_SetSelected : 0;
      if (ImGui::BeginTabItem(label, &open, flags)) {
        st.active_tab = (int)i;
        tool_form(st, tm, pg.tool_idx);
        metrics_strip(st, pg);
        ImGui::Separator();
        if (pg.tool_idx == 2) table_draw_ports(st, pg);
        else table_draw_findings(st, pg);
        ImGui::EndTabItem();
      }
      if (!open) {
        st.pages.erase(st.pages.begin() + i);
        if (st.active_tab >= (int)st.pages.size()) st.active_tab = (int)st.pages.size() - 1;
      } else {
        i++;
      }
    }
    ImGui::EndTabBar();
  }
  ImGui::End();
}

static void section_head(const char* t) {
  push_bold();
  ImGui::Text("%s", t);
  pop_font(ClopsFonts::ui_bold ? ClopsFonts::ui_bold : ClopsFonts::ui);
  ImGui::Separator();
}

void panels_draw_inspector(AppState& st) {
  ImGuiViewport* vp = ImGui::GetMainViewport();
  float W = vp->WorkSize.x > 0 ? vp->WorkSize.x : 1400;
  float H = vp->WorkSize.y > 0 ? vp->WorkSize.y : 900;
  float inspw = W * 0.22f < 280 ? 280 : (W * 0.22f > 360 ? 360 : W * 0.22f);
  float drawh = H * 0.26f < 200 ? 200 : (H * 0.26f > 280 ? 280 : H * 0.26f);
  ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + W - inspw, vp->WorkPos.y + 40), ImGuiCond_FirstUseEver);
  ImGui::SetNextWindowSize(ImVec2(inspw, H - drawh - 40), ImGuiCond_FirstUseEver);
  ImGui::Begin("Details");
  section_head("Inspector");
  std::lock_guard<std::mutex> lk(st.mu);
  if (st.active_tab < 0 || st.active_tab >= (int)st.pages.size()) {
    ImGui::Text("No selection");
    ImGui::TextDisabled("Select a result row to inspect details, evidence, and related actions.");
    ImGui::End();
    return;
  }
  ToolPage& pg = st.pages[st.active_tab];
  if (pg.tool_idx == 2) {
    if (pg.selected < 0 || pg.selected >= (int)pg.ports.size()) {
      ImGui::Text("No selection");
      ImGui::TextDisabled("Select a port row to inspect details, evidence, and related actions.");
      ImGui::End();
      return;
    }
    const PortRow& r = pg.ports[pg.selected];
    section_head("DETAILS");
    push_mono();
    ImGui::Text("Port: %d", r.port);
    ImGui::Text("Proto: %s", r.proto.c_str());
    ImGui::Text("State: %s", r.state.c_str());
    ImGui::Text("Service: %s", r.service.c_str());
    ImGui::Text("Version: %s", r.version.c_str());
    ImGui::Text("Latency: %ld ms", r.latency_ms);
    pop_font(ClopsFonts::mono);
    section_head("EVIDENCE");
    push_mono();
    ImGui::TextWrapped("Banner: %s", r.banner.c_str());
    pop_font(ClopsFonts::mono);
    section_head("ACTIONS");
    if (ImGui::Button("Send to TLS Analyzer")) {
      std::snprintf(st.target, sizeof(st.target), "%s", pg.target.c_str());
      std::snprintf(st.extra, sizeof(st.extra), "%d", r.port);
      open_page(st, 3);
    }
    if (ImGui::Button("Send to HTTP Fingerprint")) {
      std::string scheme = (r.port == 443 || r.port == 8443) ? "https" : "http";
      std::snprintf(st.target, sizeof(st.target), "%s://%s:%d", scheme.c_str(), pg.target.c_str(), r.port);
      open_page(st, 4);
    }
    if (ImGui::Button("Send to CVE Mapper")) {
      std::snprintf(st.target, sizeof(st.target), "%s", r.service.c_str());
      std::snprintf(st.extra, sizeof(st.extra), "%s", r.version.c_str());
      open_page(st, 16);
      push_toast(st, "T17 runs via core API");
    }
    if (ImGui::Button("Copy banner")) ImGui::SetClipboardText(r.banner.c_str());
  } else {
    if (pg.selected < 0 || pg.selected >= (int)pg.findings.size()) {
      ImGui::Text("No selection");
      ImGui::TextDisabled("Select a finding row to inspect details, evidence, and related actions.");
      ImGui::End();
      return;
    }
    const FindingRow& f = pg.findings[pg.selected];
    section_head("DETAILS");
    if (f.severity == "High" || f.severity == "Critical") badge(f.severity.c_str(), ImVec4(0.90f, 0.33f, 0.29f, 1.0f));
    else if (f.severity == "Medium") badge(f.severity.c_str(), ImVec4(0.82f, 0.60f, 0.13f, 1.0f));
    else if (f.severity == "Low") badge(f.severity.c_str(), ImVec4(0.25f, 0.73f, 0.44f, 1.0f));
    else badge(f.severity.c_str(), ImVec4(0.42f, 0.46f, 0.51f, 1.0f));
    push_mono();
    ImGui::TextWrapped("%s", f.title.c_str());
    pop_font(ClopsFonts::mono);
    section_head("EVIDENCE");
    push_mono();
    ImGui::TextWrapped("%s", f.detail.c_str());
    pop_font(ClopsFonts::mono);
    section_head("ACTIONS");
    if (ImGui::Button("Copy detail")) ImGui::SetClipboardText(f.detail.c_str());
    if (ImGui::Button("Mark False Positive")) {
      pg.findings.erase(pg.findings.begin() + pg.selected);
      pg.selected = -1;
      push_audit(st, "Marked false positive");
      push_toast(st, "Marked false positive");
    }
  }
  ImGui::End();
}

static void jobs_tab(AppState& st) {
  if (ImGui::BeginTable("jobs", 6, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY)) {
    ImGui::TableSetupColumn("ID");
    ImGui::TableSetupColumn("Tool");
    ImGui::TableSetupColumn("Target");
    ImGui::TableSetupColumn("Status");
    ImGui::TableSetupColumn("Rows");
    ImGui::TableSetupColumn("Elapsed");
    ImGui::TableHeadersRow();
    for (size_t i = 0; i < st.jobs.size(); i++) {
      Job& j = st.jobs[i];
      ImGui::TableNextRow();
      ImGui::TableNextColumn();
      char idb[16];
      std::snprintf(idb, sizeof(idb), "#%03d", j.id);
      if (ImGui::Selectable(idb, false, ImGuiSelectableFlags_SpanAllColumns)) {
        int ti = -1;
        if (j.tool.size() == 3 && j.tool[0] == 'T') ti = std::atoi(j.tool.c_str() + 1) - 1;
        if (ti >= 0 && ti < 25) {
          open_page(st, ti);
          st.bottom_tab = 3;
        }
      }
      ImGui::TableNextColumn();
      ImGui::Text("%s", j.tool.c_str());
      ImGui::TableNextColumn();
      push_mono();
      ImGui::Text("%s", j.target.c_str());
      pop_font(ClopsFonts::mono);
      ImGui::TableNextColumn();
      if (j.status == "Running") badge("Running", ImVec4(0.31f, 0.63f, 1.0f, 1.0f));
      else if (j.status == "Done") badge("Done", ImVec4(0.25f, 0.73f, 0.44f, 1.0f));
      else if (j.status == "Failed") badge("Failed", ImVec4(0.90f, 0.33f, 0.29f, 1.0f));
      else if (j.status == "Paused") badge("Paused", ImVec4(0.82f, 0.60f, 0.13f, 1.0f));
      else badge(j.status.c_str(), ImVec4(0.42f, 0.46f, 0.51f, 1.0f));
      ImGui::TableNextColumn();
      ImGui::Text("%d", j.rows);
      ImGui::TableNextColumn();
      ImGui::Text("%s", mmss(now_ms() - j.started_ms).c_str());
    }
    ImGui::EndTable();
  }
}

static void logs_tab(AppState& st) {
  ImGui::InputText("Filter logs", st.log_filter, sizeof(st.log_filter));
  push_mono();
  std::string lf = st.log_filter;
  for (auto& c : lf) c = (char)std::tolower(c);
  size_t shown = 0;
  for (size_t i = st.logs.size(); i > 0 && shown < 100; i--) {
    const std::string& l = st.logs[i - 1];
    if (!lf.empty()) {
      std::string low = l;
      for (auto& c : low) c = (char)std::tolower(c);
      if (low.find(lf) == std::string::npos) continue;
    }
    if (l.find("WARN") != std::string::npos) badge("WARN", ImVec4(0.82f, 0.60f, 0.13f, 1.0f));
    else if (l.find("ERROR") != std::string::npos || l.find("DENY") != std::string::npos)
      badge("ERR", ImVec4(0.90f, 0.33f, 0.29f, 1.0f));
    else badge("INF", ImVec4(0.42f, 0.46f, 0.51f, 1.0f));
    ImGui::SameLine();
    ImGui::Text("%s", l.c_str());
    shown++;
  }
  pop_font(ClopsFonts::mono);
}

static void audit_tab(AppState& st) {
  ImGui::TextDisabled("Security events. Cannot be disabled. Newest first.");
  ImGui::Separator();
  push_mono();
  size_t shown = 0;
  for (size_t i = st.audit.size(); i > 0 && shown < 100; i--) {
    ImGui::BulletText("%s", st.audit[i - 1].c_str());
    shown++;
  }
  if (st.audit.empty()) ImGui::TextDisabled("No audit events yet.");
  pop_font(ClopsFonts::mono);
}

static void output_tab(AppState& st) {
  if (st.active_tab < 0 || st.active_tab >= (int)st.pages.size()) {
    ImGui::TextDisabled("Open a tool tab to see raw output.");
    return;
  }
  ToolPage& pg = st.pages[st.active_tab];
  if (ImGui::Button("Copy all")) {
    std::string all;
    for (auto& l : pg.raw) {
      all += l;
      all += '\n';
    }
    ImGui::SetClipboardText(all.c_str());
  }
  ImGui::SameLine();
  if (ImGui::Button("Clear View")) pg.raw.clear();
  ImGui::Separator();
  push_mono();
  size_t from = pg.raw.size() > 200 ? pg.raw.size() - 200 : 0;
  for (size_t i = from; i < pg.raw.size(); i++) {
    ImGui::TextWrapped("%s", pg.raw[i].c_str());
  }
  if (pg.raw.empty()) ImGui::TextDisabled("No raw output yet. Press Run.");
  pop_font(ClopsFonts::mono);
}

void panels_draw_bottom(AppState& st) {
  ImGuiViewport* vp = ImGui::GetMainViewport();
  float W = vp->WorkSize.x > 0 ? vp->WorkSize.x : 1400;
  float H = vp->WorkSize.y > 0 ? vp->WorkSize.y : 900;
  float drawh = H * 0.26f < 200 ? 200 : (H * 0.26f > 280 ? 280 : H * 0.26f);
  ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, vp->WorkPos.y + H - drawh), ImGuiCond_FirstUseEver);
  ImGui::SetNextWindowSize(ImVec2(W, drawh), ImGuiCond_FirstUseEver);
  ImGui::Begin("Jobs / Logs / Audit");
  std::lock_guard<std::mutex> lk(st.mu);
  const char* tabs[] = {"Jobs", "Logs", "Audit", "Output"};
  for (int i = 0; i < 4; i++) {
    if (i > 0) ImGui::SameLine();
    bool sel = st.bottom_tab == i;
    if (sel) {
      ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.12f, 0.17f, 0.22f, 1.0f));
      ImGui::Button(tabs[i]);
      ImGui::PopStyleColor();
    } else if (ImGui::Button(tabs[i])) {
      st.bottom_tab = i;
    }
  }
  ImGui::Separator();
  if (st.bottom_tab == 0) jobs_tab(st);
  else if (st.bottom_tab == 1) logs_tab(st);
  else if (st.bottom_tab == 2) audit_tab(st);
  else output_tab(st);
  ImGui::End();
}

struct PalEntry {
  bool is_tool;
  int idx;
  std::string label;
};

void panels_draw_palette(AppState& st) {
  if (!st.palette_open) return;
  ImGuiViewport* vp = ImGui::GetMainViewport();
  ImVec2 center(vp->WorkPos.x + vp->WorkSize.x * 0.5f, vp->WorkPos.y + 110.0f);
  ImGui::SetNextWindowPos(ImVec2(center.x - 360, center.y), ImGuiCond_Always);
  ImGui::SetNextWindowSize(ImVec2(720, 480), ImGuiCond_FirstUseEver);
  ImGui::Begin("Command palette", &st.palette_open,
    ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoDocking);
  if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere(0);
  ImGui::InputText("Search commands", st.palette_filter, sizeof(st.palette_filter));
  ImGui::Separator();
  std::string f = st.palette_filter;
  for (auto& c : f) c = (char)std::tolower(c);
  std::vector<PalEntry> items;
  for (int i = 0; i < 25; i++) {
    std::string hay = std::string(kTools[i].id) + " " + kTools[i].name + " " + kTools[i].group + " " + kTools[i].desc;
    std::string low = hay;
    for (auto& c : low) c = (char)std::tolower(c);
    if (!f.empty() && low.find(f) == std::string::npos) continue;
    char label[160];
    std::snprintf(label, sizeof(label), "%s  %s   [%s]", kTools[i].id, kTools[i].name, kTools[i].group);
    items.push_back({true, i, label});
  }
  const char* acts[][2] = {
    {"run", "Run Active Tool   Ctrl+Enter"},
    {"stop", "Stop Running Jobs   Ctrl+."},
    {"settings", "Open Settings"},
    {"export", "Export Results to Clipboard"},
    {"clear", "Clear Finished Jobs"},
  };
  for (size_t ai = 0; ai < 5; ai++) {
    std::string low = acts[ai][1];
    for (auto& c : low) c = (char)std::tolower(c);
    if (!f.empty() && low.find(f) == std::string::npos && std::string(acts[ai][0]).find(f) == std::string::npos)
      continue;
    items.push_back({false, 100 + (int)ai, acts[ai][1]});
  }
  if (st.palette_idx < 0) st.palette_idx = 0;
  if (st.palette_idx >= (int)items.size()) st.palette_idx = (int)items.size() - 1;
  if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) st.palette_idx++;
  if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) st.palette_idx--;
  if (st.palette_idx < 0) st.palette_idx = 0;
  if (!items.empty() && st.palette_idx >= (int)items.size()) st.palette_idx = (int)items.size() - 1;
  bool activate = ImGui::IsKeyPressed(ImGuiKey_Enter);
  static std::string last_f;
  if (last_f != f) {
    st.palette_idx = 0;
    last_f = f;
  }
  push_bold();
  ImGui::Text("Navigation");
  pop_font(ClopsFonts::ui_bold ? ClopsFonts::ui_bold : ClopsFonts::ui);
  int shown = 0;
  for (size_t i = 0; i < items.size() && shown < 30; i++) {
    if (!items[i].is_tool) continue;
    bool sel = ((int)i == st.palette_idx);
    if (ImGui::Selectable(items[i].label.c_str(), sel)) {
      st.active = items[i].idx;
      open_page(st, items[i].idx);
      st.palette_open = false;
      st.palette_filter[0] = 0;
    }
    if (sel && activate) {
      st.active = items[i].idx;
      open_page(st, items[i].idx);
      st.palette_open = false;
      st.palette_filter[0] = 0;
      activate = false;
    }
    shown++;
  }
  push_bold();
  ImGui::Text("Actions");
  pop_font(ClopsFonts::ui_bold ? ClopsFonts::ui_bold : ClopsFonts::ui);
  for (size_t i = 0; i < items.size(); i++) {
    if (items[i].is_tool) continue;
    bool sel = ((int)i == st.palette_idx);
    bool clicked = ImGui::Selectable(items[i].label.c_str(), sel);
    if ((clicked || (sel && activate))) {
      int act = items[i].idx - 100;
      if (act == 0 && st.active_tab >= 0 && st.active_tab < (int)st.pages.size())
        run_tool(st, st.pages[st.active_tab].tool_idx);
      else if (act == 1) stop_jobs(st);
      else if (act == 2) st.show_settings = true;
      else if (act == 3) {
        if (st.active_tab >= 0 && st.active_tab < (int)st.pages.size()) {
          ToolPage& pg = st.pages[st.active_tab];
          std::string all;
          for (auto& l : pg.raw) {
            all += l;
            all += '\n';
          }
          ImGui::SetClipboardText(all.c_str());
          push_toast(st, "Results copied");
          push_audit(st, "Exported results to clipboard");
        }
      } else if (act == 4) {
        for (size_t k = 0; k < st.jobs.size();) {
          if (st.jobs[k].status == "Done" || st.jobs[k].status == "Cancelled" || st.jobs[k].status == "Failed")
            st.jobs.erase(st.jobs.begin() + k);
          else k++;
        }
      }
      st.palette_open = false;
      st.palette_filter[0] = 0;
      activate = false;
    }
  }
  if (!st.recent.empty()) {
    push_bold();
    ImGui::Text("Recent");
    pop_font(ClopsFonts::ui_bold ? ClopsFonts::ui_bold : ClopsFonts::ui);
    for (int ri : st.recent) {
      char label[128];
      std::snprintf(label, sizeof(label), "%s  %s", kTools[ri].id, kTools[ri].name);
      if (ImGui::Selectable(label)) {
        st.active = ri;
        open_page(st, ri);
        st.palette_open = false;
        st.palette_filter[0] = 0;
      }
    }
  }
  ImGui::End();
}

static void toasts_overlay(AppState& st) {
  ImGuiViewport* vp = ImGui::GetMainViewport();
  long now = now_ms();
  int slot = 0;
  for (size_t i = 0; i < st.toasts.size();) {
    if (st.toasts[i].until_ms <= now) {
      st.toasts.erase(st.toasts.begin() + i);
      continue;
    }
    ImVec2 pos(vp->WorkPos.x + vp->WorkSize.x - 330, vp->WorkPos.y + vp->WorkSize.y - 90 - slot * 44);
    ImGui::SetNextWindowPos(pos, ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(310, 36), ImGuiCond_Always);
    char name[32];
    std::snprintf(name, sizeof(name), "##toast%d", (int)i);
    ImGui::Begin(name, nullptr,
      ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_AlwaysAutoResize |
        ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoFocusOnAppearing);
    ImGui::Text("%s", st.toasts[i].text.c_str());
    ImGui::End();
    slot++;
    i++;
  }
}

static void scope_dialog(AppState& st) {
  if (!st.show_scope_dialog) return;
  ImGui::OpenPopup("Execution blocked");
  if (ImGui::BeginPopupModal("Execution blocked", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::Text("Target outside scope.");
    ImGui::TextDisabled("This job was blocked before network activity.");
    ImGui::TextDisabled("Add the target to Project Scope first. Scope is fixed to lab-only in this build:");
    push_mono();
    ImGui::Text("%s", st.scope_dialog_target.c_str());
    pop_font(ClopsFonts::mono);
    ImGui::Separator();
    if (ImGui::Button("Understood")) st.show_scope_dialog = false;
    ImGui::EndPopup();
  }
}

static void settings_window(AppState& st) {
  if (!st.show_settings) return;
  ImGui::SetNextWindowSize(ImVec2(460, 340), ImGuiCond_FirstUseEver);
  if (!ImGui::Begin("Settings", &st.show_settings)) {
    ImGui::End();
    return;
  }
  section_head("SAFETY");
  ImGui::Checkbox("Safe Mode", &st.safe_mode);
  ImGui::TextDisabled("Scope guard stays enforced even with Safe Mode off.");
  ImGui::Separator();
  section_head("SCOPE");
  ImGui::Text("Scope: lab-only (fixed in this build)");
  push_mono();
  ImGui::TextDisabled("localhost, example.com, 127.0.0.0/8");
  pop_font(ClopsFonts::mono);
  ImGui::Separator();
  section_head("ACCELERATION");
  ImGui::TextDisabled("%s", st.accel_text.c_str());
  ImGui::TextDisabled("GPU missing is reported honestly, never faked.");
  ImGui::Separator();
  section_head("SHORTCUTS");
  push_mono();
  ImGui::TextDisabled("Ctrl+K palette   Ctrl+Enter run   Ctrl+. stop   Esc close");
  pop_font(ClopsFonts::mono);
  if (ImGui::Button("Close")) st.show_settings = false;
  ImGui::End();
}

void panels_draw_overlays(AppState& st) {
  toasts_overlay(st);
  scope_dialog(st);
  settings_window(st);
}

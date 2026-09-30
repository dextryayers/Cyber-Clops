#include "gui.h"
#include "imgui.h"
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

// Scope mirror of Rust Scope::lab_only. UI rejects before any job starts.
bool scope_allowed(const std::string& target) {
  std::string t = target;
  // strip scheme and path
  for (const char* p : {"http://", "https://"}) {
    if (t.rfind(p, 0) == 0) t = t.substr(std::strlen(p));
  }
  auto slash = t.find('/');
  if (slash != std::string::npos) t = t.substr(0, slash);
  auto colon = t.find(':');
  std::string host = (colon == std::string::npos) ? t : t.substr(0, colon);
  for (auto& c : host) c = (char)std::tolower(c);
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

static long now_ms() {
  using namespace std::chrono;
  return (long)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
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

void run_tool(AppState& st, int tool_idx) {
  const ToolMeta& tm = kTools[tool_idx];
  std::string target;
  std::string extra;
  {
    std::lock_guard<std::mutex> lk(st.mu);
    target = st.target;
    extra = st.extra;
  }
  if (!scope_allowed(target) && std::string(tm.verb) != std::string("codec")) {
    std::lock_guard<std::mutex> lk(st.mu);
    st.logs.push_back(std::string("Denied: target outside scope: ") + target);
    return;
  }
  int jid;
  {
    std::lock_guard<std::mutex> lk(st.mu);
    jid = st.next_job++;
    st.jobs.push_back({jid, tm.id, target, "Running", now_ms()});
    st.logs.push_back(std::string("Job ") + std::to_string(jid) + " started: " + tm.id + " on " + target);
  }
  if (std::string(tm.verb).empty()) {
    std::lock_guard<std::mutex> lk(st.mu);
    st.logs.push_back(std::string("Job ") + std::to_string(jid) + " queued. Engine runs via core API. CLI verb lands next.");
    for (auto& j : st.jobs) {
      if (j.id == jid) j.status = "Queued";
    }
    return;
  }
  // Wired tools spawn clops-job and stream JSONL rows live.
  std::string cmd;
  std::string verb = tm.verb;
  if (verb == "resolve") {
    cmd = std::string("clops-job resolve --host ") + shell_escape(target);
  } else if (verb == "scan") {
    cmd = std::string("clops-job scan --host ") + shell_escape(target) + " --ports " + shell_escape(extra) +
      " --timeout 2000 --concurrency 100";
  } else if (verb == "tls") {
    cmd = std::string("clops-job tls --host ") + shell_escape(target) + " --port " + shell_escape(extra);
  } else if (verb == "fetch") {
    cmd = std::string("clops-job fetch --url ") + shell_escape(target);
  } else if (verb == "dirbrute") {
    cmd = std::string("clops-job dirbrute --base ") + shell_escape(target) + " --wordlist " + shell_escape(extra);
  } else if (verb == "codec") {
    cmd = std::string("clops-job codec --op ") + shell_escape(extra) + " --input " + shell_escape(target);
  } else if (verb == "crack-dict") {
    cmd = std::string("clops-job crack-dict ") + shell_escape(extra);
  } else {
    cmd = "";
  }
  std::thread([cmd, jid, verb, &st]() {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
      std::lock_guard<std::mutex> lk(st.mu);
      st.logs.push_back(std::string("Job ") + std::to_string(jid) + " failed to spawn. Is clops-job on PATH?");
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
        if (line.empty() || line[0] != '{') continue;
        std::lock_guard<std::mutex> lk(st.mu);
        if (verb == "scan") {
          PortRow r;
          r.port = find_int(line, "\"port\":", 0);
          r.state = find_bool(line, "\"open\":") ? "open" : "closed";
          r.service = find_str(line, "\"service\":\"");
          r.version = find_str(line, "\"version\":\"");
          r.banner = find_str(line, "\"banner\":\"");
          if (r.state == "open") {
            st.rows.push_back(r);
            rows++;
          }
        } else {
          st.logs.push_back(line.size() > 300 ? line.substr(0, 300) : line);
          rows++;
        }
      }
    }
    int rc = pclose(pipe);
    std::lock_guard<std::mutex> lk(st.mu);
    for (auto& j : st.jobs) {
      if (j.id == jid) j.status = (rc == 0 && !st.cancel_flag.load()) ? "Done" : "Cancelled";
    }
    st.logs.push_back(std::string("Job ") + std::to_string(jid) + " finished: " + std::to_string(rows) + " rows");
  }).detach();
}

void stop_jobs(AppState& st) {
  st.cancel_flag.store(true);
  std::lock_guard<std::mutex> lk(st.mu);
  for (auto& j : st.jobs) {
    if (j.status == "Running") j.status = "Cancelled";
  }
  st.logs.push_back("Stop pressed. Running jobs cancelled.");
  st.cancel_flag.store(false);
}

void panels_draw_topbar(AppState& st) {
  ImGui::BeginMainMenuBar();
  ImGui::Text("Cyber-Clops");
  ImGui::Separator();
  ImGui::Text("Scope: lab-only");
  ImGui::Separator();
  ImGui::Text(st.safe_mode ? "Safe Mode: ON" : "Safe Mode: OFF");
  ImGui::Separator();
  ImGui::Text("%s", st.accel_text.c_str());
  ImGui::Separator();
  int running = 0;
  for (auto& j : st.jobs) {
    if (j.status == "Running") running++;
  }
  ImGui::Text("Jobs: %d", running);
  ImGui::Separator();
  if (ImGui::Button("Cmd+K")) st.palette_open = true;
  ImGui::EndMainMenuBar();
}

void panels_draw_left_tree(AppState& st) {
  ImGui::Begin("Navigator");
  ImGui::Text("Targets");
  ImGui::Separator();
  for (auto g : kGroups) {
    if (ImGui::TreeNode(g)) {
      for (int i = 0; i < 25; i++) {
        if (std::string(kTools[i].group) != g) continue;
        char label[96];
        std::snprintf(label, sizeof(label), "%s %s", kTools[i].id, kTools[i].name);
        if (ImGui::Selectable(label, st.active == i)) st.active = i;
      }
      ImGui::TreePop();
    }
  }
  ImGui::End();
}

void panels_draw_center(AppState& st) {
  const ToolMeta& tm = kTools[st.active];
  ImGui::Begin("Workspace");
  ImGui::Text("%s %s", tm.id, tm.name);
  ImGui::SameLine();
  ImGui::TextDisabled("%s", tm.desc);
  ImGui::Separator();
  ImGui::InputText("Target", st.target, sizeof(st.target));
  ImGui::InputText(tm.extra_label, st.extra, sizeof(st.extra));
  const char* profiles[] = {"Fast", "Balanced", "Deep", "Lab"};
  ImGui::Combo("Profile", &st.profile, profiles, 4);
  if (ImGui::Button("Run")) run_tool(st, st.active);
  ImGui::SameLine();
  if (ImGui::Button("Stop")) stop_jobs(st);
  if (std::string(tm.verb).empty()) {
    ImGui::SameLine();
    ImGui::TextDisabled("CLI verb pending. Scope check and queue work now.");
  }
  ImGui::Separator();
  table_draw_ports(st);
  ImGui::End();
}

void panels_draw_inspector(AppState& st) {
  ImGui::Begin("Details");
  std::lock_guard<std::mutex> lk(st.mu);
  if (st.selected < 0 || st.selected >= (int)st.rows.size()) {
    ImGui::Text("No row selected.");
    ImGui::Text("Tip: run T03 on 127.0.0.1, ports 1-1000, profile Lab.");
  } else {
    const PortRow& r = st.rows[st.selected];
    ImGui::Text("Port: %d", r.port);
    ImGui::Text("State: %s", r.state.c_str());
    ImGui::Text("Service: %s", r.service.c_str());
    ImGui::Text("Version: %s", r.version.c_str());
    ImGui::Text("Banner: %s", r.banner.c_str());
  }
  ImGui::End();
}

void panels_draw_bottom(AppState& st) {
  ImGui::Begin("Jobs / Logs / Audit");
  std::lock_guard<std::mutex> lk(st.mu);
  for (auto& j : st.jobs) {
    ImGui::BulletText("Job %d %s %s [%s]", j.id, j.tool.c_str(), j.target.c_str(), j.status.c_str());
  }
  ImGui::Separator();
  size_t from = st.logs.size() > 30 ? st.logs.size() - 30 : 0;
  for (size_t i = from; i < st.logs.size(); i++) {
    ImGui::BulletText("%s", st.logs[i].c_str());
  }
  ImGui::End();
}

void panels_draw_palette(AppState& st) {
  if (!st.palette_open) return;
  ImGui::Begin("Command palette", &st.palette_open);
  ImGui::InputText("Filter", st.palette_filter, sizeof(st.palette_filter));
  std::string f = st.palette_filter;
  for (auto& c : f) c = (char)std::tolower(c);
  for (int i = 0; i < 25; i++) {
    std::string hay = std::string(kTools[i].id) + " " + kTools[i].name;
    std::string low = hay;
    for (auto& c : low) c = (char)std::tolower(c);
    if (!f.empty() && low.find(f) == std::string::npos) continue;
    if (ImGui::Selectable(hay.c_str())) {
      st.active = i;
      st.palette_open = false;
    }
  }
  ImGui::End();
}

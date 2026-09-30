#include "gui.h"
#include "imgui.h"

static const char* kTools[] = {
  "T01 Subdomain", "T03 Port Scan", "T04 SSL", "T07 Dir Brute",
  "T14 Repeater", "T20 Cracker", "T25 Report"
};

void panels_draw_topbar(const AccelBadge& accel, int jobs_running) {
  ImGui::BeginMainMenuBar();
  ImGui::Text("Cyber-Clops");
  ImGui::Separator();
  ImGui::Text("Project: demo.clops");
  ImGui::Separator();
  ImGui::Text("Scope: lab-only");
  ImGui::Separator();
  ImGui::Text("Safe Mode: ON");
  ImGui::Separator();
  ImGui::Text("CPU: %s", accel.cpu.c_str());
  ImGui::Text("GPU: %s", accel.cuda ? "CUDA" : "None, CPU only");
  ImGui::Text("Backend: %s", accel.backend.c_str());
  ImGui::Separator();
  ImGui::Text("Jobs: %d", jobs_running);
  ImGui::Separator();
  if (ImGui::Button("Cmd+K")) {}
  ImGui::EndMainMenuBar();
}

void panels_draw_left_tree(int& active_tool) {
  ImGui::Begin("Navigator");
  ImGui::Text("Targets");
  ImGui::Separator();
  const char* groups[] = {"Recon", "Web", "Network", "Crack", "Intel", "Report"};
  for (auto g : groups) {
    if (ImGui::TreeNode(g)) {
      for (int i = 0; i < 7; i++) {
        bool sel = (active_tool == i);
        if (ImGui::Selectable(kTools[i], sel)) active_tool = i;
      }
      ImGui::TreePop();
    }
  }
  ImGui::End();
}

void panels_draw_center(int active_tool, std::vector<PortRow>& rows, char* target_buf, int& profile) {
  ImGui::Begin("Workspace");
  ImGui::Text("%s", kTools[active_tool]);
  ImGui::SameLine();
  ImGui::TextDisabled("Run with scope guard. Stop cancels in under 500 ms.");
  ImGui::Separator();
  ImGui::InputText("Target", target_buf, 256);
  const char* profiles[] = {"Fast", "Balanced", "Deep", "Lab"};
  ImGui::Combo("Profile", &profile, profiles, 4);
  if (ImGui::Button("Run")) {
    rows.push_back({80, "open", "http", "", "ClopsLab/0.1"});
  }
  ImGui::SameLine();
  if (ImGui::Button("Stop")) {}
  ImGui::Separator();
  int sel = -1;
  table_draw_ports(rows, sel);
  ImGui::End();
}

void panels_draw_inspector(const PortRow* selected) {
  ImGui::Begin("Details");
  if (!selected) {
    ImGui::Text("No row selected.");
    ImGui::Text("Tip: run T03 on 127.0.0.1 profile Lab.");
  } else {
    ImGui::Text("Port: %d", selected->port);
    ImGui::Text("State: %s", selected->state.c_str());
    ImGui::Text("Service: %s", selected->service.c_str());
    ImGui::Text("Banner: %s", selected->banner.c_str());
  }
  ImGui::End();
}

void panels_draw_bottom(const std::vector<std::string>& logs) {
  ImGui::Begin("Jobs / Logs / Audit");
  for (auto& l : logs) ImGui::BulletText("%s", l.c_str());
  ImGui::End();
}

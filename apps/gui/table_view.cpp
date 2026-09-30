#include "gui.h"
#include "imgui.h"
#include <cctype>
#include <cstdio>

static void sev_color(const std::string& sev) {
  if (sev == "High" || sev == "Critical") ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.90f, 0.33f, 0.29f, 1.0f));
  else if (sev == "Medium") ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.82f, 0.60f, 0.13f, 1.0f));
  else if (sev == "Low") ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.25f, 0.73f, 0.44f, 1.0f));
  else ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.65f, 0.69f, 0.74f, 1.0f));
}

static bool row_match(const std::string& hay, const std::string& needle) {
  if (needle.empty()) return true;
  std::string h = hay;
  for (auto& c : h) c = (char)std::tolower(c);
  return h.find(needle) != std::string::npos;
}

void table_draw_ports(AppState& st, ToolPage& page) {
  if (page.ports.empty()) {
    ImGui::Text("No results yet.");
    ImGui::TextDisabled("Enter a target in scope and press Run. Try the local lab: 127.0.0.1, ports 1-1000, profile Lab.");
    return;
  }
  ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY |
    ImGuiTableFlags_Sortable | ImGuiTableFlags_Resizable;
  char title[64];
  std::snprintf(title, sizeof(title), "Open ports (%d)", (int)page.ports.size());
  std::string flt = st.table_filter;
  for (auto& c : flt) c = (char)std::tolower(c);
  if (ClopsFonts::mono) ImGui::PushFont((ImFont*)ClopsFonts::mono);
  if (ImGui::BeginTable(title, 7, flags)) {
    ImGui::TableSetupColumn("Port");
    ImGui::TableSetupColumn("Proto");
    ImGui::TableSetupColumn("State");
    ImGui::TableSetupColumn("Service");
    ImGui::TableSetupColumn("Version");
    ImGui::TableSetupColumn("Banner");
    ImGui::TableSetupColumn("Latency");
    ImGui::TableHeadersRow();
    ImGuiListClipper clipper;
    clipper.Begin((int)page.ports.size());
    while (clipper.Step()) {
      for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
        const PortRow& r = page.ports[i];
        char joined[512];
        std::snprintf(joined, sizeof(joined), "%d %s %s %s %s", r.port, r.service.c_str(),
          r.version.c_str(), r.banner.c_str(), r.state.c_str());
        if (!row_match(joined, flt)) continue;
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        bool sel = (page.selected == i);
        char label[32];
        std::snprintf(label, sizeof(label), "%d", r.port);
        if (ImGui::Selectable(label, sel, ImGuiSelectableFlags_SpanAllColumns)) {
          page.selected = i;
          st.selected = i;
        }
        ImGui::TableNextColumn();
        ImGui::Text("%s", r.proto.c_str());
        ImGui::TableNextColumn();
        sev_color("Low");
        ImGui::Text("%s", r.state.c_str());
        ImGui::PopStyleColor();
        ImGui::TableNextColumn();
        ImGui::Text("%s", r.service.c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%s", r.version.c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%s", r.banner.c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%ld ms", r.latency_ms);
      }
    }
    ImGui::EndTable();
  }
  if (ClopsFonts::mono) ImGui::PopFont();
}

void table_draw_findings(AppState& st, ToolPage& page) {
  if (page.findings.empty()) {
    ImGui::Text("No results yet.");
    ImGui::TextDisabled("Enter a target in scope and press Run.");
    return;
  }
  ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY |
    ImGuiTableFlags_Sortable | ImGuiTableFlags_Resizable;
  char title[64];
  std::snprintf(title, sizeof(title), "Findings (%d)", (int)page.findings.size());
  std::string flt = st.table_filter;
  for (auto& c : flt) c = (char)std::tolower(c);
  if (ImGui::BeginTable(title, 3, flags)) {
    ImGui::TableSetupColumn("Severity");
    ImGui::TableSetupColumn("Title");
    ImGui::TableSetupColumn("Detail");
    ImGui::TableHeadersRow();
    ImGuiListClipper clipper;
    clipper.Begin((int)page.findings.size());
    while (clipper.Step()) {
      for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
        const FindingRow& f = page.findings[i];
        if (!row_match(f.severity + " " + f.title + " " + f.detail, flt)) continue;
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        bool sel = (page.selected == i);
        sev_color(f.severity);
        if (ImGui::Selectable(f.severity.c_str(), sel, ImGuiSelectableFlags_SpanAllColumns)) {
          page.selected = i;
          st.selected = i;
        }
        ImGui::PopStyleColor();
        ImGui::TableNextColumn();
        if (ClopsFonts::mono) ImGui::PushFont((ImFont*)ClopsFonts::mono);
        ImGui::Text("%s", f.title.c_str());
        if (ClopsFonts::mono) ImGui::PopFont();
        ImGui::TableNextColumn();
        std::string short_d = f.detail.size() > 120 ? f.detail.substr(0, 120) : f.detail;
        ImGui::TextDisabled("%s", short_d.c_str());
      }
    }
    ImGui::EndTable();
  }
}

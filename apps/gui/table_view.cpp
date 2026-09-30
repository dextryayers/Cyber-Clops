#include "gui.h"
#include "imgui.h"
#include <cstdio>

void table_draw_ports(AppState& st) {
  ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY |
    ImGuiTableFlags_Sortable | ImGuiTableFlags_Resizable;
  std::lock_guard<std::mutex> lk(st.mu);
  char title[64];
  std::snprintf(title, sizeof(title), "Results (%d rows)", (int)st.rows.size());
  if (ImGui::BeginTable("results", 5, flags)) {
    ImGui::TableSetupColumn("Port");
    ImGui::TableSetupColumn("State");
    ImGui::TableSetupColumn("Service");
    ImGui::TableSetupColumn("Version");
    ImGui::TableSetupColumn("Banner");
    ImGui::TableHeadersRow();
    ImGuiListClipper clipper;
    clipper.Begin((int)st.rows.size());
    while (clipper.Step()) {
      for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        bool sel = (st.selected == i);
        char label[32];
        std::snprintf(label, sizeof(label), "%d", st.rows[i].port);
        if (ImGui::Selectable(label, sel, ImGuiSelectableFlags_SpanAllColumns)) st.selected = i;
        ImGui::TableNextColumn();
        ImGui::Text("%s", st.rows[i].state.c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%s", st.rows[i].service.c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%s", st.rows[i].version.c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%s", st.rows[i].banner.c_str());
      }
    }
    ImGui::EndTable();
  }
  (void)title;
}

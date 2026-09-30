#include "gui.h"
#include "imgui.h"

void table_draw_ports(const std::vector<PortRow>& rows, int& selected) {
  ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders
    | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Sortable;
  if (ImGui::BeginTable("ports", 4, flags)) {
    ImGui::TableSetupColumn("Port");
    ImGui::TableSetupColumn("State");
    ImGui::TableSetupColumn("Service");
    ImGui::TableSetupColumn("Banner");
    ImGui::TableHeadersRow();
    ImGuiListClipper clipper;
    clipper.Begin((int)rows.size());
    while (clipper.Step()) {
      for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        bool sel = (selected == i);
        char label[32];
        snprintf(label, sizeof(label), "%d", rows[i].port);
        if (ImGui::Selectable(label, sel, ImGuiSelectableFlags_SpanAllColumns)) selected = i;
        ImGui::TableNextColumn();
        ImGui::Text("%s", rows[i].state.c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%s", rows[i].service.c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%s", rows[i].banner.c_str());
      }
    }
    ImGui::EndTable();
  }
}

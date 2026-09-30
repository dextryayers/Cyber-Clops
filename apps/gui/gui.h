#pragma once
// Cyber-Clops GUI shell. English only. No emdash in strings.
#include <string>
#include <vector>

struct PortRow {
  int port = 0;
  std::string state;
  std::string service;
  std::string version;
  std::string banner;
};

struct AccelBadge {
  std::string cpu;
  std::string backend;
  bool cuda = false;
  long md5_hs = 0;
};

void panels_draw_topbar(const AccelBadge& accel, int jobs_running);
void panels_draw_left_tree(int& active_tool);
void panels_draw_center(int active_tool, std::vector<PortRow>& rows, char* target_buf, int& profile);
void panels_draw_inspector(const PortRow* selected);
void panels_draw_bottom(const std::vector<std::string>& logs);
void table_draw_ports(const std::vector<PortRow>& rows, int& selected);

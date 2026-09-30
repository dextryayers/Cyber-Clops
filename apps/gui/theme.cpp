// Cyber-Clops ops console theme. Exact SKILL design tokens.
// BG_0 foundation, BG_1 panes, BG_2 elevated, LINE_0 borders.
// No gradients, no glow.
#include "imgui.h"

void apply_ops_theme() {
  ImGuiStyle& s = ImGui::GetStyle();
  s.WindowRounding = 6.0f;
  s.ChildRounding = 6.0f;
  s.FrameRounding = 4.0f;
  s.GrabRounding = 4.0f;
  s.TabRounding = 4.0f;
  s.ScrollbarRounding = 4.0f;
  s.WindowBorderSize = 1.0f;
  s.FrameBorderSize = 0.0f;
  s.PopupRounding = 6.0f;
  s.WindowPadding = ImVec2(10, 8);
  s.FramePadding = ImVec2(8, 4);
  s.ItemSpacing = ImVec2(8, 5);
  s.ItemInnerSpacing = ImVec2(6, 4);
  s.IndentSpacing = 16.0f;
  s.ScrollbarSize = 12.0f;

  ImVec4* c = s.Colors;
  const ImVec4 bg0(0.043f, 0.055f, 0.067f, 1.0f);
  const ImVec4 bg1(0.063f, 0.078f, 0.098f, 1.0f);
  const ImVec4 bg2(0.082f, 0.102f, 0.125f, 1.0f);
  const ImVec4 line(0.141f, 0.169f, 0.200f, 1.0f);
  const ImVec4 txt0(0.906f, 0.925f, 0.945f, 1.0f);
  const ImVec4 txt1(0.659f, 0.694f, 0.733f, 1.0f);
  const ImVec4 txt2(0.427f, 0.467f, 0.510f, 1.0f);
  const ImVec4 grn(0.231f, 0.647f, 0.365f, 1.0f);
  const ImVec4 grn_h(0.282f, 0.729f, 0.427f, 1.0f);
  const ImVec4 grn_a(0.180f, 0.541f, 0.306f, 1.0f);
  const ImVec4 red(0.898f, 0.325f, 0.294f, 1.0f);
  const ImVec4 warn(0.824f, 0.600f, 0.133f, 1.0f);

  c[ImGuiCol_Text] = txt0;
  c[ImGuiCol_TextDisabled] = txt2;
  c[ImGuiCol_WindowBg] = bg1;
  c[ImGuiCol_ChildBg] = bg0;
  c[ImGuiCol_PopupBg] = bg2;
  c[ImGuiCol_Border] = line;
  c[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
  c[ImGuiCol_FrameBg] = bg2;
  c[ImGuiCol_FrameBgHovered] = ImVec4(0.118f, 0.145f, 0.176f, 1.0f);
  c[ImGuiCol_FrameBgActive] = ImVec4(0.141f, 0.173f, 0.204f, 1.0f);
  c[ImGuiCol_TitleBg] = bg2;
  c[ImGuiCol_TitleBgActive] = ImVec4(0.118f, 0.145f, 0.176f, 1.0f);
  c[ImGuiCol_TitleBgCollapsed] = bg1;
  c[ImGuiCol_MenuBarBg] = bg2;
  c[ImGuiCol_ScrollbarBg] = bg0;
  c[ImGuiCol_ScrollbarGrab] = ImVec4(0.180f, 0.220f, 0.263f, 1.0f);
  c[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.231f, 0.282f, 0.333f, 1.0f);
  c[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.282f, 0.341f, 0.400f, 1.0f);
  c[ImGuiCol_CheckMark] = grn;
  c[ImGuiCol_SliderGrab] = grn;
  c[ImGuiCol_SliderGrabActive] = grn_h;
  c[ImGuiCol_Button] = ImVec4(0.118f, 0.145f, 0.176f, 1.0f);
  c[ImGuiCol_ButtonHovered] = ImVec4(0.157f, 0.192f, 0.231f, 1.0f);
  c[ImGuiCol_ButtonActive] = grn_a;
  c[ImGuiCol_Header] = ImVec4(0.118f, 0.145f, 0.176f, 1.0f);
  c[ImGuiCol_HeaderHovered] = ImVec4(0.157f, 0.192f, 0.231f, 1.0f);
  c[ImGuiCol_HeaderActive] = ImVec4(0.180f, 0.220f, 0.263f, 1.0f);
  c[ImGuiCol_Separator] = line;
  c[ImGuiCol_SeparatorHovered] = txt2;
  c[ImGuiCol_SeparatorActive] = txt1;
  c[ImGuiCol_ResizeGrip] = line;
  c[ImGuiCol_ResizeGripHovered] = txt2;
  c[ImGuiCol_ResizeGripActive] = txt1;
  c[ImGuiCol_Tab] = bg2;
  c[ImGuiCol_TabHovered] = grn_a;
  c[ImGuiCol_TabActive] = ImVec4(0.118f, 0.165f, 0.200f, 1.0f);
  c[ImGuiCol_TabUnfocused] = bg1;
  c[ImGuiCol_TabUnfocusedActive] = bg2;
  c[ImGuiCol_TableHeaderBg] = bg2;
  c[ImGuiCol_TableBorderStrong] = line;
  c[ImGuiCol_TableBorderLight] = ImVec4(0.110f, 0.137f, 0.165f, 1.0f);
  c[ImGuiCol_TableRowBg] = bg1;
  c[ImGuiCol_TableRowBgAlt] = ImVec4(0.078f, 0.096f, 0.118f, 1.0f);
  c[ImGuiCol_TextSelectedBg] = ImVec4(0.184f, 0.361f, 0.255f, 1.0f);
  c[ImGuiCol_NavHighlight] = grn;
  c[ImGuiCol_NavWindowingHighlight] = grn;
  (void)red;
  (void)warn;
}

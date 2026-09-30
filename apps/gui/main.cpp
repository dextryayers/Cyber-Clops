// Cyber-Clops GUI entry. SDL3 + OpenGL3 + Dear ImGui docking.
// English only. Accel badge loads from real clops-accel-probe JSON.
// Tool runs spawn real clops-job verbs and stream JSONL rows.
#include <SDL3/SDL.h>
#include <SDL3/SDL_opengl.h>
#include "imgui.h"
#include "backends/imgui_impl_sdl3.h"
#include "backends/imgui_impl_opengl3.h"
#include "gui.h"
#include <cstdio>
#include <cstring>

namespace ClopsFonts {
void* ui = nullptr;
void* ui_bold = nullptr;
void* mono = nullptr;
}

static void* try_font(ImGuiIO& io, const char* path, float size) {
  FILE* f = std::fopen(path, "rb");
  if (!f) return nullptr;
  std::fclose(f);
  return (void*)io.Fonts->AddFontFromFileTTF(path, size);
}

static std::string run_capture(const char* cmd) {
  std::string out;
  FILE* p = popen(cmd, "r");
  if (!p) return out;
  char buf[2048];
  while (fgets(buf, sizeof(buf), p)) {
    out += buf;
    if (out.size() > 4096) break;
  }
  pclose(p);
  return out;
}

static std::string json_str(const std::string& body, const char* name) {
  // Tolerates pretty printed JSON with spaces around the colon.
  std::string key = std::string("\"") + name + "\"";
  auto p = body.find(key);
  if (p == std::string::npos) return "";
  p += key.size();
  while (p < body.size() && (body[p] == ' ' || body[p] == '\t' || body[p] == '\n' || body[p] == '\r' || body[p] == ':')) p++;
  if (p >= body.size() || body[p] != '"') return "";
  p++;
  std::string o;
  for (size_t i = p; i < body.size() && o.size() < 64; i++) {
    if (body[i] == '"') break;
    o += body[i];
  }
  return o;
}

static std::string load_accel() {
  std::string body = run_capture("clops-accel-probe 2>/dev/null");
  if (body.empty()) return "CPU: unknown | Backend: CPU only | GPU: none";
  std::string cpu = json_str(body, "cpu");
  std::string backend = json_str(body, "backend");
  bool cuda = body.find("\"cuda\":true") != std::string::npos;
  if (cpu.empty()) cpu = "unknown";
  if (backend.empty()) backend = "CPU only";
  char buf[192];
  std::snprintf(buf, sizeof(buf), "CPU: %s | Backend: %s | GPU: %s", cpu.c_str(), backend.c_str(),
    cuda ? "CUDA" : "none");
  return buf;
}

int main(int, char**) {
  if (!SDL_Init(SDL_INIT_VIDEO)) {
    printf("SDL_Init failed: %s\n", SDL_GetError());
    return 1;
  }
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
  SDL_Window* win = SDL_CreateWindow("Cyber-Clops", 1400, 900, SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE);
  if (!win) {
    printf("CreateWindow failed: %s\n", SDL_GetError());
    return 1;
  }
  SDL_GLContext gl = SDL_GL_CreateContext(win);
  SDL_GL_MakeCurrent(win, gl);
  SDL_GL_SetSwapInterval(1);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO();
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_DockingEnable;
  ClopsFonts::ui = try_font(io, "/usr/share/fonts/opentype/inter/Inter-Regular.otf", 15.0f);
  ClopsFonts::ui_bold = try_font(io, "/usr/share/fonts/opentype/inter/Inter-Medium.otf", 15.0f);
  ClopsFonts::mono = try_font(io, "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 14.0f);
  apply_ops_theme();
  ImGui_ImplSDL3_InitForOpenGL(win, gl);
  ImGui_ImplOpenGL3_Init("#version 130");

  AppState st;
  st.accel_text = load_accel();
  {
    // Short backend label for metric strips. Parsed from the same probe JSON.
    std::string body = run_capture("clops-accel-probe 2>/dev/null");
    std::string be = json_str(body, "backend");
    st.backend = be.empty() ? "CPU" : be;
  }
  {
    std::lock_guard<std::mutex> lk(st.mu);
    st.logs.push_back("Ready. Scope: lab-only. Safe Mode: ON.");
    st.logs.push_back(st.accel_text);
  }
  bool run = true;

  while (run) {
    SDL_Event e;
    while (SDL_PollEvent(&e)) {
      ImGui_ImplSDL3_ProcessEvent(&e);
      if (e.type == SDL_EVENT_QUIT) run = false;
      if (e.type == SDL_EVENT_KEY_DOWN) {
        const SDL_KeyboardEvent& k = e.key;
        bool ctrl = (k.mod & SDL_KMOD_CTRL) != 0;
        if (ctrl && k.key == SDLK_K) st.palette_open = !st.palette_open;
        if (ctrl && k.key == SDLK_RETURN) {
          if (st.active_tab >= 0 && st.active_tab < (int)st.pages.size())
            run_tool(st, st.pages[st.active_tab].tool_idx);
          else
            run_tool(st, st.active);
        }
        if (ctrl && k.key == SDLK_PERIOD) stop_jobs(st);
        if (k.key == SDLK_ESCAPE) {
          st.palette_open = false;
          st.show_settings = false;
          st.show_scope_dialog = false;
        }
      }
    }
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplSDL3_NewFrame();
    ImGui::NewFrame();
    ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport());
    panels_draw_topbar(st);
    panels_draw_left_tree(st);
    panels_draw_center(st);
    panels_draw_inspector(st);
    panels_draw_bottom(st);
    panels_draw_palette(st);
    panels_draw_overlays(st);

    ImGui::Render();
    int w = 0, h = 0;
    SDL_GetWindowSize(win, &w, &h);
    io.DisplaySize.x = (float)w;
    io.DisplaySize.y = (float)h;
    glViewport(0, 0, w, h);
    glClearColor(0.04f, 0.05f, 0.06f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    SDL_GL_SwapWindow(win);
  }

  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplSDL3_Shutdown();
  ImGui::DestroyContext();
  SDL_GL_DestroyContext(gl);
  SDL_DestroyWindow(win);
  SDL_Quit();
  return 0;
}

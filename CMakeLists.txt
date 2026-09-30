cmake_minimum_required(VERSION 3.24)
project(CyberClops VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

option(CL_OPS_ENABLE_CUDA "Enable CUDA backend" OFF)
option(CL_OPS_ENABLE_HIP "Enable HIP backend for AMD" OFF)
option(CL_OPS_ENABLE_OPENCL "Enable OpenCL backend" ON)
option(CL_OPS_ENABLE_ISPC "Enable ISPC SIMD backend" ON)
option(CL_OPS_BUILD_GUI "Build Dear ImGui GUI shell" ON)
option(CL_OPS_BUILD_TESTS "Build native tests" ON)

# Honest defaults: CUDA OFF on machines without nvcc.
# Dispatcher always builds CPU path. GPU is optional.

include(FetchContent)

if(CL_OPS_BUILD_GUI)
  # No sudo environments lack some X11 dev packages. XScrnSaver is
  # optional for a security toolkit, so default it off when unset.
  if(NOT DEFINED SDL_X11_XSCRNSAVER)
    set(SDL_X11_XSCRNSAVER OFF)
  endif()
  # SDL3 via FetchContent, no sudo needed.
  # Uses release-3.4.x for stability.
  FetchContent_Declare(
    SDL3
    GIT_REPOSITORY https://github.com/libsdl-org/SDL.git
    GIT_TAG release-3.4.0
    GIT_SHALLOW TRUE
  )
  # Dear ImGui docking branch.
  FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG docking
    GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(SDL3 imgui)
endif()

add_library(clops_native STATIC
  native/cpp/dispatch/dispatch.cpp
  native/cpp/dispatch/bench.cpp
  native/cpp/simd/sha_scalar.cpp
  native/net/scan.c
  native/net/svc_probe.c
)

target_include_directories(clops_native PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/native/cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/native/net
)

if(CL_OPS_ENABLE_OPENCL)
  find_package(OpenCL QUIET)
  if(OpenCL_FOUND)
    target_link_libraries(clops_native PUBLIC OpenCL::OpenCL)
    target_compile_definitions(clops_native PUBLIC CLOPS_HAS_OPENCL=1)
  else()
    message(STATUS "OpenCL headers not found. Building without OpenCL link. Runtime detection still works via dlopen.")
    target_compile_definitions(clops_native PUBLIC CLOPS_HAS_OPENCL=0)
  endif()
endif()

if(CL_OPS_ENABLE_CUDA)
  include(CheckLanguage)
  check_language(CUDA)
  if(CMAKE_CUDA_COMPILER)
    enable_language(CUDA)
    add_library(clops_accel_cuda STATIC
      native/accel/cuda/md5.cu
      native/accel/cuda/sha256.cu
    )
    target_compile_definitions(clops_accel_cuda PUBLIC CLOPS_HAS_CUDA=1)
    target_link_libraries(clops_native PUBLIC clops_accel_cuda)
  else()
    message(WARNING "CL_OPS_ENABLE_CUDA=ON but no CUDA compiler found. Continuing CPU only.")
  endif()
endif()

find_program(ISPC_BIN ispc)
if(CL_OPS_ENABLE_ISPC AND ISPC_BIN)
  message(STATUS "ISPC found: ${ISPC_BIN}")
  target_compile_definitions(clops_native PUBLIC CLOPS_HAS_ISPC=1)
else()
  message(STATUS "ISPC not found. Using scalar plus Rust SIMD path. This is expected on dev laptops.")
  target_compile_definitions(clops_native PUBLIC CLOPS_HAS_ISPC=0)
endif()

if(CL_OPS_BUILD_GUI)
  add_executable(clops_gui
    apps/gui/main.cpp
    apps/gui/panels.cpp
    apps/gui/table_view.cpp
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_sdl3.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
  )
  target_include_directories(clops_gui PRIVATE
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
    apps/gui
    native/cpp
  )
  find_package(OpenGL REQUIRED)
  target_link_libraries(clops_gui PRIVATE SDL3::SDL3 OpenGL::GL clops_native)
endif()

if(CL_OPS_BUILD_TESTS)
  enable_testing()
  add_executable(clops_native_test tests/native_test.cpp)
  target_include_directories(clops_native_test PRIVATE tests native/cpp)
  target_link_libraries(clops_native_test PRIVATE clops_native)
  add_test(NAME native_test COMMAND clops_native_test)
endif()

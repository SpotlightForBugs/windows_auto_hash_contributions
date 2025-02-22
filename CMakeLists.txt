cmake_minimum_required(VERSION 3.15)
project(stanev_help_crack)

# ----------------------------------------------------------------------------
# 0) Basic setup: force static runtime linking (/MT instead of /MD on Windows).
# ----------------------------------------------------------------------------
message(STATUS "Forcing static runtime linking for MSVC and static libs on other platforms...")
set(CMAKE_CXX_STANDARD 17)

foreach(flag_var
        CMAKE_C_LINK_FLAGS
        CMAKE_C_LINK_FLAGS_DEBUG
        CMAKE_C_LINK_FLAGS_RELEASE
        CMAKE_CXX_LINK_FLAGS
        CMAKE_CXX_LINK_FLAGS_DEBUG
        CMAKE_CXX_LINK_FLAGS_RELEASE
        CMAKE_EXE_LINKER_FLAGS
        CMAKE_EXE_LINKER_FLAGS_DEBUG
        CMAKE_EXE_LINKER_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_MINSIZEREL
        CMAKE_C_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_MINSIZEREL
        CMAKE_CXX_FLAGS_RELWITHDEBINFO
)
    string(REPLACE "/MD" "-MT" ${flag_var} "${${flag_var}}")
endforeach()

# Link statically to stdlib if desired (GCC/MinGW).
set(CMAKE_EXE_LINKER_FLAGS
        "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++"
)

# ----------------------------------------------------------------------------
# 1) We’ll download, verify, and build help_crack.exe via PyInstaller
# ----------------------------------------------------------------------------
set(HELPCRACK_PY_URL      "https://wpa-sec.stanev.org/hc/help_crack.py")
set(HELPCRACK_PY_DST      "${CMAKE_BINARY_DIR}/help_crack.py")
set(HELPCRACK_PY_MD5      "2fc8e957f849b72cb21866a6df7d6883")
set(HELPCRACK_BUILD_EXE   "${CMAKE_BINARY_DIR}/help_crack.exe")

message(STATUS "Downloading help_crack.py from: ${HELPCRACK_PY_URL}")
file(DOWNLOAD
        "${HELPCRACK_PY_URL}"
        "${HELPCRACK_PY_DST}"
        EXPECTED_MD5 "${HELPCRACK_PY_MD5}"
)
message(STATUS "Successfully downloaded help_crack.py and MD5 verified.")

add_custom_command(
        OUTPUT ${HELPCRACK_BUILD_EXE}
        COMMENT "Building help_crack.exe using PyInstaller..."
        COMMAND python -m venv "${CMAKE_BINARY_DIR}/pyenv"
        COMMAND "${CMAKE_BINARY_DIR}/pyenv/Scripts/python.exe" -m pip install --upgrade pip
        COMMAND "${CMAKE_BINARY_DIR}/pyenv/Scripts/python.exe" -m pip install pyinstaller
        COMMAND "${CMAKE_BINARY_DIR}/pyenv/Scripts/pyinstaller.exe"
        --onefile
        "${HELPCRACK_PY_DST}"
        --distpath "${CMAKE_BINARY_DIR}"
        --name "help_crack"
        DEPENDS "${HELPCRACK_PY_DST}"
        VERBATIM
)

# Move help_crack.exe into the source directory so resources.rc can find it
set(HELPCRACK_SRC_EXE "${CMAKE_SOURCE_DIR}/help_crack.exe")
add_custom_command(
        OUTPUT ${HELPCRACK_SRC_EXE}
        COMMENT "Moving help_crack.exe into source directory..."
        COMMAND ${CMAKE_COMMAND} -E rename
        "${HELPCRACK_BUILD_EXE}"
        "${HELPCRACK_SRC_EXE}"
        DEPENDS ${HELPCRACK_BUILD_EXE}
)

# A target to ensure help_crack.exe is ready in the source tree
add_custom_target(build_help_crack_exe ALL
        DEPENDS ${HELPCRACK_SRC_EXE}
)

# ----------------------------------------------------------------------------
# 2) Let resources.rc wait for help_crack.exe to exist
# ----------------------------------------------------------------------------
set_source_files_properties(
        "${CMAKE_SOURCE_DIR}/resources.rc"
        PROPERTIES
        OBJECT_DEPENDS "${HELPCRACK_SRC_EXE}"
)

# ----------------------------------------------------------------------------
# 3) Sources (shared by both standard.exe and headless.exe)
# ----------------------------------------------------------------------------
set(SOURCES
        main.cpp
        resources.rc
        resource.h
)

# ----------------------------------------------------------------------------
# 4) Build standard.exe (DEBUG=0)
# ----------------------------------------------------------------------------
message(STATUS "Configuring target: standard.exe with DEBUG=0")
add_executable(standard ${SOURCES})
target_compile_definitions(standard PRIVATE DEBUG=0)

# link to urlmon & bit7z
target_link_libraries(standard PRIVATE urlmon)

# If using bit7z as a subdirectory:
add_subdirectory(${CMAKE_SOURCE_DIR}/third_party/bit7z)
target_link_libraries(standard PRIVATE bit7z)

# Copy 7z.dll after building
add_custom_command(TARGET standard POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/7z.dll"
        $<TARGET_FILE_DIR:standard>
)

# ----------------------------------------------------------------------------
# 5) Build headless.exe (DEBUG=1)
# ----------------------------------------------------------------------------
message(STATUS "Configuring target: headless.exe with DEBUG=1")
add_executable(headless ${SOURCES})
target_compile_definitions(headless PRIVATE DEBUG=1)

target_link_libraries(headless PRIVATE urlmon bit7z)

add_custom_command(TARGET headless POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/7z.dll"
        $<TARGET_FILE_DIR:headless>
)

# ----------------------------------------------------------------------------
# 6) Clean up all intermediate files except final binaries
# ----------------------------------------------------------------------------
# Once both standard.exe and headless.exe (and help_crack.exe) have been built,
# delete the PyInstaller venv, spec, leftover build folders, etc.
add_custom_target(clean_intermediates
        COMMENT "Removing intermediate PyInstaller/venv files except .exe binaries..."
        COMMAND ${CMAKE_COMMAND} -E remove_directory "${CMAKE_BINARY_DIR}/pyenv"
        COMMAND ${CMAKE_COMMAND} -E remove -f "${CMAKE_BINARY_DIR}/help_crack.spec"
        COMMAND ${CMAKE_COMMAND} -E remove -f "${HELPCRACK_PY_DST}"
        # If PyInstaller created a build/ folder or other leftover dirs in the binary dir:
        COMMAND ${CMAKE_COMMAND} -E remove_directory "${CMAKE_BINARY_DIR}/build"
)

# Make sure cleanup happens after everything is built
add_dependencies(clean_intermediates build_help_crack_exe standard headless)

add_custom_target(stanev_help_crack ALL
        DEPENDS standard headless
)


add_custom_target(build_and_cleanup ALL
        DEPENDS build_help_crack_exe standard headless clean_intermediates
)

message(STATUS "CMake configuration complete!")

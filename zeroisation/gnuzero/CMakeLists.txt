cmake_minimum_required(VERSION 3.12)


project("GCC_Plugin")

# set(CMAKE_MESSAGE_LOG_LEVEL "DEBUG")
set(CXX_STANDARD 20)

set(GCC_VERSION "not set" CACHE STRING "Version of the compiler to use.")
message(DEBUG "GCC_VERSION: ${GCC_VERSION}")
message(STATUS "CMAKE_C_COMPILER: ${CMAKE_C_COMPILER}")
message(STATUS "CMAKE_CXX_COMPILER: ${CMAKE_CXX_COMPILER}")
message(STATUS "CMAKE_C_COMPILER_VERSION: ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "CMAKE_CXX_COMPILER_VERSION: ${CMAKE_CXX_COMPILER_VERSION}")

string(COMPARE EQUAL "${GCC_VERSION}" "not set" GCC_SET)
if (${GCC_SET})
  message(FATAL_ERROR "Please set the GCC version to used.")
endif()
set(GCC_INSTALL_DIR "$ENV{HOME}/.local")
set(GCC_INSTALL_DIR_BIN "${GCC_INSTALL_DIR}/bin")
set(GCC_INSTALL_DIR_INCLUDE "${GCC_INSTALL_DIR}/lib/gcc/x86_64-pc-linux-gnu/${GCC_VERSION}/include")
set(GCC_INSTALL_DIR_PLUGIN_INCLUDE "${GCC_INSTALL_DIR}/lib/gcc/x86_64-pc-linux-gnu/${GCC_VERSION}/plugin/include")

# Looking for gcc
# message(CHECK_START "Looking for GCC in ${GCC_INSTALL_DIR_BIN}")
# find_file(GCC_PATH
#   NAMES "gcc_modified"
#   PATHS ${GCC_INSTALL_DIR_BIN}
#   NO_DEFAULT_PATH
#   REQUIRED
# )
set(GCC_PATH "/usr/bin/gcc")
set(CMAKE_C_COMPILER ${GCC_PATH})
# message(CHECK_PASS "found")
# message(DEBUG "GCC_PATH: ${GCC_PATH}")

#Looking for g++
# message(CHECK_START "Looking for G++ in ${GCC_INSTALL_DIR_BIN}")
# find_file(G++_PATH
#   NAMES "g++_modified"
#   PATHS ${GCC_INSTALL_DIR_BIN}
#   NO_DEFAULT_PATH
#   REQUIRED
#   )
set(G++_PATH "/usr/bin/g++")
set(CMAKE_CXX_COMPILER ${G++_PATH})
# message(CHECK_PASS "found")
# message(DEBUG "G++_PATH: ${G++_PATH}")

# Looking for GCC plugin header
message(CHECK_START "Looking for GCC plugin header in ${GCC_INSTALL_DIR_PLUGIN_INCLUDE}")
find_file(GCC_PLUGIN_HEADER
  NAMES "gcc-plugin.h"
  PATHS ${GCC_INSTALL_DIR_PLUGIN_INCLUDE}
  NO_DEFAULT_PATH
  REQUIRED
  )
message(CHECK_PASS "found")
message(DEBUG "GCC_PLUGIN_HEADER: ${GCC_PLUGIN_HEADER}")

set(LIB_NAME "scrub")

set(SRC "src/plugin_init.cc"
        "src/sm_scrub.cc"
        "src/attribute.cc"
        "src/utils.cc"
)
set(OPT "-Wall"
        "-g"
        "-fno-rtti"
        "-fdiagnostics-color=always"
)
message(DEBUG "SRC: ${SRC}")
message(DEBUG "OPT: ${OPT}")
add_library(${LIB_NAME} MODULE)
target_include_directories(${LIB_NAME} PUBLIC "inc"
                                        PUBLIC ${GCC_INSTALL_DIR_PLUGIN_INCLUDE}
                                        PUBLIC ${GCC_INSTALL_DIR_INCLUDE}
                                        scrub PRIVATE "/home/ankita/Desktop/GNUZero/gnuzero_artifacts/gcc_fork/gcc")
                                         
#"${CMAKE_SOURCE_DIR}/../../gcc_fork/gcc")
target_sources(${LIB_NAME} PRIVATE ${SRC})
target_compile_options(${LIB_NAME} PRIVATE ${OPT})

#target_compile_definitions(${LIB_NAME} PRIVATE DEBUG=1)

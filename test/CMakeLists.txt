#
# PROJECT, LIBRARY AND BINARY NAMES
#

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(active_secret_unit_tests)
SET(ExecutableName active_secret_tests)
SET(LibraryName ActiveSecret)

#
# PLATFORM IDENTIFIERS
#

SET(PlatformExt cpp)

IF (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  SET(PlatformName win)
  ADD_DEFINITIONS(-D_WINDOWS -DWIN32 -D_WIN32)

  IF (BUILD_SHARED_LIBS)
    ADD_DEFINITIONS(-D_USRDLL -D_EXPORT_DLL_ -D_USEGUIDLL -D_USREXDLL -D_USRSTUDIODLL)
  ENDIF()
ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  SET(PlatformName linux)
ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  SET(PlatformName osx)
  SET(PlatformExt mm)
ELSE()
  MESSAGE(FATAL_ERROR "Unsupported platform, CMake will exit")
ENDIF()

IF (${PlatformName} MATCHES "win")
  SET(PlatformDir win10)
ELSE()
  SET(PlatformDir ${PlatformName})
ENDIF()

#
# CONFIGURABLE PATHS
#

# CLibs needed for Google Test/Mock

IF (DEFINED ENV{CLIBS_PATH})
  SET(CLibsPath $ENV{CLIBS_PATH})
ELSE()
  GET_FILENAME_COMPONENT(CLibsPath "../../clibs" ABSOLUTE)
ENDIF()

GET_FILENAME_COMPONENT(GoogleTestPath "../../googletest" ABSOLUTE)
GET_FILENAME_COMPONENT(CLibsIncludePath "${CLibsPath}/include/${PlatformDir}" ABSOLUTE)
GET_FILENAME_COMPONENT(CLibsLibPath "${CLibsPath}/lib/${PlatformDir}/Release" ABSOLUTE)

# Additional library dependencies

IF (DEFINED ENV{COMMON_PATH})
  SET(CommonPath $ENV{COMMON_PATH})
ELSE()
  GET_FILENAME_COMPONENT(CommonPath ../../mmx-common ABSOLUTE)
ENDIF()

MESSAGE(STATUS "")
MESSAGE(STATUS "Configurable paths:")
MESSAGE(STATUS "  GoogleTestPath   ${GoogleTestPath}")
MESSAGE(STATUS "  CLibs            ${CLibsPath}")
MESSAGE(STATUS "  CLibsInclude     ${CLibsIncludePath}")
MESSAGE(STATUS "  CLibsLib         ${CLibsLibPath}")
MESSAGE(STATUS "  Common           ${CommonPath}")

#
# COMPILER CONFIGURATION
#

MESSAGE(STATUS "")

# Use C++ 14
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Wno-long-long -pedantic")
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")

# To use DEBUG
IF (DEFINED ENV{DEBUG})
  SET(CMAKE_BUILD_TYPE Debug)
  MESSAGE(STATUS "Compiling for DEBUG")
ENDIF()

IF (${PlatformName} MATCHES "osx")
  # Mac OS X specific code
  MESSAGE(STATUS "Compliling for Darwin")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -Wno-undefined-var-template")
ENDIF()

IF (MSVC)
  # Force to always compile with W4
  IF(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
    STRING(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
  ENDIF()
ELSEIF (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
  # Update if necessary
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-long-long -pedantic")
ENDIF()

IF (DEFINED ENV{GTEST_USE_OWN_TR1_TUPLE})
  ADD_DEFINITIONS( -DGTEST_USE_OWN_TR1_TUPLE=1 )
ENDIF()

ADD_DEFINITIONS( -DGTEST_LANG_CXX11=1 )

# Needed for mmx-common
IF (DEFINED ENV{MX_DATE_TIME_POSIX_REGEX})
  ADD_DEFINITIONS( -DMX_DATE_TIME_POSIX_REGEX=1 )
ENDIF()

MESSAGE(STATUS "${CMAKE_CXX_FLAGS}")

#
# INCLUDE DIRECTORIES
#

INCLUDE_DIRECTORIES(
  ../src
  ./fixtures
  ${GoogleTestPath}/googlemock
  ${GoogleTestPath}/googlemock/include
  ${GoogleTestPath}/googletest
  ${GoogleTestPath}/googletest/include
  ${CLibsIncludePath}
  ${CommonPath}/src
  )

#
# SOURCE CODE
#

FUNCTION(ADD_FILES file_list)
  FOREACH(_src ${ARGN})
    GET_FILENAME_COMPONENT(_full_path ${_src} ABSOLUTE)
    LIST(APPEND ${file_list} ${_full_path})
  ENDFOREACH()
  SET(${file_list} ${${file_list}} PARENT_SCOPE)
ENDFUNCTION(ADD_FILES)

FILE(
  GLOB_RECURSE
  LibrarySrc
  ../src/*
  )

FILE(
  GLOB_RECURSE
  TestSrc
  fixtures/*
  src/*
  )

FILE(
  GLOB
  ScriptSrc
  ../config/script.cpp
  )

ADD_FILES(
  GTestSrc
  ${GoogleTestPath}/googletest/src/gtest-all.cc
  )

ADD_FILES(
  GMockSrc
  ${GoogleTestPath}/googlemock/src/gmock-all.cc
  )

FILE(
  GLOB_RECURSE
  CommonSrc
  ${CommonPath}/src/*
  )


#
# LIBRARIES - BINARY
#

UNSET(CURL CACHE)
FIND_LIBRARY(
  CURL
  NAMES curl
  PATHS ${CLibsLibPath}
  NO_DEFAULT_PATH
  )

IF (${PlatformName} MATCHES "linux")
  FIND_LIBRARY(
    DL
    NAMES dl
    )
ELSEIF (${PlatformName} MATCHES "osx")
  FIND_LIBRARY(
    LibC++
    NAMES c++
    )
ENDIF()

FIND_LIBRARY(
  OpenSSL
  NAMES ssl
  PATHS ${CLibsLibPath}
  NO_DEFAULT_PATH
  )

FIND_LIBRARY(
  OpenSSLCrypto
  NAMES crypto
  PATHS ${CLibsLibPath}
  NO_DEFAULT_PATH
  )

FIND_LIBRARY(
  PThread
  NAMES pthread
  )

FIND_LIBRARY(
  Z
  NAMES z
  PATHS ${CLibsLibPath}
  NO_DEFAULT_PATH
  )

MESSAGE(STATUS "")
MESSAGE(STATUS "Dependent libraries:")
MESSAGE(STATUS "  dl              ${DL}")
MESSAGE(STATUS "  libc++          ${LibC++}")
MESSAGE(STATUS "  openssl         ${OpenSSL}")
MESSAGE(STATUS "  openssl crypto  ${OpenSSLCrypto}")
MESSAGE(STATUS "  pthread         ${PThread}")
MESSAGE(STATUS "  z               ${Z}")

#
# LIBRARIES - SOURCE
#

ADD_LIBRARY(
  GTest
  ${GTestSrc}
  )

ADD_LIBRARY(
  GMock
  ${GMockSrc}
  )

ADD_LIBRARY(
  MMX-Common
  ${CommonSrc}
  )

ADD_LIBRARY(
  ${LibraryName}
  ${LibrarySrc}
  )

#
# CREATE EXECUTABLE
#

ADD_EXECUTABLE(
  ${ExecutableName}
  ${TestSrc}
  )
ADD_EXECUTABLE(script ${ScriptSrc})

add_custom_target(script_run
  COMMAND script
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "run script to encrypt strings"
)

add_dependencies(${LibraryName} script_run)

#
# LINK
#

MESSAGE(STATUS "")

TARGET_LINK_LIBRARIES(
  ${ExecutableName}
  ${LibraryName}
  GTest
  GMock
  MMX-Common
  ${LibC++}
  ${OpenSSL}
  ${OpenSSLCrypto}
  ${DL}
  ${PThread}
  ${Z}
  )

TARGET_LINK_LIBRARIES(
  script
  ${LibC++}
  ${OpenSSL}
  ${OpenSSLCrypto}
  ${DL}
  ${PThread}
  ${Z}
  )

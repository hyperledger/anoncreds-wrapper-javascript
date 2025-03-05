project(anoncredsreactnative)
cmake_minimum_required(VERSION 3.4.1)

set (PACKAGE_NAME "anoncredsreactnative")
set (LIB_NAME "anoncreds")
file (GLOB LIBANONCREDS_DIR "${CMAKE_SOURCE_DIR}/../native/mobile/android/${ANDROID_ABI}")

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)
set (BUILD_DIR ${CMAKE_SOURCE_DIR}/build)

find_package(fbjni REQUIRED CONFIG)
find_package(ReactAndroid REQUIRED CONFIG)

include_directories(
  ../cpp
  ../cpp/include
  "${LIBANONCREDS_DIR}"
)

add_library(
  ${PACKAGE_NAME}
  SHARED
  cpp-adapter.cpp
  ../cpp/HostObject.cpp
  ../cpp/turboModuleUtility.cpp
  ../cpp/anoncreds.cpp
)

target_include_directories(
  ${PACKAGE_NAME}
  PRIVATE
  "${NODE_MODULES_DIR}/react-native/ReactCommon"
  "${NODE_MODULES_DIR}/react-native/ReactCommon/callinvoker"
  "${NODE_MODULES_DIR}/react-native/ReactAndroid/src/main/jni/react/turbomodule"
)

find_library(
  ANONCREDS_LIB 
  anoncreds
  paths ${LIBANONCREDS_DIR}
  NO_CMAKE_FIND_ROOT_PATH
)

if (NOT ANONCREDS_LIB)
  message(FATAL_ERROR "Could not find ANONCREDS_LIB at: ${LIBANONCREDS_DIR}")
endif()

if(${REACT_NATIVE_VERSION} GREATER_EQUAL 76)
  target_link_libraries(${PACKAGE_NAME} ReactAndroid::reactnative)
else()
  target_link_libraries(${PACKAGE_NAME} ReactAndroid::reactnativejni)
endif()

target_link_libraries(
  ${PACKAGE_NAME}
  ${ANONCREDS_LIB}
  ReactAndroid::jsi
  fbjni::fbjni
)

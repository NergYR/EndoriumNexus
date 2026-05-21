cmake_minimum_required(VERSION 3.28)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(EndoriumNexusBackend VERSION 0.1.0 LANGUAGES CXX)

  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)

  option(NEXUS_BUILD_TESTS "Build Endorium Nexus tests" ON)
  option(NEXUS_ENABLE_ASAN "Enable AddressSanitizer" OFF)
  option(NEXUS_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
endif()

if(NOT COMMAND nexus_apply_sanitizers)
  list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
  include(Sanitizers)
endif()

include(GNUInstallDirs)
include(CTest)
find_package(PkgConfig REQUIRED)

find_package(Drogon CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PostgreSQL REQUIRED)
find_package(ZLIB REQUIRED)
pkg_check_modules(LIBUV REQUIRED IMPORTED_TARGET libuv)

find_library(ARGON2_LIBRARY NAMES argon2)
if(NOT ARGON2_LIBRARY)
  find_file(
    ARGON2_LIBRARY
    NAMES libargon2.so.1
    PATHS /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu
    REQUIRED
  )
endif()

set(NEXUS_CORE_SOURCES
  libs/core/src/config.cpp
  libs/core/src/time.cpp
  libs/core/src/uv_runtime.cpp
)

set(NEXUS_SECURITY_SOURCES
  libs/security/src/ad_crypto.cpp
  libs/security/src/password_hasher.cpp
  libs/security/src/totp.cpp
  libs/security/src/pki.cpp
)

set(NEXUS_STORAGE_SOURCES
  libs/storage/src/database.cpp
)

set(NEXUS_JOBS_SOURCES
  libs/jobs/src/queue.cpp
)

set(NEXUS_PROTOCOL_SOURCES
  libs/protocol/src/dns.cpp
  libs/protocol/src/dhcp.cpp
  libs/protocol/src/kerberos.cpp
  libs/protocol/src/ldap.cpp
  libs/protocol/src/repo.cpp
)

add_library(nexus_core ${NEXUS_CORE_SOURCES})
target_include_directories(nexus_core PUBLIC libs/core/include)
target_link_libraries(nexus_core PUBLIC PkgConfig::LIBUV)
nexus_apply_sanitizers(nexus_core)

add_library(nexus_security ${NEXUS_SECURITY_SOURCES})
target_include_directories(nexus_security PUBLIC libs/security/include)
target_link_libraries(nexus_security
  PUBLIC
    OpenSSL::Crypto
    ${ARGON2_LIBRARY}
)
nexus_apply_sanitizers(nexus_security)

add_library(nexus_storage ${NEXUS_STORAGE_SOURCES})
target_include_directories(nexus_storage PUBLIC libs/storage/include)
target_link_libraries(nexus_storage
  PUBLIC
    nexus_core
    PostgreSQL::PostgreSQL
)
nexus_apply_sanitizers(nexus_storage)

add_library(nexus_jobs ${NEXUS_JOBS_SOURCES})
target_include_directories(nexus_jobs PUBLIC libs/jobs/include)
target_link_libraries(nexus_jobs PUBLIC nexus_core)
nexus_apply_sanitizers(nexus_jobs)

add_library(nexus_protocol ${NEXUS_PROTOCOL_SOURCES})
target_include_directories(nexus_protocol PUBLIC libs/protocol/include)
target_link_libraries(nexus_protocol
  PUBLIC
    nexus_core
    ZLIB::ZLIB
    OpenSSL::Crypto
)
nexus_apply_sanitizers(nexus_protocol)

target_link_libraries(nexus_security PUBLIC nexus_core)
target_link_libraries(nexus_jobs PUBLIC nexus_core)
target_link_libraries(nexus_protocol PUBLIC nexus_core)

add_executable(nexus-api
  apps/api/main.cpp
  apps/api/platform_state.cpp
)
target_include_directories(nexus-api PRIVATE apps/api)
target_link_libraries(nexus-api
  PRIVATE
    Drogon::Drogon
    nexus_core
    nexus_jobs
    nexus_protocol
    nexus_security
    nexus_storage
)
nexus_apply_sanitizers(nexus-api)

add_executable(nexus-directory apps/directory/main.cpp)
target_include_directories(nexus-directory PRIVATE ${JSONCPP_INCLUDE_DIRS})
target_link_libraries(nexus-directory PRIVATE nexus_core nexus_protocol nexus_security PostgreSQL::PostgreSQL ${JSONCPP_LIBRARIES})
nexus_apply_sanitizers(nexus-directory)

add_executable(nexus-network apps/network/main.cpp)
target_link_libraries(nexus-network PRIVATE nexus_core nexus_protocol PostgreSQL::PostgreSQL)
nexus_apply_sanitizers(nexus-network)

add_executable(nexus-pki-repo apps/pki_repo/main.cpp)
target_link_libraries(nexus-pki-repo PRIVATE nexus_core)
nexus_apply_sanitizers(nexus-pki-repo)

add_executable(nexus-services apps/services/main.cpp)
target_include_directories(nexus-services PRIVATE ${JSONCPP_INCLUDE_DIRS} ${PostgreSQL_INCLUDE_DIRS})
target_link_libraries(nexus-services PRIVATE nexus_core ${JSONCPP_LIBRARIES} ${PostgreSQL_LIBRARIES})
nexus_apply_sanitizers(nexus-services)

add_executable(nexusctl apps/nexusctl/main.cpp)
target_link_libraries(nexusctl
  PRIVATE
    nexus_core
    nexus_protocol
    nexus_security
    nexus_storage
)
nexus_apply_sanitizers(nexusctl)

if(NEXUS_BUILD_TESTS)
  add_executable(nexus-unit
    tests/unit_tests.cpp
    apps/api/platform_state.cpp
  )
  target_include_directories(nexus-unit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(nexus-unit
    PRIVATE
      Drogon::Drogon
      nexus_core
      nexus_jobs
      nexus_protocol
      nexus_security
      nexus_storage
  )
  add_test(NAME nexus-unit COMMAND nexus-unit)
  nexus_apply_sanitizers(nexus-unit)
endif()

install(TARGETS
  nexus-api
  nexus-directory
  nexus-network
  nexus-pki-repo
  nexus-services
  nexusctl
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/../ops/systemd/endorium-nexus-api.service
  ${CMAKE_CURRENT_SOURCE_DIR}/../ops/systemd/endorium-nexus-directory.service
  ${CMAKE_CURRENT_SOURCE_DIR}/../ops/systemd/endorium-nexus-network.service
  ${CMAKE_CURRENT_SOURCE_DIR}/../ops/systemd/endorium-nexus-pki-repo.service
  ${CMAKE_CURRENT_SOURCE_DIR}/../ops/systemd/endorium-nexus-services.service
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system
)

install(DIRECTORY
  ${CMAKE_CURRENT_SOURCE_DIR}/sql/migrations
  DESTINATION ${CMAKE_INSTALL_DATADIR}/endorium-nexus/sql
)

set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME "endorium-nexus")
set(CPACK_PACKAGE_VENDOR "Endorium")
set(CPACK_PACKAGE_CONTACT "ops@endorium.local")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
include(CPack)

file(
    DOWNLOAD https://github.com/cpm-cmake/CPM.cmake/releases/latest/download/get_cpm.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/get_cpm.cmake
)
include(${CMAKE_CURRENT_BINARY_DIR}/get_cpm.cmake)

# src/blockstorage/CMakeLists.txt
# src/blockstorage/CMakeLists.txt
# Small CMake helper to add the in-memory blockstorage impl and headers.

add_library(blockstorage_inmemory
    BlockStorageInMemory.cpp
)

target_include_directories(blockstorage_inmemory PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/blockstorage
)

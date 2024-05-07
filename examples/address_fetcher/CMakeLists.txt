include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(address_fetcher main.cpp utilities.cpp)
target_link_libraries(address_fetcher PRIVATE elfio::elfio)

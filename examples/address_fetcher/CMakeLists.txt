CPMAddPackage(
    NAME capstone-cpp
    GITHUB_REPOSITORY "25077667/capstone-cpp"
    GIT_TAG "0.1.5"
)

# Ser SRC variable to the all the cpp source files under current directory
file(GLOB ADDRESS_FETCHER_SRC *.cpp)

add_executable(address_fetcher ${ADDRESS_FETCHER_SRC})
target_include_directories(address_fetcher PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CAPSTONE_WRAPPER_INCLUDE_DIR})
target_link_libraries(address_fetcher PRIVATE elfio::elfio ${CAPSTONE_WRAPPER_LIBRARY})

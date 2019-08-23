cmake_minimum_required (VERSION 3.5)
if (UNIX)
  add_definitions(-Wno-sign-compare -Wno-enum-compare)
endif(UNIX)
project(restserver)
set (CMAKE_CXX_STANDARD 11)
include_directories("${CMAKE_SOURCE_DIR}")

add_executable(restserver
  main.cpp
  src/handler.cpp
  )

set(Casablanca_LIBRARIES "-lopenabe -lpthread -lboost_system -lcrypto -lssl -lcpprest")
target_link_libraries(restserver ${Casablanca_LIBRARIES})






include_directories(.)

add_executable(
  main

  main.cpp
)

add_definitions(-DDEBUG)

target_link_libraries(
  main

  snark
)

target_include_directories(
  main

  PUBLIC
  ${SOURCE_DIR}/sm3
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
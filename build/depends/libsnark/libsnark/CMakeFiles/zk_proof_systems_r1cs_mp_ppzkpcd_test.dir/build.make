# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/pingxie/Project/graduation/sm3

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/pingxie/Project/graduation/sm3/build

# Include any dependencies generated for this target.
include depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/depend.make

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/progress.make

# Include the compile flags for this target's objects.
include depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/flags.make

depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp.o: depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/flags.make
depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp.o: ../depends/libsnark/libsnark/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/pingxie/Project/graduation/sm3/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp.o"
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp.o -c /home/pingxie/Project/graduation/sm3/depends/libsnark/libsnark/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp

depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp.i"
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/pingxie/Project/graduation/sm3/depends/libsnark/libsnark/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp > CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp.i

depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp.s"
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/pingxie/Project/graduation/sm3/depends/libsnark/libsnark/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp -o CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp.s

# Object files for target zk_proof_systems_r1cs_mp_ppzkpcd_test
zk_proof_systems_r1cs_mp_ppzkpcd_test_OBJECTS = \
"CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp.o"

# External object files for target zk_proof_systems_r1cs_mp_ppzkpcd_test
zk_proof_systems_r1cs_mp_ppzkpcd_test_EXTERNAL_OBJECTS =

depends/libsnark/libsnark/zk_proof_systems_r1cs_mp_ppzkpcd_test: depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/zk_proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/tests/test_r1cs_mp_ppzkpcd.cpp.o
depends/libsnark/libsnark/zk_proof_systems_r1cs_mp_ppzkpcd_test: depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/build.make
depends/libsnark/libsnark/zk_proof_systems_r1cs_mp_ppzkpcd_test: depends/libsnark/libsnark/libsnark.a
depends/libsnark/libsnark/zk_proof_systems_r1cs_mp_ppzkpcd_test: depends/libsnark/depends/libff/libff/libff.a
depends/libsnark/libsnark/zk_proof_systems_r1cs_mp_ppzkpcd_test: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/zk_proof_systems_r1cs_mp_ppzkpcd_test: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/zk_proof_systems_r1cs_mp_ppzkpcd_test: /usr/lib/x86_64-linux-gnu/libgmpxx.so
depends/libsnark/libsnark/zk_proof_systems_r1cs_mp_ppzkpcd_test: depends/libsnark/depends/libzm.a
depends/libsnark/libsnark/zk_proof_systems_r1cs_mp_ppzkpcd_test: depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/pingxie/Project/graduation/sm3/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable zk_proof_systems_r1cs_mp_ppzkpcd_test"
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/build: depends/libsnark/libsnark/zk_proof_systems_r1cs_mp_ppzkpcd_test

.PHONY : depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/build

depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/clean:
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/clean

depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/depend:
	cd /home/pingxie/Project/graduation/sm3/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/pingxie/Project/graduation/sm3 /home/pingxie/Project/graduation/sm3/depends/libsnark/libsnark /home/pingxie/Project/graduation/sm3/build /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/zk_proof_systems_r1cs_mp_ppzkpcd_test.dir/depend


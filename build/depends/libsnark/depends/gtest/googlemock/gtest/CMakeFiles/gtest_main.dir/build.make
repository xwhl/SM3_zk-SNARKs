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
include depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/depend.make

# Include the progress variables for this target.
include depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/progress.make

# Include the compile flags for this target's objects.
include depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/flags.make

depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o: depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/flags.make
depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o: ../depends/libsnark/depends/gtest/googletest/src/gtest_main.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/pingxie/Project/graduation/sm3/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o"
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/depends/gtest/googlemock/gtest && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/gtest_main.dir/src/gtest_main.cc.o -c /home/pingxie/Project/graduation/sm3/depends/libsnark/depends/gtest/googletest/src/gtest_main.cc

depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/gtest_main.dir/src/gtest_main.cc.i"
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/depends/gtest/googlemock/gtest && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/pingxie/Project/graduation/sm3/depends/libsnark/depends/gtest/googletest/src/gtest_main.cc > CMakeFiles/gtest_main.dir/src/gtest_main.cc.i

depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/gtest_main.dir/src/gtest_main.cc.s"
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/depends/gtest/googlemock/gtest && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/pingxie/Project/graduation/sm3/depends/libsnark/depends/gtest/googletest/src/gtest_main.cc -o CMakeFiles/gtest_main.dir/src/gtest_main.cc.s

# Object files for target gtest_main
gtest_main_OBJECTS = \
"CMakeFiles/gtest_main.dir/src/gtest_main.cc.o"

# External object files for target gtest_main
gtest_main_EXTERNAL_OBJECTS =

depends/libsnark/depends/gtest/googlemock/gtest/libgtest_main.a: depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/src/gtest_main.cc.o
depends/libsnark/depends/gtest/googlemock/gtest/libgtest_main.a: depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/build.make
depends/libsnark/depends/gtest/googlemock/gtest/libgtest_main.a: depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/pingxie/Project/graduation/sm3/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libgtest_main.a"
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/depends/gtest/googlemock/gtest && $(CMAKE_COMMAND) -P CMakeFiles/gtest_main.dir/cmake_clean_target.cmake
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/depends/gtest/googlemock/gtest && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/gtest_main.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/build: depends/libsnark/depends/gtest/googlemock/gtest/libgtest_main.a

.PHONY : depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/build

depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/clean:
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/depends/gtest/googlemock/gtest && $(CMAKE_COMMAND) -P CMakeFiles/gtest_main.dir/cmake_clean.cmake
.PHONY : depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/clean

depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/depend:
	cd /home/pingxie/Project/graduation/sm3/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/pingxie/Project/graduation/sm3 /home/pingxie/Project/graduation/sm3/depends/libsnark/depends/gtest/googletest /home/pingxie/Project/graduation/sm3/build /home/pingxie/Project/graduation/sm3/build/depends/libsnark/depends/gtest/googlemock/gtest /home/pingxie/Project/graduation/sm3/build/depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest_main.dir/depend


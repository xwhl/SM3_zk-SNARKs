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

# Utility rule file for Nightly.

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/Nightly.dir/progress.make

depends/libsnark/libsnark/CMakeFiles/Nightly:
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark && /usr/bin/ctest -D Nightly

Nightly: depends/libsnark/libsnark/CMakeFiles/Nightly
Nightly: depends/libsnark/libsnark/CMakeFiles/Nightly.dir/build.make

.PHONY : Nightly

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/Nightly.dir/build: Nightly

.PHONY : depends/libsnark/libsnark/CMakeFiles/Nightly.dir/build

depends/libsnark/libsnark/CMakeFiles/Nightly.dir/clean:
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/Nightly.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/Nightly.dir/clean

depends/libsnark/libsnark/CMakeFiles/Nightly.dir/depend:
	cd /home/pingxie/Project/graduation/sm3/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/pingxie/Project/graduation/sm3 /home/pingxie/Project/graduation/sm3/depends/libsnark/libsnark /home/pingxie/Project/graduation/sm3/build /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark/CMakeFiles/Nightly.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/Nightly.dir/depend

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

# Utility rule file for NightlyConfigure.

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/NightlyConfigure.dir/progress.make

depends/libsnark/libsnark/CMakeFiles/NightlyConfigure:
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark && /usr/bin/ctest -D NightlyConfigure

NightlyConfigure: depends/libsnark/libsnark/CMakeFiles/NightlyConfigure
NightlyConfigure: depends/libsnark/libsnark/CMakeFiles/NightlyConfigure.dir/build.make

.PHONY : NightlyConfigure

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/NightlyConfigure.dir/build: NightlyConfigure

.PHONY : depends/libsnark/libsnark/CMakeFiles/NightlyConfigure.dir/build

depends/libsnark/libsnark/CMakeFiles/NightlyConfigure.dir/clean:
	cd /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/NightlyConfigure.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/NightlyConfigure.dir/clean

depends/libsnark/libsnark/CMakeFiles/NightlyConfigure.dir/depend:
	cd /home/pingxie/Project/graduation/sm3/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/pingxie/Project/graduation/sm3 /home/pingxie/Project/graduation/sm3/depends/libsnark/libsnark /home/pingxie/Project/graduation/sm3/build /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark /home/pingxie/Project/graduation/sm3/build/depends/libsnark/libsnark/CMakeFiles/NightlyConfigure.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/NightlyConfigure.dir/depend


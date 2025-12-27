# -Wno-switch-default: Suppresses warnings for switch statements without default cases.
# Required for 7zSignature.cpp which uses exhaustive enum switches where all cases are
# explicitly handled, making a default case unnecessary and potentially hiding bugs.
CFLAGS_WARN = -Weverything -Wfatal-errors -Wno-poison-system-directories -Wno-switch-default
CXX_STD_FLAGS = -std=c++98
CXX_STD_FLAGS = -std=c++11
CXX_STD_FLAGS = -std=c++14
CXX_STD_FLAGS = -std=c++17
CXX_STD_FLAGS = -std=c++20
CXX_STD_FLAGS = -std=c++23

CXX_STD_FLAGS = -std=c++11

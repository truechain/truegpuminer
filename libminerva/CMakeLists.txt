# file(GLOB HEADERS "*.h")
# file(GLOB SOURCES "*.cpp")

set(SOURCES
	hash.h fruithash.cpp
	sha3.h sha3.cpp
	mtool.h mtool.cpp
)


add_library(minerva ${SOURCES})

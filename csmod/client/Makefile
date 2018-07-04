######## SGX SDK Settings ########
CC ?= gcc
CXX ?= g++

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif
 
Seal_OutEnclave_Files := $(wildcard Seal_OutEnclave/*.cpp) $(wildcard Seal_OutEnclave/util/*.cpp)
App_Include_Paths := -IOutEnclaveTest -ISeal_OutEnclave -I.

App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := -pthread  # 

CXXFLAGS := $(App_Cpp_Flags) -DHAVE_CONFIG_H
Seal_OutEnclave_Objects := $(Seal_OutEnclave_Files:.cpp=.o)
App_Name := App

.PHONY: all run

all: $(App_Name)

######## App Objects ########

OutEnclaveTest/%.o: OutEnclaveTest/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

socket_client.o: socket_client.cpp
	g++ -O2 -c $< -o $@

$(App_Name): OutEnclaveTest/MakeConfigure.o OutEnclaveTest/OutEnclaveTest.o OutEnclaveTest/ReadData.o $(Seal_OutEnclave_Objects) socket_client.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


.PHONY: clean

	
clean:
	@rm -f $(App_Name) $(App_Cpp_Objects) *.hex

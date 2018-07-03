######## SGX SDK Settings ########
CC ?= gcc-7
CXX ?= g++-7
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
# Hardware mode v.s. sim mode if comment this line
SGX_ARCH ?= x64
SGX_PRERELEASE ?= 1
#SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

#App_Cpp_Files := $(wildcard OutEnclaveTest/*.cpp) 
Seal_OutEnclave_Files := $(wildcard Seal_OutEnclave/*.cpp) $(wildcard Seal_OutEnclave/util/*.cpp)
App_Include_Paths := -I$(SGX_SDK)/include -IOutEnclaveTest -ISeal_OutEnclave -I.

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -pthread -l$(Urts_Library_Name)  # 


ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

CXXFLAGS := $(App_Cpp_Flags) -DHAVE_CONFIG_H
#App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
Seal_OutEnclave_Objects := $(Seal_OutEnclave_Files:.cpp=.o)
App_Name := App

######## Enclave Settings ########

ifeq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
else
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := SealEnclaveTest/SealEnclaveTest.cpp $(wildcard SEAL/*.cpp) $(wildcard SEAL/util/*.cpp)  #$(wildcard SealEnclaveTest/*.cpp)
Enclave_Include_Paths := -ISealEnclaveTest -I. -ISEAL -I$(SGX_SDK)/include -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport
Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths) 
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -lsgx_tcxx -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=SealEnclaveTest/SealEnclaveTest.lds

#CXXFLAGS := $(Enclave_Cpp_Flags) -DHAVE_CONFIG_H   # default for c++; CFLAGS for c; CPPFLAGS for both
# enable here to compile enclave.so

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_Name := SealEnclaveTest.so
Signed_Enclave_Name := SealEnclaveTest.signed.so
Enclave_Config_File := SealEnclaveTest/SealEnclaveTest.config.xml

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
else
Build_Mode = HW_PRERELEASE
endif
else
Build_Mode = HW_DEBUG
endif
else
Build_Mode = SIM_MODE
endif

.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) # $(Enclave_Name) $(Signed_Enclave_Name)
#	@echo "The project has been built in release hardware mode."
#	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
#	@echo "To sign the enclave use the command:"
#	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
#	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
#	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Name) #   $(Signed_Enclave_Name) # enable enclave library here
#
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

OutEnclaveTest/SealEnclaveTest_u.c: $(SGX_EDGER8R) SealEnclaveTest/SealEnclaveTest.edl
	@cd SealEnclaveTest && $(SGX_EDGER8R) --untrusted ../SealEnclaveTest/SealEnclaveTest.edl --search-path ../SealEnclaveTest --search-path -I$(SGX_SDK)/include
	@mv SealEnclaveTest/SealEnclaveTest_u.c SealEnclaveTest/SealEnclaveTest_u.h OutEnclaveTest/
	@echo "GEN  =>  $@"

OutEnclaveTest/SealEnclaveTest_u.o: OutEnclaveTest/SealEnclaveTest_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

OutEnclaveTest/%.o: OutEnclaveTest/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): OutEnclaveTest/SealEnclaveTest_u.o OutEnclaveTest/MakeConfigure.o OutEnclaveTest/OutEnclaveTest.o OutEnclaveTest/ReadData.o $(Seal_OutEnclave_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

SealEnclaveTest/SealEnclaveTest_t.c: $(SGX_EDGER8R) SealEnclaveTest/SealEnclaveTest.edl
	@cd SealEnclaveTest && $(SGX_EDGER8R) --trusted ../SealEnclaveTest/SealEnclaveTest.edl --search-path ../SealEnclaveTest --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

SealEnclaveTest/SealEnclaveTest_t.o: SealEnclaveTest/SealEnclaveTest_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

#SealEnclaveTest/%.o: SealEnclaveTest/%.cpp SealEnclaveTest/SealEnclaveTest_t.o
#	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
#	@echo "CXX  <=  $<"

#SEAL/%.o: SEAL/%.cpp
#	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
#	@echo "CXX  <=  $<"

#SEAL/util/%.o: SEAL/util/%.cpp
#	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
#	@echo "CXX  <=  $<"

#SealEnclaveTest/SealEnclaveTest.o: SealEnclaveTest/SealEnclaveTest.cpp SealEnclaveTest/SealEnclaveTest_t.o
#	@$(CXX) $(Enclave_Cpp_Flags) -c SealEnclaveTest/SealEnclaveTest.cpp -o $@
#	@echo "CXX  <=  $<"
 
#$(Enclave_Cpp_Objects): $(Enclave_Cpp_Files)
#	@$(CXX) $(Enclave_Cpp_Flags) -DHAVE_CONFIG_H -march=native -c $< -o $@
#	@echo "CXX($(Enclave_Cpp_Objects))  <=  $(Enclave_Cpp_Files)"

$(Enclave_Name): SealEnclaveTest/SealEnclaveTest_t.o $(Enclave_Cpp_Objects) # SealEnclaveTest/SealEnclaveTest.o 
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key SealEnclaveTest/SealEnclaveTest_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"
	@echo "The project has been built in $(Build_Mode) mode."

.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) SealEnclaveTest/SealEnclaveTest_u.* $(Enclave_Cpp_Objects) $(Enclave_C_Objects) SealEnclaveTest/SealEnclaveTest_t.* *.hex

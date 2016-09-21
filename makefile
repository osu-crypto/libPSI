

TARGETNAME ?= frontend.exe


to_lowercase = $(subst A,a,$(subst B,b,$(subst C,c,$(subst D,d,$(subst E,e,$(subst F,f,$(subst G,g,$(subst H,h,$(subst I,i,$(subst J,j,$(subst K,k,$(subst L,l,$(subst M,m,$(subst N,n,$(subst O,o,$(subst P,p,$(subst Q,q,$(subst R,r,$(subst S,s,$(subst T,t,$(subst U,u,$(subst V,v,$(subst W,w,$(subst X,x,$(subst Y,y,$(subst Z,z,$1))))))))))))))))))))))))))

CONFIG ?= RELEASE


CONFIGURATION_FLAGS_FILE := $(call to_lowercase,$(CONFIG)).mak
include $(CONFIGURATION_FLAGS_FILE)


ifeq ($(BINARYDIR),)
error:
	$(error Invalid configuration, please check your inputs)
endif


PRIMARY_LIB=$(BINARYDIR)/libPSI.a 
PRIMARYTESTS_LIB=$(BINARYDIR)/libPSITests.a

SRC=.

FRONTEND_DIR=$(SRC)/frontend
PRIMARY_DIR=$(SRC)/libPSI
PRIMARYTESTS_DIR=$(SRC)/libPSI_Tests


FRONTEND_SRC=$(wildcard $(FRONTEND_DIR)/*.cpp)
FRONTEND_OBJ=$(addprefix $(BINARYDIR)/,$(FRONTEND_SRC:.cpp=.o))


PRIMARY_SRC=\
	$(wildcard $(PRIMARY_DIR)/Common/*.cpp) \
	$(wildcard $(PRIMARY_DIR)/Crypto/*.cpp) \
	$(wildcard $(PRIMARY_DIR)/MPSI/*.cpp) \
	$(wildcard $(PRIMARY_DIR)/MPSI/Dcw/*.cpp)\
        $(wildcard $(PRIMARY_DIR)/MPSI/DKT/*.cpp)\
	$(wildcard $(PRIMARY_DIR)/RiotPSI/*.cpp) \
	$(wildcard $(PRIMARY_DIR)/OT/*.cpp) \
	$(wildcard $(PRIMARY_DIR)/OT/Base/*.cpp) \
	$(wildcard $(PRIMARY_DIR)/Network/*.cpp) 


PRIMARY_OBJ=$(addprefix $(BINARYDIR)/,$(PRIMARY_SRC:.cpp=.o)) 
PRIMARY_H=$(PRIMARY_SRC:.cpp=.h)

PRIMARYTESTS_SRC=$(wildcard $(PRIMARYTESTS_DIR)/*.cpp) 
PRIMARYTESTS_OBJ=$(addprefix $(BINARYDIR)/,$(PRIMARYTESTS_SRC:.cpp=.o))
PRIMARYTESTS_H=$(PRIMARYTESTS_SRC:.cpp=.h)



TPL=thirdparty/linux
BOOST=thirdparty/linux/boost


INC=-I./libPSI/\
    -I./libPSI_Tests/\
    -I$(TPL)\
    -I$(BOOST)/includes/

TPL_LIB=$(BOOST)/stage/lib/libboost_system.a\
	$(BOOST)/stage/lib/libboost_thread.a\
	$(TPL)/miracl/miracl/source/libmiracl.a\
	$(TPL)/cryptopp/libcryptopp.a\
	$(TPL)/mpir/.libs/libmpir.a 

LIB=\
	$(TPL_LIB)\
	-lpthread\
	-lrt

EXPORTHEADS=$(PRIMARY_H) $(PRIMARYTESTS_H)


LDFLAGS += $(COMMONFLAGS)
LDFLAGS += -L$(BINARYDIR)
LDFLAGS += $(addprefix -L,$(LIBRARY_DIRS))
#LDFLAGS += $(addprefix -l,$(LIBRARY_NAMES))

#LDFLAGS +=  -Wl,--verbose

CXXFLAGS += $(COMMONFLAGS)
CXXFLAGS += $(addprefix -I,$(INCLUDE_DIRS)) -std=c++11 
CXXFLAGS += $(addprefix -D,$(PREPROCESSOR_MACROS))





#######################################################################################


PRIMARY_OUTPUTS := \
	$(BINARYDIR)/$(TARGETNAME)



all: $(PRIMARY_OUTPUTS)

-include $(all_objs:.o=.dep)

clean: 
	rm -fr $(BINARYDIR) 

$(BINARYDIR):
	mkdir $(BINARYDIR)


$(BINARYDIR)/$(TARGETNAME): $(FRONTEND_OBJ) $(EXTERNAL_LIBS) $(PRIMARY_LIB) $(PRIMARYTESTS_LIB)
	$(LD) -o $@ $(LDFLAGS) $(START_GROUP) $(FRONTEND_OBJ) $(LIBRARY_LDFLAGS)\
         -Wl,-Bstatic  $(addprefix -l,$(STATIC_LIBRARY_NAMES))\
	 -Wl,-Bdynamic  $(addprefix -l,$(SHARED_LIBRARY_NAMES))\
	 -Wl,--as-needed  $(END_GROUP)

#	 -Wl,--verbose



$(BINARYDIR)/%.o : %.cpp $(all_make_files) |$(BINARYDIR)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@ -MD -MF $(@:.o=.dep)

$(PRIMARY_LIB): $(PRIMARY_OBJ) | $(BINARYDIR)
	$(AR) $(ARFLAGS) $@ $(PRIMARY_OBJ) 

$(PRIMARYTESTS_LIB): $(PRIMARYTESTS_OBJ) | $(BINARYDIR)
	$(AR) $(ARFLAGS) $@ $(PRIMARYTESTS_OBJ)


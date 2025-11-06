# ==============================================================================
#  Makefile
# ==============================================================================

# Settings
NAME    = sslkeylog
TARGET  = lib$(NAME).so
CFLAGS  = -Wall -Wextra -Werror
LDFLAGS =
SRCDIR  = src
OBJDIR  = obj


# Command
AR     = ar
CC     = gcc
LINK   = $(CC)
MKDIR  = mkdir
RANLIB = ranlib


# Options
OPTIONS_WARNING = -Wall -Wextra -Werror
OPTIONS_DEPENDS = -MMD -MP


# Auto Settings
VPATH = $(SRCDIR)
SRCS  = $(wildcard $(addsuffix /*.c,$(SRCDIR)))
OBJS  = $(addprefix $(OBJDIR)/, $(notdir $(addsuffix .o, $(basename $(SRCS)))))
DEPS  = $(OBJS:$(OBJDIR)/%.o=$(OBJDIR)/%.d)
CFLAGS += $(OPTIONS_WARNING) $(OPTIONS_DEPENDS)
ifeq ($(strip lib$(NAME).so),$(strip $(TARGET)))
CFLAGS += -fPIC
endif

# ------------------------------------------------------------------------------
#  Rules
# ------------------------------------------------------------------------------
all: $(TARGET)


# ------------------------------------------------------------------------------
#  Link
# ------------------------------------------------------------------------------
# .so
ifeq ($(strip lib$(NAME).so),$(strip $(TARGET)))
$(TARGET): $(OBJS)
	$(LINK) $(LDFLAGS) -shared -Wl,-soname,$(TARGET) -o $@ $^ $(LIBS)
endif

# .a
ifeq ($(strip $(NAME).a),$(strip $(TARGET)))
$(TARGET): $(OBJS)
	$(AR) rv $@ $^
	$(RANLIB) $@
endif

# .exe
ifeq ($(strip $(NAME)),$(strip $(TARGET)))
$(TARGET): $(OBJS)
	$(LINK) $(LDFLAGS) -o $@ $^ $(LIBS)
endif


# ------------------------------------------------------------------------------
#  Compile
# ------------------------------------------------------------------------------
$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR):
	$(MKDIR) -p $(OBJDIR)

# ------------------------------------------------------------------------------
#  Clean
# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	$(RM) -f $(OBJDIR)/*.o $(OBJDIR)/*.d $(TARGET)

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif

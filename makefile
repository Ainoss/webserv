
CC = gcc
CFLAGS = -g
INCLUDES = -I$(INCDIR)

SRCDIR = src
INCDIR = include
OBJDIR = objs
IMG_NAME = fs.img

SRCS = connection.c picohttpparser.c
OBJ_NAMES = $(patsubst %.c,%.o,$(SRCS))
OBJS = $(addprefix $(OBJDIR)/,$(OBJ_NAMES))

# vpath %.o $(OBJDIR)
vpath %.h $(INCDIR)
vpath %.c $(SRCDIR)

.PHONY: all clean

all: server

server: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

#$(OBJDIR)/%.o : %.c
#	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJS) : $(OBJDIR)/%.o : %.c $(OBJDIR)/%.d
	$(CC) -MT $@ -MMD -MP -MF $(OBJDIR)/$*.d $(CFLAGS) $(INCLUDES) -c $< -o $@;

-include $(OBJS:.o=.d)

$(OBJDIR)/%.d : ;

#$(OBJDIR)/%.d : %.c | $(OBJDIR)
#	@$(CC) -MT $@ -MM -MP $(CFLAGS) $(INCLUDES) $< > $@;
#	@echo "extract dependencies to $@"

$(OBJS): | $(OBJDIR)

$(OBJDIR):
	@mkdir $@

clean:
	rm -rf test test.o $(OBJDIR) 


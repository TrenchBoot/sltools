PROG=	iommu-util
SRCS=	main.c dmar.c acpi_decode.c utils.c

CFLAGS+= -Wall -O2 -D_LINUX -Wstrict-prototypes

all: $(PROG)

$(PROG) : $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(PROG)

CLEANFILES= $(PROG)

clean:
	rm -f $(CLEANFILES) $(patsubst %.c,%.o, $(SRCS))

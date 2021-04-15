# Makefile.

EXECS=project

project: project.c
	cc -o project project.c

tests: tests.sh
	./tests.sh

clean:
	rm -f $(EXECS)

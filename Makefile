ERL = erl
EFLAGS = -pa ../netspire-core/ebin

all: compile

compile:
	$(ERL) $(EFLAGS) -make

clean:
	rm -f erl_crash.dump
	find . -name "*~" -exec rm -f {} \;

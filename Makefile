ERL = erl
EFLAGS = -pa ../netspire-core/ebin

all: compile

compile:
	$(ERL) $(EFLAGS) -make

clean:
	rm -rf ebin erl_crash.dump
	find . -name "*~" -exec rm -rf {} \;

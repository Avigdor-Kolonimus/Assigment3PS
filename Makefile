CXX=gcc
CXXFLAGS=-Wall -Wvla -Werror
RUNNABLE = attack

make:
	$(CXX)  $(CXXFLAGS) -o $(RUNNABLE) Attacker.c CreAndSenPac.c

clean:
	rm *.o attack
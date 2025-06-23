compiler = g++
exec = graveyard
libs = -l sqlite3 -l bcrypt -l crypto -l ssl
includes =
source = main.cpp

all: $(source)
	$(compiler) main.cpp -o $(exec) $(libs)





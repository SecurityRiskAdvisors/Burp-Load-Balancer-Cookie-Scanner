all:
	javac -source 1.8 -target 1.8 src/*/*.java -d bin
	jar cvf bigip.jar -C bin/ .

clean:
	rm ./bin/*/*
	rm bigip.jar

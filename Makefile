all:
	javac -source 1.8 -target 1.8 -sourcepath src -d bin -classpath src/burp/*.java
	javac -source 1.8 -target 1.8 -sourcepath src -d bin -classpath src/com/securityriskadvisors/*.java 
	jar cvf bigip.jar -C bin/ .

clean:
	rm ./bin/*/*
	rm bigip.jar

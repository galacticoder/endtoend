def same(string_1, string_2):
	if string_1==string_2:(
		print("IP1 and IP2 are the same")
	)
	else:(
		print("IP1 and IP2 arent the same")
	)

def check(string_1, string_2):
	str1 = len(string_1)
	str2 = len(string_1)
	if str1 > str2:(
		print("IP1 is longer")
	)
	elif str2 > str1:(
		print("IP2 is longer")
	)
	same(string_1,string_2)

def length(com1):
	print(len(com1))


string1 = input("IP1: ")
string2 = input("IP2: ")

com1 = string1
com2 = string2

check(string1, string2)
length(com1)